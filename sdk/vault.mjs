import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { validateSecretItem } from '@kotoba-lang/kagitaba/secret-item';
const encoder = new TextEncoder();
const format = 'kagi-secret-v1';
const opaque = /^[a-f0-9]{32}$/;
const fail = () => { throw new Error('Invalid encrypted secret.'); };
function contextBytes(context) {
  if (!context || Object.keys(context).length !== 4 ||
      typeof context.ownerId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(context.ownerId) ||
      !opaque.test(context.vaultId) || !opaque.test(context.itemId) ||
      !Number.isSafeInteger(context.generation) || context.generation < 1) fail();
  return encoder.encode(JSON.stringify([format, context.ownerId, context.vaultId, context.itemId, context.generation]));
}
function keyBytes(key, context) {
  if (!(key instanceof Uint8Array) || key.length !== 32) fail();
  return hkdf(sha256, key, undefined, contextBytes(context), 32);
}
function encode(bytes) {
  let text = ''; for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function decode(value, min, max) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1 || value.length > max * 2) fail();
  let bytes; try { bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), ch => ch.charCodeAt(0)); } catch { fail(); }
  if (bytes.length < min || bytes.length > max || encode(bytes) !== value) fail();
  return bytes;
}
export function newVaultKey() { return randomBytes(32); }
export function newOpaqueId() { return Array.from(randomBytes(16), b => b.toString(16).padStart(2, '0')).join(''); }
export function validateEnvelope(envelope) {
  if (!envelope || Object.keys(envelope).length !== 4 || envelope.format !== format ||
      envelope.algorithm !== 'AES-256-GCM-HKDF-SHA256') fail();
  decode(envelope.nonce, 12, 12); decode(envelope.ciphertext, 16, 24592);
  return envelope;
}
export function sealSecret(key, context, item) {
  validateSecretItem(item); if (item.id !== context.itemId) fail();
  const plaintext = encoder.encode(JSON.stringify(item));
  if (plaintext.length > 24576) fail();
  const nonce = randomBytes(12), derived = keyBytes(key, context);
  try {
    return { format, algorithm: 'AES-256-GCM-HKDF-SHA256', nonce: encode(nonce),
      ciphertext: encode(gcm(derived, nonce, contextBytes(context)).encrypt(plaintext)) };
  } finally { derived.fill(0); plaintext.fill(0); }
}
export function openSecret(key, context, envelope) {
  validateEnvelope(envelope);
  const derived = keyBytes(key, context); let plaintext;
  try {
    plaintext = gcm(derived, decode(envelope.nonce, 12, 12), contextBytes(context))
      .decrypt(decode(envelope.ciphertext, 16, 24592));
    const item = validateSecretItem(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)));
    if (item.id !== context.itemId) fail();
    return item;
  } catch { fail(); }
  finally { derived.fill(0); plaintext?.fill(0); }
}
