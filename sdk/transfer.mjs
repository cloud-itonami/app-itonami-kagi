import { x25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
const enc = new TextEncoder();
const fail = () => { throw new Error('Invalid vault transfer.'); };
const hex = b => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
function unhex(s, size) {
  if (typeof s !== 'string' || !new RegExp(`^[a-f0-9]{${size * 2}}$`).test(s)) fail();
  return Uint8Array.from(s.match(/../g), n => parseInt(n, 16));
}
function requestBytes(r) {
  if (!r || Object.keys(r).length !== 5 || r.format !== 'kagi-device-request-v1' ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(r.ownerId) || !Number.isSafeInteger(r.expiresAt) ||
      !/^[a-f0-9]{32}$/.test(r.requestId)) fail();
  unhex(r.publicKey, 32);
  return enc.encode(JSON.stringify([r.format, r.ownerId, r.requestId, r.publicKey, r.expiresAt]));
}
export function deviceFingerprint(request) { return hex(sha256(requestBytes(request))); }
export function createDeviceRequest(ownerId, now = Date.now()) {
  const privateKey = randomBytes(32);
  const request = { format: 'kagi-device-request-v1', ownerId, requestId: hex(randomBytes(16)),
    publicKey: hex(x25519.getPublicKey(privateKey)), expiresAt: now + 600000 };
  return { request, privateKey, fingerprint: deviceFingerprint(request) };
}
function encrypt(key, aad, snapshot) {
  const plain = enc.encode(snapshot), nonce = randomBytes(12);
  if (plain.length > 16777216) fail();
  try { return { nonce: hex(nonce), ciphertext: hex(gcm(key, nonce, aad).encrypt(plain)) }; }
  finally { plain.fill(0); }
}
function decrypt(key, aad, box) {
  if (typeof box.ciphertext !== 'string' || box.ciphertext.length > 33554464 || box.ciphertext.length < 32 || box.ciphertext.length % 2) fail();
  let plain;
  try {
    plain = gcm(key, unhex(box.nonce, 12), aad).decrypt(unhex(box.ciphertext, box.ciphertext.length / 2));
    return new TextDecoder('utf-8', { fatal: true }).decode(plain);
  } catch { fail(); } finally { plain?.fill(0); }
}
function live(r, now) {
  requestBytes(r);
  if (r.expiresAt <= now || r.expiresAt > now + 600000) fail();
}
/** The fingerprint must be compared on the recipient device through a trusted channel. */
export function sealDeviceTransfer(request, confirmedFingerprint, snapshot, now = Date.now()) {
  live(request, now);
  if (confirmedFingerprint !== deviceFingerprint(request)) fail();
  const ephemeral = randomBytes(32);
  let derived;
  try {
    const shared = x25519.getSharedSecret(ephemeral, unhex(request.publicKey, 32));
    try { derived = hkdf(sha256, shared, undefined, requestBytes(request), 32); }
    finally { shared.fill(0); }
    return { format: 'kagi-device-transfer-v1', request, ephemeralPublicKey: hex(x25519.getPublicKey(ephemeral)),
      ...encrypt(derived, requestBytes(request), snapshot) };
  } finally { ephemeral.fill(0); derived?.fill(0); }
}
export function transferFingerprint(transfer) {
  if (!transfer || transfer.format !== 'kagi-device-transfer-v1') fail();
  return hex(sha256(enc.encode(JSON.stringify([transfer.format, deviceFingerprint(transfer.request), transfer.ephemeralPublicKey, transfer.nonce, transfer.ciphertext]))));
}
export function openDeviceTransfer(privateKey, expectedRequest, transfer, confirmedSenderFingerprint, now = Date.now()) {
  if (confirmedSenderFingerprint !== transferFingerprint(transfer)) fail();
  live(expectedRequest, now);
  if (!transfer || Object.keys(transfer).length !== 5 || transfer.format !== 'kagi-device-transfer-v1' ||
      deviceFingerprint(transfer.request) !== deviceFingerprint(expectedRequest) || privateKey.length !== 32 ||
      hex(x25519.getPublicKey(privateKey)) !== expectedRequest.publicKey) fail();
  let derived;
  try {
    const shared = x25519.getSharedSecret(privateKey, unhex(transfer.ephemeralPublicKey, 32));
    try { derived = hkdf(sha256, shared, undefined, requestBytes(expectedRequest), 32); }
    finally { shared.fill(0); }
    return decrypt(derived, requestBytes(expectedRequest), transfer);
  } finally { derived?.fill(0); }
}
const recoveryAAD = enc.encode('kagi-recovery-v1');
/** Random 256-bit recovery code, independent of account passwords and the vault key. */
export function sealRecovery(snapshot) {
  const key = randomBytes(32);
  try { return { code: hex(key), package: { format: 'kagi-recovery-v1', ...encrypt(key, recoveryAAD, snapshot) } }; }
  finally { key.fill(0); }
}
export function openRecovery(code, packageValue) {
  if (!packageValue || Object.keys(packageValue).length !== 3 || packageValue.format !== 'kagi-recovery-v1') fail();
  const key = unhex(code, 32);
  try { return decrypt(key, recoveryAAD, packageValue); } finally { key.fill(0); }
}
