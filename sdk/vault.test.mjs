import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secretItem } from '@kotoba-lang/kagitaba/secret-item';
import { newVaultKey, sealSecret, openSecret, validateEnvelope } from './vault.mjs';
const context = { ownerId: 'owner-a', vaultId: 'a'.repeat(32), itemId: 'b'.repeat(32), generation: 1 };
const item = secretItem({ id: context.itemId, title: 'Private provider', key: 'PROVIDER_API_KEY', value: 'synthetic-secret' });
test('all kagitaba fields are encrypted with fresh nonces', () => {
  const key = newVaultKey(), a = sealSecret(key, context, item), b = sealSecret(key, context, item);
  assert.deepEqual(openSecret(key, context, a), item); assert.notEqual(a.nonce, b.nonce);
  for (const value of [item.title, item.key, item.value]) assert.equal(JSON.stringify(a).includes(value), false);
});
test('owner, vault, item, generation and wrong-key substitution cannot decrypt', () => {
  const key = newVaultKey(), envelope = sealSecret(key, context, item);
  for (const changed of [{ ownerId: 'owner-b' }, { vaultId: 'c'.repeat(32) }, { itemId: 'd'.repeat(32) }, { generation: 2 }]) {
    assert.throws(() => openSecret(key, { ...context, ...changed }, envelope), /Invalid encrypted secret/);
  }
  assert.throws(() => openSecret(newVaultKey(), context, envelope), /Invalid encrypted secret/);
});
test('reject tamper, truncated tags, noncanonical encoding and extra plaintext fields', () => {
  const key = newVaultKey(), envelope = sealSecret(key, context, item);
  const bytes = Buffer.from(envelope.ciphertext, 'base64url'); bytes[0] ^= 1;
  assert.throws(() => openSecret(key, context, { ...envelope, ciphertext: bytes.toString('base64url') }));
  for (const change of [{ ciphertext: 'AA' }, { nonce: envelope.nonce + '=' }, { plaintext: item.value }]) {
    assert.throws(() => validateEnvelope({ ...envelope, ...change }));
  }
});
