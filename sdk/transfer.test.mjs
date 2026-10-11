import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceRequest, deviceFingerprint, transferFingerprint, sealDeviceTransfer, openDeviceTransfer, sealRecovery, openRecovery } from './transfer.mjs';
test('recipient-bound device transfer rejects substitution, expiry and tampering', () => {
  const a = createDeviceRequest('owner', 1000), b = createDeviceRequest('owner', 1000);
  const box = sealDeviceTransfer(a.request, a.fingerprint, 'synthetic snapshot', 1001);
  assert.equal(openDeviceTransfer(a.privateKey, a.request, box, transferFingerprint(box), 1002), 'synthetic snapshot');
  assert.throws(() => sealDeviceTransfer(b.request, a.fingerprint, 'x', 1001));
  assert.throws(() => openDeviceTransfer(b.privateKey, b.request, box, transferFingerprint(box), 1002));
  assert.throws(() => openDeviceTransfer(a.privateKey, a.request, box, transferFingerprint(box), 601001));
  assert.throws(() => openDeviceTransfer(a.privateKey, a.request, {...box, ciphertext: '00'+box.ciphertext.slice(2)}, transferFingerprint(box), 1002));
  assert.notEqual(deviceFingerprint({...a.request, ownerId:'other'}), a.fingerprint);
});
test('recovery requires separate random code and authenticates all snapshot bytes', () => {
  const a = sealRecovery('synthetic snapshot'), b = sealRecovery('other');
  assert.equal(openRecovery(a.code, a.package), 'synthetic snapshot');
  assert.throws(() => openRecovery(b.code, a.package));
  assert.throws(() => openRecovery(a.code, {...a.package, nonce:'00'.repeat(12)}));
  assert.ok(!JSON.stringify(a.package).includes(a.code));
});
