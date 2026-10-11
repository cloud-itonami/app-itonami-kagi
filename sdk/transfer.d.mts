export interface DeviceRequest { format: 'kagi-device-request-v1'; ownerId: string; requestId: string; publicKey: string; expiresAt: number }
export interface DeviceTransfer { format: 'kagi-device-transfer-v1'; request: DeviceRequest; ephemeralPublicKey: string; nonce: string; ciphertext: string }
export interface RecoveryPackage { format: 'kagi-recovery-v1'; nonce: string; ciphertext: string }
export function deviceFingerprint(request: DeviceRequest): string;
export function createDeviceRequest(ownerId: string, now?: number): { request: DeviceRequest; privateKey: Uint8Array; fingerprint: string };
export function sealDeviceTransfer(request: DeviceRequest, confirmedFingerprint: string, snapshot: string, now?: number): DeviceTransfer;
export function transferFingerprint(transfer: DeviceTransfer): string;
export function openDeviceTransfer(privateKey: Uint8Array, expectedRequest: DeviceRequest, transfer: DeviceTransfer, confirmedSenderFingerprint: string, now?: number): string;
export function sealRecovery(snapshot: string): { code: string; package: RecoveryPackage };
export function openRecovery(code: string, packageValue: RecoveryPackage): string;
