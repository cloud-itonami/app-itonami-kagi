import type { SecretItem } from '@kotoba-lang/kagitaba/secret-item';
export interface VaultContext { ownerId: string; vaultId: string; itemId: string; generation: number }
export interface Envelope { format: 'kagi-secret-v1'; algorithm: 'AES-256-GCM-HKDF-SHA256'; nonce: string; ciphertext: string }
export function newVaultKey(): Uint8Array;
export function newOpaqueId(): string;
export function validateEnvelope(value: unknown): Envelope;
export function sealSecret(key: Uint8Array, context: VaultContext, item: SecretItem): Envelope;
export function openSecret(key: Uint8Array, context: VaultContext, envelope: Envelope): SecretItem;
