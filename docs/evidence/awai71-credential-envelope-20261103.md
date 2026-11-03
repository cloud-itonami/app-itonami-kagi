# Experimental native credential envelope

`kotoba/kagi/credential_envelope.kotoba` provides a versioned, bounded
recipient-encrypted seal/open component using canonical `pqh.hybrid` and
ChaCha20-Poly1305. The caller supplies the recipient public keys, exact
context, ephemeral and ML-KEM randomness and nonce. The open path additionally
checks that both public keys match the supplied recipient private keys. The
context is bound into both the KEM transcript and AEAD associated data. This
format is distinct from historical Kagi grants.

On a local ARM64 Mac, the complete component, test module, and dependencies
from `kotoba-lang/kotoba` commit
`0f4916e2e18cfd32a82c1e0fd9e633f4618adce6` were compiled as modules with
separate source locks. Synthetic test group results were **7 / 63 / 63**,
each its documented full bitmask. They cover successful seal/open, wrong
context and recipient, changed ciphertext, magic, ephemeral public key,
ML-KEM ciphertext, nonce and tag, wrong private keys, truncation, empty or
oversized plaintext and wrong nonce length. A negative-control dependency with
AEAD tag verification removed returned **1** instead of group A's 7.

| Image | Source-lock SHA-256 | Signed image SHA-256 |
|---|---|---|
| group A | `e998a9d7c8596f67e8413c51bbb4483616e8f283848ca705b668c4b5a56eff7f` | `881a4280cfc04d0bb1ea0aaf0fce985a85a9a3b825e54ca3d216bef646273e7e` |
| group B | `094e4b1202bdfc01641c2669dacd0331a15965c1bddfc8a047a707b4293f58ea` | `304e9f2cde86903c9e061d8083e9d0e9f7f80a1fdd7fc1b06360bfaf4b55e5f0` |
| group C | `2c7dddffc30d36e81f90823730cc6f52d6ec10ddb366631c26105ace75103e31` | `3b0b1ff5619a9da9a67e92343169264f83c5c380d4314600109c573209a7cca0` |
| tag-check mutant | `cc078a19f713596e0f336de994c04427df97d1003d8e4e9462d033054d180967` | `10fcc62336df3e681f67732df561d802e7c6b6bc5630255b34522319f41d050f` |

The Amu Mac root SHA-256 was
`920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6`;
the diagnostic packager was
`f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d`.
The test uses only synthetic keys and bytes, and no network or credentials.

This is not wired into Kagi CLI or any bot. The basic public-key envelope does
**not** authenticate its sender or authorize a lease; the trusted host must supply
and verify the exact recipient, canonical scope/purpose/audience/expiry
context, issuer identity, policy, replay state, revocation and clock. It must
generate independent, fresh secure random inputs and prevent nonce/key reuse.
The byte API returns plaintext to its trusted caller and does not establish
process isolation, secret erasure or constant-time behavior. No real GitHub
token, installation, revocation, secure delivery, production artifact, or
interoperability with an independent implementation has been tested. The wire
format remains an experimental candidate pending review and integration.

## Issuer signature candidate

A later revision adds `credential-signing-message`, a domain-separated
SHA-256 digest of the recipient, length-framed context and envelope, and
`credential-open-signed`, which checks a prime-order Ed25519 public key and
signature before opening. The trusted host must independently select and
authorize the issuer key: a valid signature from an arbitrary supplied key is
not authorization. The unverified `credential-open-unverified` remains a lower-level
primitive, and must not be used as an authorized broker operation.

On the same Mac the complete component and updated native tests returned
**7 / 63 / 63 / 63** for groups A–D. Group D covers a valid signed envelope,
altered context or ciphertext, changed issuer or signature, and an invalid
issuer key. A negative control with the signature verification call removed
returned **47** instead of 63. Only synthetic seeds, tokens and keys were
used. Exact source locks for these images are in the sibling evidence folder.

| Image | Source-lock SHA-256 | Signed image SHA-256 |
|---|---|---|
| group A | `f278ffc6677661e6558023327abe5aa849c9d476f315f7c5b152e9d5ed72bb2e` | `44b13ae16225281a32f0ccd72d7005980df51f5a1439d25b326a6e0adea72426` |
| group B | `5f1a08a90fc3dbae0e9650933a9ca14214fe1143b256d1e3053ac861a05cac04` | `dce12d0f70b721c486da82c06960b0dfd6f7fa98b1886691fffe22648a753ba1` |
| group C | `dc6031bfbb8ac46d24452322e08cd1f6ba0796ffbc706e8765866340100cc9bc` | `73cfcb7fa5e9d42429f82bee03ef2757e0b3e387c5288cba91b890d7710d66d5` |
| group D | `e855dc6e934b03f0c8fe9e62a8820adddcce8839e16ab8d04fbb0820c31b51ef` | `f8211b0be2b8c2477f90dd91684b833ee4f026014d8f1212958c712e1e6b7577` |
| signature-check mutant | `c0683e2176c22bc2629e74adf7c40068eaf606a7849ae26dcbbb9223f2970568` | `3d9369fcf9278ab3b961c1b84bed75f2283a4b0b0c4c0007464811e1d3deef1b` |

These tests do not supply issuer policy, validate scope/expiry/revocation,
provide replay protection, or qualify a host, secret delivery or production
artifact. The native cryptographic code does not claim constant-time or
guaranteed secret erasure. No real GitHub credential was issued or handled.
