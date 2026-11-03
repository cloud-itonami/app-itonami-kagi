# Kagi credential broker prerequisite: ML-KEM native check

The native GitHub credential broker and its recipient-encrypted lease are not
implemented or qualified by this test. As a prerequisite investigation on
2026-11-03, the canonical `kotoba-lang/kotoba` tree at commit
`0f4916e2e18cfd32a82c1e0fd9e633f4618adce6` contained native SHA-3,
ML-KEM-768, X25519, ChaCha20-Poly1305 and hybrid KEM source. An older AWAI-117
inventory describing these as absent is stale. Presence is not a claim that
the complete credential protocol or its host has been qualified.

On the local macOS ARM64 host, the exact SHA-3 and ML-KEM source and the
upstream ML-KEM native gate were composed into a source-unity fixture. The
Amu root compiler checked and compiled it; the extracted native `main` was
packaged and ad-hoc signed. The gate returned bitmask **63**, its documented
pass: selected FIPS 203 known-answer vectors, invalid-input checks, a
round-trip, implicit rejection and NTT-table checks. A negative-control image
with the second NTT zeta changed from 1729 to 1730 returned **40**, not 63.
The operations were CPU-limited diagnostic fixtures; no key, token, bot,
network service or production configuration was used.

SHA-256:

- `gov.nist.sha3/kotoba/sha3/core.kotoba`: `1eaab0d5288fecf64189ef86560b201bed6ca9222482a8b368ea586a692e843c`
- `gov.nist.mlKem/kotoba/mlkem/core.kotoba`: `164c2062607688b55fe353305ea45dd0de12805827a735952b3098d0e65de5dd`
- `gov.nist.mlKem/kotoba/mlkem/native_gate.kotoba`: `6e50c27a8796957ceb41a55ba400a42ac0516e3cc0eff861f8f653fffa486584`
- composed source: `11f29e0a6cdd9be6e38b81d94b6e8fe6f88a0479c3f48be064b0ff293213bd49`
- signed test image: `3c229416626cea72626043461f7ab08b99a72c351a3fd2cc5835280fc6b65d03`
- Mac Amu root compiler: `920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6`
- diagnostic packager: `f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d`

The upstream source expressly does not claim constant-time behavior; it
requires externally supplied secure randomness. This gate alone does not test
the hybrid combiner, AEAD, authenticated peer binding, secret isolation,
RSA GitHub App signing, installation token issuance, revocation, secure
Git/GH credential delivery or the complete Kagi host. Prior upstream native
results for other algorithms are separate evidence and were not reproduced in
this run. Production use still requires the complete protocol and host to be
reviewed and qualified.

## Hybrid KEM and grant-format integration

The same canonical Kotoba revision's `pqh.native-gate` group A was compiled
as separately resolved modules under a SHA-256-pinned source lock on the
local Mac. Its documented success bitmask is 7; the fixture returned **7**.
A negative-control build changing the hybrid KEM salt returned **0**. Group A
checks independent known answers for encapsulation and decapsulation and binds
caller info. It does not exercise the whole Kagi credential lifecycle or
replace the upstream gates' other groups.

The positive source-lock SHA-256 was
`c102e5830d119d984df0a521d4aeb3219cde2bcd627b84f251bc66d794420821`,
and the signed positive test image SHA-256 was
`9c88a71cfd6b7d37fd3e0aba487c0b27c47378987775349fd82f93ef45845e07`.
The altered-salt source-lock SHA-256 was
`60e0ce1e966db9e663813d95de66b05cc2cfe4a88ee79b202424a6ec3d52d55c`,
and its signed test image SHA-256 was
`32f282b5cbd615724ca60aadf9499ccd3764e4069b2de455e09d5e9bb11a6fb0`.
Compiler and diagnostic packager hashes are the same as above.

There is an integration distinction: Kagi's historical `src/kagi/crypto.cljk`
grant format uses the `kagi/kem/v1` combiner, its own transcript ordering and
host-encoded public keys, and wraps the DEK with AES-256-GCM. The canonical
native `pqh.hybrid` source uses the `etzhayyim/pqh-v1/kem` salt and a different
transcript ordering. Calling that function is therefore not a drop-in
implementation of the historical grant format. The owner has explicitly said
old keys and vault migration are not required; the new broker still needs an
explicit versioned envelope and a pinned, reviewed choice of cryptographic
construction and recipient/purpose binding before either side is deployed.
The historical implementation remains migration inventory and was not run.
