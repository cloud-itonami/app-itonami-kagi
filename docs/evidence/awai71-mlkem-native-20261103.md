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
