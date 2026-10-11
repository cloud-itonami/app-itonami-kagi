# Mithril E2EE secret SDK — technical preview

`@kotoba-lang/kagi/mithril-vault` exposes a bounded JavaScript credential adapter.
It uses the same Noble AES-GCM/HKDF primitives as `kagi.crypto.noble`. The existing
CLJK provider opens a committed synthetic SDK fixture; this is an interoperability
check, not an independent cryptographic audit.

A fresh random 32-byte Vault key derives a per-context encryption key with
HKDF-SHA256. AAD and derivation bind the protocol, owner, vault, item and generation.
A fresh 96-bit nonce accompanies each AES-256-GCM ciphertext. All kagitaba fields,
including title and variable name, are encrypted. Transport accepts only this
versioned envelope, never the plaintext item or Vault key. The generation must
match the committed item's revision. Clients retain a trusted minimum revision;
a fresh device still needs authenticated state transfer from an existing device.

This API does NOT implement the governed vault actor, password derivation, device
admission, PQC recipient sharing, recovery UX, browser autofill or account login.
Do not describe the symmetric adapter as a complete PQC vault. Those remain the
existing CLJK components or follow-up integration work. A server cannot validate
that a user's ciphertext actually contains a secret rather than arbitrary bytes.

`openSecret` returns plaintext only to the caller. Use only in a trusted main
process or isolated worker; do not expose it to a renderer or language model.
JavaScript cannot guarantee erasure of immutable strings. Byte scratch buffers
are cleared, but this is not hardware custody or secure-memory certification.

Run `npm run test:sdk`, existing Noble interop tests and
`kagi.mithril-sdk-interop-test`. General-user release requires the independent
review and recovery drill stated in SECURITY.md.
