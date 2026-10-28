# ENGI transfer interop vectors (JUN-501 S0-a)

`test/native/engi_transfer_vectors.json` fixes what a kagi funds-role signer
must reproduce so that ENGI accepts its output (ADR 0021, network-awai-apex):

- `did:key` of an Ed25519 key: `did:key:z` + base58btc(`0xed 0x01` || pub32).
- `transfer-id` = `b` + base32-lower(`0x01 0x71 0x12 0x20` || SHA-256 of the
  canonical TransferBody), as in `engi.core/canonical-transfer-body` and
  `kotobase.cid/graph-cid-from-name`.
- the signature is plain Ed25519 over the UTF-8 bytes of the `transfer-id`
  (`engi.crypto/sign-transfer`), base64url. It is not the kagi permit
  signature (`kagi.agent.action.v1\n` + permit); a funds role needs its own
  signing domain.

Seeds are the published RFC 8032 section 7.1 test seeds. They are public and
must never be operational keys.

## What is established (2026-10-28)

- `engi.crypto` (run with `kbb test/native/engi_transfer_check.cljk` from a
  `kotoba-lang/engi` checkout) and the independent oracle
  (`python3 -I test/native/gen_engi_transfer_vectors.py`, hashlib + OpenSSL)
  agree on the did:key, transfer-id and signature for both cases, and
  `verify-transfer-id-sig` accepts them.
- Negative controls: a changed amount changes the transfer-id; a signature
  over one transfer-id does not verify for another; it does not verify under
  the receiver's did:key.

## What is not established

The native kagi side (pinned Amu SHA-256/Ed25519 owners) has not been run
against these vectors: that needs the arm64 Linux native build. Until then
this is a reference for the native gate, not evidence about the native
signer.
