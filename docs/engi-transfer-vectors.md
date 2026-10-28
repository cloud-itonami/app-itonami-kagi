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

## Native result (2026-10-28)

`test/native/s0a_gate.sh` builds and runs a gate with the lock-pinned
compiler (amu `2c6be47e`, F3 `bcebb888...`) and the two pinned owner sources
(sha2, ed25519; digests match `native-local-host.lock.json`), in an arm64
Linux VM (the machine's existing podman applehv VM; nothing was downloaded).
Artifact `s0a-gate` SHA-256
`841805d4f621441aa20dfa98523536fb49005f3e7bd5def297f7dbc6e9783d4b`;
assembly `84109c32c811fe3cd42700998c958ada9628a869571a67e3f5f44425495da45d`.
The build was repeated through the committed script and reproduced both
digests.

7 of 7 checks pass: the public key from the seed, and for each case the
SHA-256 of the canonical TransferBody and the Ed25519 signature over the
transfer-id text all equal the oracle. A mutation (one hex digit of one
signature changed) gives 6 of 7 with exactly that case failing.

## What is not established

- Base32/base58btc/base64url, i.e. computing the transfer-id and did:key
  text natively from the TransferBody (JUN-501 S0-b). The gate checks the
  signature over the transfer-id text given by the vector, not the CID text
  derived natively.
- The funds role, its own signing domain, policy limits and the mutual
  binding (S0-c to S0-e) are not implemented.
- This is not custody evidence: the build runs on a development VM with
  public test seeds. The host remains a local software custody candidate
  (`independentCustody=false`, `productionQualified=false`).
