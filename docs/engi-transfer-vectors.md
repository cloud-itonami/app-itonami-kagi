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

## S0-b: text encodings derived natively (2026-10-28)

`sh test/native/s0a_gate.sh COMPILER OWNERS NEW_BUILD_DIR s0b` (same pinned
compiler and owners; artifact SHA-256
`af1d0cf993ba23bbfcf1a27dd39e88d583183624c08f43c2c5819f2687d5b213`, assembly
`eca3a72a5d081a95ace94e2e3997c2f1414a47bd710cb514a5fdbd16811dd70e`) computes
in native code, from the canonical TransferBody text and the public seed:

- the transfer-id (`b` + base32-lower of the CID header and SHA-256),
- the did:key (base58btc of `0xed 0x01 || pub`),
- the base64url Ed25519 signature over the transfer-id text,

and compares each with the ENGI vector. 8 of 8 pass (including a leading-zero
base58 case and a negative control that an altered body gives another
transfer-id). A mutation of one transfer-id character in the vector fails
exactly the two checks of that case (6 of 8 pass). The S0-a suite still
passes through the same script with the unchanged artifact digest.

The codec functions live in the gate file only (a prototype for the funds
role); moving them into the signer needs an assembler and lock update (S0-c).

## What is not established

- The canonical TransferBody is taken as the vector's text; assembling it
  from receiver, amount, nonce and ts inside the signer is part of S0-c.
- The funds role, its own signing domain, policy limits and the mutual
  binding (S0-c to S0-e) are not implemented.
- This is not custody evidence: the build runs on a development VM with
  public test seeds. The host remains a local software custody candidate
  (`independentCustody=false`, `productionQualified=false`).
