# Native funds role (JUN-501 S0-c, ADR 0021)

The pure core (`kotoba/kagi/agent_signer.kotoba`) gains a third policy role,
`funds`, with exactly one purpose, `en-transfer`:

```
kagi.agent.policy.v1 funds SCOPE AUDIENCE DELEGATE en-transfer MAX_TTL_MS
```

`agent` and `node` policies are unchanged, and `en-transfer` is admitted only
for `funds` (an `agent` policy with `en-transfer`, or a `funds` policy with
another purpose, is a `signer/role-purpose` refusal).

## A separate signing domain

An ENGI transfer is accepted when its spender's `self-sig` is a plain Ed25519
signature over the UTF-8 text of the transfer-id (`engi.crypto/sign-transfer`).
The agent/node author signature is over `kagi.agent.action.v1\n` + permit.
The two must never be interchangeable:

- `kg-sign` now refuses a `funds` policy (returns empty), so a funds permit can
  never yield an action-domain signature;
- `kg-sign-transfer` signs only under a `funds` policy and an `en-transfer`
  permit, and signs the transfer-id text, not the permit.

## What `kg-sign-transfer` checks

It runs the same gate as `kg-sign` (`kg-permit-problem`: active keyset, policy
pin, head/epoch, exact purpose/scope/audience, writer fence and parent,
`lastSequence + 1`, deadline, delegate signature) and then:

- the seed must derive the keyset's current author key; the spender is that
  key's did:key, computed in the signer, never supplied by the caller;
- the receiver must be `did:key:z` followed only by base58btc characters, so no
  space, newline or other character can add or change a body field, and it must
  differ from the spender;
- the amount is a canonical positive decimal; `ts` a canonical number; `nonce`
  and `spender-prev` are kagi labels;
- the signer builds the canonical TransferBody itself from those fields and
  requires its SHA-256 to equal the permit's body digest. The delegate's
  signature therefore commits to this one transfer, and the signer never signs
  caller-supplied bytes.

The result is the base64url signature, or empty on any refusal. As with
`kg-sign`, persisting replay state before releasing a signature is the host's
job.

## Evidence (2026-10-28, this source, pinned compiler and owners)

Same pinned `amu-root` and owner sources as the host lock, in the existing
arm64 Linux VM. Gate: `sh test/native/s0a_gate.sh COMPILER OWNERS NEW_DIR s0c`
(vectors from `test/native/s0c/gen_vectors.py`, an OpenSSL/hashlib oracle that
first reproduces the pinned agent genesis digest and proof).

- S0-c gate: 23 of 23 pass, including the ENGI signature match, transfer-id and
  did:key built in the signer, role/purpose admission, action-domain refusal,
  agent-role refusal, changed amount, smuggled receiver (with and without a
  permit committing to it), self-transfer, non-did:key receiver, zero and
  non-canonical amount, replay, expired and future permit, bad delegate
  signature, wrong author seed, short seed.
- Mutation: removing the body-digest binding fails exactly the changed-amount
  check; letting `kg-sign` accept funds fails exactly its refusal check;
  removing the receiver screen fails exactly the smuggled-receiver check that
  the permit commits to (the first version of the gate missed this, because
  the digest binding hid it; that case was added).
- Regression with this core: the 32-case core gate 32 of 32; S0-a 7 of 7;
  S0-b 8 of 8; a host built from it passes `host_gate.py` and
  `agent_host_gate.py` (exit 0 each).

## Not established

- `native-local-host.lock.json` still pins the JUN-299 build. This core changes
  `kotoba/kagi/agent_signer.kotoba`'s digest and the host artifact (a host
  built from it has SHA-256
  `78b4532b4dfc86d2881310171b1f5e2e478b901302b19439421d24f2a3cb2958`). The lock
  is not refreshed here; that is S0-g.
- No host command signs a transfer yet: journalling a funds operation
  (sequence, parent, durable commit before the signature is released) and the
  CLI surface are not implemented. The core function is pure.
- Recipient allowlist, per-transaction and daily limits (S0-d), the mutual
  binding with the identity keyset (S0-e), and process isolation / kill switch
  measurements (S0-f) are not implemented.
- Not custody evidence: public test seeds, a development VM, no independent
  guardian. The host remains `independentCustody=false`,
  `productionQualified=false`.
