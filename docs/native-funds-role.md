# Native funds role (JUN-501 S0-c, S0-d and S0-c2, ADR 0021)

The pure core (`kotoba/kagi/agent_signer.kotoba`) gains a third policy role,
`funds`, with exactly one purpose, `en-transfer`:

```
kagi.agent.policy.v1 funds SCOPE AUDIENCE DELEGATE en-transfer MAX_TTL_MS MAX_AMOUNT DAILY_CAP ALLOWLIST_SHA256
```

A funds policy has ten fields (agent and node policies keep seven); the
original seven-field funds shape of S0-c is refused. The last three fields are
the S0-d limits below. Because the policy line is pinned by the keyset's
policy digest, changing a limit needs a guardian-signed `govern` event; the
agent, the delegate and the host cannot change it.

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
- S0-d limits (`kg-funds-limits-ok?`): the amount is at most `MAX_AMOUNT`;
  `spent + amount` is at most `DAILY_CAP`; the allowlist text hashes to the
  pinned `ALLOWLIST_SHA256` and lists the receiver as a whole line. The
  allowlist is `"\n"` followed by one did:key and `"\n"` per receiver, passed
  with the request and accepted only if it matches the pinned digest. `spent`
  (the amount already signed in the current window) is supplied by the host
  from its journal; the pure function neither keeps nor resets it. A policy
  with a cap above the daily cap, a zero cap or a non-hex digest is refused
  (`signer/funds-limits`);
- the signer builds the canonical TransferBody itself from those fields and
  requires its SHA-256 to equal the permit's body digest. The delegate's
  signature therefore commits to this one transfer, and the signer never signs
  caller-supplied bytes.

The result is the base64url signature, or empty on any refusal. As with
`kg-sign`, persisting replay state before releasing a signature is the host's
job.

## Host commands (S0-c2)

`kagi-host` gains the funds path, using the existing private root, replay
journal and durable append:

```
init-local ROOT funds SCOPE AUDIENCE en-transfer MAX_TTL_MS MAX_AMOUNT DAILY_CAP ALLOWLIST_FILE
permit-funds-local ROOT RECEIVER AMOUNT SPENDER_PREV NONCE TS
sign-funds-local ROOT REQUEST_FILE
```

- `init-local` for a funds root writes the ten-field policy (the allowlist
  digest is computed from the file) and stores the allowlist in the root
  (`allowlist`, exclusive create). An unreadable allowlist file traps
  (fail-closed crash from the private-read capability), and an empty one is
  refused.
- `permit-funds-local` builds the canonical TransferBody itself (the spender is
  the keyset's author did:key), checks the receiver, amount and the pinned
  limits against the **journal-derived** `spent`, and has the delegate sign a
  permit committing to that body. Output: `PERMIT(13) DELEGATE RECEIVER AMOUNT
  SPENDER_PREV NONCE TS`.
- `sign-funds-local` re-runs every check in `kg-sign-transfer-hex` with the
  journal-derived `spent` and the stored allowlist, appends a
  `kagi.host.fentry.v1` entry (commit time, permit, delegate signature, author
  signature in hex, previous-entry hash, and the five transfer fields) with the
  same compare-and-append, clock and deadline checks as `sign-local`, and only
  then releases the signature (base64url, over the transfer-id) with the
  transfer-id and `spentBefore`.
- Replay (`kh-cursor-step`) accepts a funds entry only if the policy is funds,
  the permit gate passes, the rebuilt body matches the permit's digest, and the
  author signature verifies over the rebuilt transfer-id. `spent` is the sum of
  the amounts of today's (UTC) funds entries in the verified journal, so it
  cannot be lowered by editing the journal (the proof breaks) and is never a
  caller input. A funds root has no agent path, and an agent root has no funds
  path.

## Evidence (2026-10-28, this source, pinned compiler and owners)

Same pinned `amu-root` and owner sources as the host lock, in the existing
arm64 Linux VM. Gate: `sh test/native/s0a_gate.sh COMPILER OWNERS NEW_DIR s0c`
(vectors from `test/native/s0c/gen_vectors.py`, an OpenSSL/hashlib oracle that
first reproduces the pinned agent genesis digest and proof).

- Funds gate: 35 of 35 pass. Policy admission (role/purpose, old shape, cap
  above daily, zero cap, bad digest); the ENGI signature match and the
  transfer-id and did:key built in the signer; action-domain refusal and
  agent-role refusal; changed amount, smuggled or spaced receiver (also when the
  permit commits to that body), self-transfer, non-did:key receiver, zero and
  non-canonical amount; replay, expired, future, bad delegate signature, wrong
  author seed, short seed; exact daily cap signed and one more refused,
  negative `spent`, a permit-committed amount above the per-transaction cap,
  a forged allowlist that still lists the receiver, an empty allowlist, a
  receiver missing from the pinned list, and an entry that only extends the
  receiver.
- Mutations, each failing only the check that guards it: dropping the
  body-digest binding; letting `kg-sign` accept funds; dropping the receiver
  screen (first missed because the digest binding hid it, so a permit-committed
  case was added); dropping the per-transaction cap; the daily cap; the
  allowlist digest (first missed because a list without the receiver is also
  refused by membership, so a forged list that keeps the receiver was added);
  negative `spent`; and the membership check (two checks fail).
- Regression with this core: the 32-case core gate 32 of 32; S0-a 7 of 7;
  S0-b 8 of 8; a host built from it passes `host_gate.py` and
  `agent_host_gate.py` (exit 0 each).
- Host gate (S0-c2): `python3 test/native/funds_host_gate.py --artifact
  kagi-host --output NEW_DIR` passes 15 cases, with OpenSSL verifying each
  signature over the transfer-id as an independent oracle: init with limits;
  refusals before any permit (off-list receiver, over the per-transaction cap,
  zero, self); a signed transfer after the durable append; replay and a
  changed amount refused with the journal unchanged; restart recovers the
  sequence; `spent` derived from the journal (7, then 14); the daily cap
  refuses 14 + 7, signs 14 + 6 and refuses one more; lowering a journalled
  amount breaks the proof; a bad journalled author signature on the last entry
  breaks the proof; funds and agent roots do not cross.
- Host mutations: ignoring the journal for `spent` fails the daily-cap case;
  not verifying a journalled signature fails the signature case (first version
  tampered a non-final entry, which the prev-hash link also catches, so the case
  now targets the last entry).

## Not established

- `native-local-host.lock.json` still pins the JUN-299 build. A host built from
  this source has SHA-256
  `f32f4efb28f0b4379d1bd693b30429569469d67fccbca6c2a4b44dfc5ab854e7`. The lock
  and the qualification receipts are not refreshed here; that is S0-g.
- The window is the UTC day taken from the host's wall clock; the journal makes
  a clock rollback visible but there is no independent time source.
- The mutual binding with the identity keyset (S0-e) and process isolation /
  kill switch measurements (S0-f) are not implemented. Nothing submits a signed
  transfer to ENGI, and the counterparty's `counter-sig` is not produced here.
- Not custody evidence: public test seeds are not used in the host gate (it
  draws fresh native entropy), but it runs on a development VM with one
  administrator and no independent guardian. The host remains
  `independentCustody=false`, `productionQualified=false`. The limit values in
  the vectors and gate (10 per transaction, 20 per day) are test values; real
  values are governed grants (JUN-527), not decided by an agent.
