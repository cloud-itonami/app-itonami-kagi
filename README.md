# kagi — native agent keysets and signing authority

Owner direction, 2026-10-23: use canonical Kotoba / Amu selfhost without
JVM dependencies. Old keys and vault migration / compatibility are out of
scope. Existing user key data is not read, changed or deleted.

The native v1 foundation is `kotoba/kagi/agent_signer.kotoba` and
`kotoba/kagi/cli.kotoba`. The agent owns its keyset and signing policy;
node operator keys, recovery governance, delegated sessions, encryption
keys and financial authority remain distinct.

`bin/kagi` is a symlink to the installed `target/native/kagi` ELF, with no
shell interpreter, JVM discovery, CLJK hook, Node or compatibility fallback.
Without that native artifact it cannot start. The currently selected target
is native Linux arm64, including a Linux VM on macOS; this is not a native
macOS executable or qualification of other targets.

## Current component surface

- SHA-256-pinned keyset genesis, parent / epoch validation and explicit
  author rotation, revocation, recovery and management-policy changes.
- Up to three independent Ed25519 management signature slots with a
  configurable threshold. This is individual multisignature validation,
  not shared-secret threshold cryptography.
- Author possession proof, separate management / author / action domains.
- Exact-purpose / scope / audience policies, delegate signatures, bounded
  TTL, sequence, parent head and writer fence checks.
- Native `help`, `status`, and offline `verify-keyset <trusted-genesis-sha256>
  <public-bundle-file>`. The genesis pin is independent installer/operator
  input; the bundle cannot establish its own trust.

The native signer core passed 28 cases, including an independent OpenSSL
signature oracle, plus mutations removing management / delegate / replay
checks. This is a component gate, not production key-custody qualification.
The scope string is an exact policy identifier; it does not admit a mon,
validate a CID, create a Cell or execute an application by itself.

## Remaining native integration

Native private key generation/storage, durable replay/audit state,
constant-time / secret-memory qualification, signed node registration,
hata Cell execution, persistent stdio, Murakumo / Yataverse connection and
restoration are not yet admitted by this foundation. `status` reports
custody/node/Cell as unqualified/unconnected. No private seed is exported.

The admitted Amu root refused native entropy / clock. Their native
replacement in [Amu PR #1518](https://github.com/kotoba-lang/amu/pull/1518)
now passes arm64 provider gates, ENOSYS / grant refusals, combined compiler
self-rebuild and 24 exact runtime regressions. It remains a candidate pending
full qualification; no bootstrap root has been replaced.
Native file metadata, private creation and durable journal operations need
their own runtime gates before operational custody.

See [native format and evidence](docs/native-agent-signers.md),
[agent sovereignty ADR](https://github.com/network-awai/network-awai-apex/pull/47),
and [JUN-299](https://linear.app/kotobalabs/issue/JUN-299).

## Build and CDCI

Use the pinned Amu selfhost-built compiler and reviewed SHA-256 / Ed25519
source pins. Local source-unity diagnostics do not qualify a project linker,
installer or native CDCI controller. Native artifacts and their source locks
must be verified before installation at `target/native/kagi`.

`kotoba/kagi/assemble.kotoba` is the native component source assembler. It
checks the pinned owner digests before assembling the CLI or test gate;
changed owners and existing output are refused. The native path reproduces
the verified CLI artifact byte-for-byte.

The former JDK 24 / Clojure / Node workflow was removed, without leaving a
disabled fallback. No replacement CI success is claimed. See
[AGENTS.md](AGENTS.md) for the retired checks and open native controller gate.
Old CLJK sources and [the former README](docs/history/legacy-vault-README.md)
are historical migration inventory, not a supported execution route.
Root `deps.edn`, `nbb.edn`, npm manifests and hosted phase tooling are
retired to `docs/history/*.txt`; they are not active dependency manifests.
