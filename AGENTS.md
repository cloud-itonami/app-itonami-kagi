# kagi native architecture

Owner direction 2026-10-23: kagi must not depend on JVM; old keys and vault
compatibility / migration are not required. Preserve existing user key data.

- Canonical implementation: `kotoba/kagi/*.kotoba`, compiled by Amu selfhost
  to a loaderless native image. No JVM, Node, NBB, KBB, hosted compiler or
  C compiler/loader fallback in build, packaging or execution.
- `bin/kagi` dispatches only the installed native artifact. Unavailable
  commands fail closed. Never silently read `~/.kagi`, import old keys or
  delegate to old CLJK entrypoints.
- Agent author keys, node operational keys, recovery governance, delegated
  sessions and data encryption / financial authority are distinct. App
  containers, browser UI and LLMs never receive persistent private seeds.
- Pin genesis independently of untrusted bundles. Verify management
  signatures, author possession, parent / epoch and purpose / scope /
  audience. Clock, writer fence and replay journal are trusted native host
  inputs, not app-supplied booleans.
- Old `src/` CLJK and helper scripts are migration inventory, not a supported
  final runtime. Do not restore them to fill an unqualified native feature.
- Root JVM / nbb / npm manifests and the hosted phase script are retired to
  `docs/history/*.txt`. They must not be restored as build/runtime fallback.
- Honor the workspace canonical client-runtime and per-operation browser
  consent contract. Native bot delegation does not mint browser consent.

## CDCI retirement

Removed `.github/workflows/ci.yml`: JDK 24, Clojure, Node, phase JS/Wasm
matrix, security adoption, JVM suite, WebAuthn PRF and JVM lint.
No replacement CI is claimed. The signer gate is a local native component
gate; native x86_64 controller / CDCI qualification remains open. Retired
tests do not become covered merely because native source exists.
