# Current policy and real cryptographic envelope

On 2026-11-05 the current Kagi policy, provider-response validation,
`github-checkpoint-seal-approved`, credential envelope and updated synthetic
integration test were assembled with source-locked crypto/JCS dependencies.
The source lock was checked and the generated native Darwin ARM64 image ran
with real X25519, ML-KEM, ChaCha20-Poly1305 and Ed25519 code. A synthetic
eligible token sealed, signed and opened; wider repository selection,
expired response, wrong HTTP status and a duplicate token field in an
otherwise complete response were refused. The test returned its full bitmask
31. No real token, request or GitHub operation was used.

The candidate intentionally validates repository selection in both the policy
and token-response layers. Removing only the token-response selection check
still returned 31 because policy rejected the wider scope first. Removing both
selection checks produced 29, exposing the wider-selection negative case.
This is a two-guard mutation, not evidence that either individual layer alone
was tested here. The complete duplicate-key input avoids the earlier weak
case that was missing other required fields and would have failed regardless.

The pinned compiler and diagnostic packager SHA-256 were
`920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6` and
`f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d`;
both signatures were checked. The integration test source SHA-256 was
`438db1c5ccef459a1d089a78df809612f95cd78ea54989674f2c34ee25df66cf`.
Source-lock and signed image SHA-256 pairs:

- Current: `c1426f748aba81dff6c28ed1138390a5d25151bffeb22ad07351779f62bc6f4c` / `b8da3861e65d953a729634c7c890528e519da453fd6207a97f9da87f9d8eca83`.
- Token guard removed: `f028b7400259f64d3550b9cea2fd4c1282cb95cd1cef3a1eec6b9a7d838de6e0` / `719445f82c83bc6838fe1651c764f1b6506e369322c12cdb1a837862a9937f89`.
- Both guards removed: `d2de90fa186353148d47d2cc3b73766eeb6edf5b7dd924929c4e677318a0ea3d` / `9e7c5a3bc187a96d0c77abbcd6e627535c7d60ec6bf9866235b4d0315435d680`.

The fixture processes had a three-second CPU cap without a hard memory cap.
The earlier version of `verify.py` had SHA-256
`e1b2fd01b72a16a466b8f979b08c3f78d3761e39064b4c86e6724d058005325d`
uses local absolute paths and historical pinned crypto dependencies. This is a
synthetic integration test, not a production broker. The authenticated
requester, App issuer, HTTPS transport, actual installation token, secret
storage/delivery, revocation, replay handling, and runtime source closure are
still unqualified. It does not qualify a resource governor or bot deployment.

## Signed issuance composition

`github-checkpoint-signed-issue` now composes the existing approved seal
with an issuer signature over the exact recipient, provider expiry and
canonical context. It returns `signature(64) || envelope`, or an empty vector
on refusal. It requires the independently supplied issuer public key to be a
valid prime-order key and to match the supplied 32-byte seed. This is a
byte-level experimental component: it does not authenticate the host inputs,
protect or erase keys, issue a GitHub token, enforce replay, or reconcile an
unsealed upstream token.

The updated source-locked native fixture returned bitmask 255: in addition to
the previous controls, the newly composed output opened successfully; a
different valid issuer, a short seed and a tampered signature were refused.
The token-selection-only mutant still returned 255; removing both selection
guards returned 253. Removing the seed-to-issuer match returned 191, showing
that the valid-but-different issuer case exercises that check. Current source
SHA-256 values: issuance component
`f6fbe14bf4d0d71c185a82c3192b5ee95a1e16678fffad9ea3b5d5179f638b4d`;
test `16f7ca48fe3f8b5fc50bf5a937d2d1e2fd65b14c18260a13b21359a893ef2fc4`;
test harness `e478157cb8e8456172170f2fa42d4bc4d5df22f9bfe12be03a479cce606d5e15`.
The current signed image SHA-256 was
`fc36bf13cdbea088f7694fe5861be2825bc40e3059c3fa539460538f73ee1d85`;
its source lock SHA-256 was
`14ecff001183ab4a00745d11a052054ca1946ea88890ceaa7a42d1020e205a49`.
The source-locked diagnostic used synthetic data and the same compiler,
packager and CPU limit above. Full host, GitHub and governor gates remain open.
