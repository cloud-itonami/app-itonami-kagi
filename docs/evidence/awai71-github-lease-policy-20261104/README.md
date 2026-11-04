# GitHub lease policy candidate

`github_lease_policy.kotoba` provides a pure request decision for an exact
repository and authenticated principal, fixed `checkpoint-archive` purpose,
contents read/write permission and owner-supplied maximum/requested TTL. A
separate decision rejects a returned provider expiry that is not later than the
trusted clock or exceeds the requested deadline. The owner must first verify the
policy signature; the host must authenticate the requester and supply a trusted
clock. The issuer must independently enforce repository selection and exact
GitHub permissions, verify the response, seal the secret to the requester,
journal the lease and handle revocation/unknown outcomes. None of those are
implemented or implied by a `lease/request-eligible` result.

The `contents:read` and `contents:write` labels describe only contents access;
GitHub's required metadata read access and the complete provider permission
response must be checked by the future issuer. This candidate is not wired to
CLI, host, a signer, GitHub or Itonami. No token is created or handled.
Rejecting a provider expiry beyond a requested shorter deadline is deliberate;
the broker must not assume that a locally shortened lease invalidates an
otherwise valid provider token.

On one Mac, a selected unity of the actual policy forms and native source cases
passed the previously staged Amu source check and executed with a signed
native diagnostic packager. It checked exact repository, wildcard rejection,
principal, purpose, permission, TTL and expiry boundaries; a mutant that
ignored repository mismatch failed. Fixture SHA-256:
`bf43ae0489c3fd53de11354ebf24495113878ff112421bea4a3df21113cad781`;
signed test image SHA-256:
`d957f306dd3d683250c4cc4da0d82511e12e042ffba1f8e5d34276e8464d8c99`.
The fixed diagnostic compiler required the test unity to export only `main`;
the module's independent export/import closure, selfhost build, real signed
policy, host and GitHub behavior remain unqualified.

## Scoped request and normalized provider metadata

The candidate now requires a positive, exactly representable repository ID in
the authorized request budget and constructs a non-secret GitHub installation
token request body with exactly that one `repository_ids` entry and contents
read/write plus metadata read. The trusted issuer must independently bind the
ID to the owner-approved full name and installation. GitHub documents that an
omitted repository restriction can grant access to all repositories in the
installation: <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>.

A separate function checks **already parsed** non-secret provider metadata:
one selected repository, exact name and ID, exactly the requested contents
permission plus metadata read, and a valid bounded expiry. Missing or extra
scope/permissions refuse. It is deliberately conservative and may reject a
legitimate response that has a different documented representation; actual API
compatibility has not been tested. Caller-supplied counts alone are not proof of response contents. The lower-level
metadata function does not accept token bytes and must not be used as a
substitute for validating the authenticated provider response.

The updated selected source composition passed the pinned diagnostic Amu
source check and the local signed native fixture, including exact request body,
invalid ID, repository/permission/expiry refusals, and the repository-match
mutant. Source SHA-256 was
`97b7c5bb0f3c533869eee3bb9567d02aeaa97821725ab324fe80d38d2af69881`;
signed fixture SHA-256 was
`2fe0aaa64dd839e5270fdcd69a43d79830cc52e6622637ed630b93c6282d67b3`.
No App, credential, network request or token was created by this test.

## Bounded provider JSON validation

`github-lease-provider-response-problem` validates one bounded response using
`jcs.reader` (which refuses duplicate and escaped keys), checks a nonempty
ASCII-safe unescaped token in place without decoding or returning it, and binds
one private selected repository's name and ID, the exact two allowed
permissions, and the response expiry. Its timestamp parser accepts only UTC
second timestamps for years 2020–2100 and rejects invalid calendar dates;
fractional/offset timestamps conservatively refuse. The response bytes still
contain a secret and must stay within a trusted host's bounded protected memory;
this pure check does not implement secure erasure, locking, transport or seal.

A signed diagnostic Mac native fixture composed the actual reader, policy and
synthetic non-secret provider examples. It tested acceptance and refusal for
wrong ID, multiple repositories, public repo, too-broad/extra permissions,
duplicate keys, empty or escaped-control token, expired deadline and invalid
calendar values; the repository policy mutant still failed. Selected source
check and native execution passed. Fixture SHA-256:
`72b8c929bf12382ab318c04f82ae326c25bd4a5e5d3673a94e9a5bb68fb4a2ab`;
signed fixture SHA-256:
`408784f502e2d94e6755d33ec433ac6a75fbb2b713c13b94589d459b7b3beee6`.
These are synthetic fixtures, not a live GitHub response, authenticated TLS,
provider response compatibility, authorization, token sealing, revocation,
qualified host or selfhost build.

## Current token format and HTTP outcome

The initial 512-byte, alphanumeric-only lexical envelope would reject GitHub's
current stateless installation tokens, which may contain dot separators and
are about 520 bytes. GitHub asks integrators to treat these tokens as opaque:
<https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out/>.
The candidate now accepts 1–8192 unescaped visible ASCII bytes except quote
and backslash, without interpreting a prefix or JWT claims. This remains a
conservative transport envelope, not proof that all future provider formats
will fit. Control characters, JSON escapes and excessive length refuse.

The response validator also requires the trusted transport's HTTP status to be
201 and refuses any top-level `error` member. GitHub documents 201 as the
creation response: <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>.
A signed native Mac synthetic fixture accepted a dot-separated token exceeding
520 bytes and refused a token over 8192 bytes, a non-201 response, and a
contradictory error member. Separate mutants bypassing repository match or
HTTP status caused the fixture to fail. Fixture source SHA-256 was
`114c3f3e708ffc0f4e2257698bbf994ca0cb42be24bda97e9d27f533ec8191b0`;
signed positive image SHA-256 was
`20f21d30fb14422fc4bb1107ed85b4dcf4b198be953015e9a3b99360974f43ee`.

The response is still synthetic. The trusted host must bind status and body to
the same authenticated response, protect and erase secret material, enforce
issuer/repository policy, seal and revoke tokens, and fail closed on unknown
outcomes. Actual GitHub compatibility and selfhost remain unqualified.

## Reproducible source-pinned diagnostic gate

`test/native/github-lease/gate.py` accepts explicit SHA-256-pinned signed
compiler and packager inputs and an explicit reader file. It requires the JCS
reader SHA-256 `f8af2953904bd0a96e7b5c3b9e34151bcae3754e5358669adb8ac289acc0872f`,
which matches `kotoba-lang/kotoba` commit
`d04a7564c75faf182fa6effe46a7bb80ebc7a4a5` at
`lib/org.ietf.jcs/kotoba/jcs/reader.kotoba`. The test-only Python assembler
strips namespace headers, builds an explicit `main` fixture and two guard
mutants, signs locally, executes them and rechecks source/tool bytes. A local
Mac run passed; fixture image SHA-256 was
`20f21d30fb14422fc4bb1107ed85b4dcf4b198be953015e9a3b99360974f43ee`.

With `--sha2 /path/to/sha2/core.kotoba`, the gate also builds and executes
`kotoba/kagi/github_lease_assemble.kotoba` using the SHA-256-pinned owner
source `2c59ef55bc2b527c1aac723c0fee896eba75ee82fecd212a2858782beadc6888`.
The native assembler's output matched the Python fixture byte for byte; it
refused an incorrect policy digest and an existing output. The diagnostic host
must supply trusted source digests and an exclusive, host-owned FD3 directory;
it must prevent path aliases and concurrent input modifications. The Python
harness still bootstraps the diagnostic and independently checks its output.

This gate is an independently pinned diagnostic, not Kagi's production native
component assembler, a verified source-lock/import build or production CI.
It has no network or secret inputs and does not qualify issuer, sealing,
authentication, host or selfhost. Before integration, the native build must
bind the reader and the actual imported module through its own reviewed lock.

## Non-secret GitHub App JWT signing input

The policy candidate now constructs the unsigned `header.payload` bytes for a
GitHub App RS256 JWT, with a positive numeric App ID, `iat` 60 seconds before
the trusted caller's time and `exp` 300 seconds after it. Invalid or
unrepresentable ID/time inputs return empty. The encoding uses unpadded
base64url and contains only fixed JSON plus decimal numbers. GitHub documents
RS256, the issuer, clock-skew recommendation and a maximum expiration window:
<https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app>.

The pinned local Darwin native diagnostic accepted an independently generated
fixed test vector, rejected invalid App ID/time, and detected separate clock
guard and expiry mutations. Its native diagnostic assembler also reproduced
the selected source fixture. Policy/source-unity/image SHA-256:
`88f8d4c590f7e4ed3b1909da782563e860858056e594104d7812bbff40a65b9f` /
`124ed0a946763740dc1bf19dbbaf37434f30f489346dbce6844f5aa793a7e8f3` /
`07130d634d8216352404e8d8b7db472dc6aa625173d1703ab1c792f6defb96ae`.

This is only an unsigned input, not a JWT or an authorization. Trusted clock,
issuer binding, RS256 private-key custody and signing, GitHub transport, token
issuance, sealing, revocation, host integration and selfhost qualification
remain open. No secret, real App or GitHub issuance was used in this test.

## Main envelope integration and contradictory provider responses

The draft incorporates Kagi main `7d9467d` as a merge parent, bringing in the
experimental checkpoint response and encrypted-envelope components from #60.
That is branch integration, not evidence of a host or broker deployment.
The merged checkpoint token parser previously allowed an HTTP 201 response
with both a valid-looking token and a top-level `error` member. It now refuses
such a response before returning a token or expiry, consistent with this
draft's separate provider-policy validator.

A local signed Darwin native source-unity diagnostic composed the selected
current JCS reader, checkpoint token parser and its synthetic response cases.
The original groups passed, a normal response still passed, and a response
containing `error: null` was refused. A separate image with only this guard
removed failed. Source/unity/image SHA-256:
`ab55b7e7e2f89797c0a869d371167366163185133c3d4103e9ec12f47aed8e4f` /
`24388684e9f2d15cf69c20fa8efdf4a22e6a8d77d087f1d21a11aea1cf648307` /
`cd93056e99cd793d154e9ec69581a0888449f9bef8bf3d1fa324528cdab13a8b`.
The diagnostic does not run the integrated encryption or an actual provider.

These are still distinct interfaces: the request policy uses
`checkpoint-archive`, accepts read or write requests and bounds opaque token
text at 8192 bytes; the checkpoint envelope fixes `bot-checkpoint`, write
access and a 4096-byte plaintext bound. Their meanings and seconds/milliseconds
must be explicitly reconciled before any issuer composes them. In particular,
a provider token rejected after issuance is an outstanding credential that
requires revocation or expiry reconciliation; it must not be silently retried.
No such reconciliation, secure host, real App or token is implemented here.
