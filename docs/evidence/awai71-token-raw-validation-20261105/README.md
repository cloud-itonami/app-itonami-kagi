# Token response raw validation diagnostic

The token response validator now inspects the complete JSON token string in its
original byte vector instead of decoding a temporary plaintext vector merely
to validate it. It refuses JSON escapes, matching the separate issuance policy;
actual token extraction still produces a plaintext vector. The original HTTP
response, extracted token, cryptographic temporaries and operating-system buffers
remain sensitive. This change does not establish erasure or a secure host.

On 2026-11-05 a selected-source native Darwin ARM64 diagnostic assembled the
pinned JCS reader, token validator and token tests. The positive case passed
(bitmasks 255, 511, 7). A mutant removing the backslash refusal failed. New
negative cases cover valid JSON Unicode and slash escapes. Synthetic inputs only;
no GitHub token, HTTP request, production issuer or end-to-end bot was tested.

The diagnostic used the signed experimental compiler and packager pinned in
`check.py`, and a 3-second per-child CPU cap without a hard memory cap. Source
unity SHA-256: `1ede48380f7bb27cc5b643d39fd897671caee6972572f010509109fac878030c`;
signed test image SHA-256:
`45042d450bb79b64ceede4000293feaf86c59923e4ad9d7ecf79a554d52f39ab`.
The local script records specific temporary dependency paths and is a diagnostic,
not a portable production build or selfhost qualification.

## Cryptographic composition regression

After the raw-validation change, `integration.py` reran the valid selected-source
fixture with its pinned JCS and cryptographic dependencies. The native image
returned the expected bitmask 255 for synthetic sealing, signing, opening and
refusal controls. Its signed image SHA-256 was
`45e65b2830f780df34ff3568beb9c20637addd4cf7dea5691a96059aede2c8c2`, and
its source lock SHA-256 was
`33c217f10364eef2bc23494997c32c5df818415464c39dd5cfade3df8d0e2edd`.
The script derives from the archived `awai71-policy-crypto-current-20261105`
operator with only the valid case enabled; it uses absolute local paths and
3-second per-process CPU limits, without a hard memory cap. This does not test
real credentials, HTTP transport, host isolation or governor qualification.
