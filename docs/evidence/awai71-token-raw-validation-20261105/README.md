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
