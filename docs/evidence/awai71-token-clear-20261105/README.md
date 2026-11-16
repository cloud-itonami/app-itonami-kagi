# Temporary issuance token buffer

The issuance composition overwrites its extracted token vector after the seal
call returns, including a refused seal. This is a best-effort overwrite of that
specific vector, not a guarantee for the HTTP response, crypto intermediates,
allocator copies, traps, or OS memory. The host still owns secret handling.

A selected-source native fixture used a stub sealer that aliases the synthetic
plaintext as its result so that the test can observe zeroed bytes. The normal
fixture passed; removing the `gi-clear!` call made it fail. The fixture image
SHA-256 was `5943549d4996409abba53e8cf1cc369aa74e230b7de939b999b7761bb00dc94c`;
source unity SHA-256 was
`64ff214b03f3fbbad55e8df657a6135549319c589504196fbfae0b78ff453257`.
The test uses a stub, not the production seal implementation. The separately
pinned selected-source native crypto composition fixture passed bitmask 255
with real crypto code and synthetic input after the change; signed image
SHA-256 `7721685431ee61cdfa4e5492b739359d2d4dc7a47335880d06bff124106b9cc6`,
source lock SHA-256
`5ce1ba38f6b9a4a43a8c8a28da4fa4c78286a9428ff8f64241ca433ff1782e79`.

Both diagnostics used pinned signed compiler and packager images and a
3-second CPU limit without an independent hard memory cap. `check.py` derives
its focused test from the checked-in gate and uses local absolute paths; it is
not a portable production build. No real credential, broker or GitHub request
was used. The native issuer, transport, sandbox and resource governor remain
unqualified.

The checked-in `test/native/github-lease/gate.py` was also run without its
optional native-assembler input. Its positive and repository, HTTP, JWT clock,
JWT expiry, token error, policy and token-clear mutant controls all passed;
`nativeAssembler` was false. The previously unbuildable stub integration
fixture was scoped to the approved-seal functions; the separate real-crypto
fixture above continues to cover signed issuance. These checks do not qualify
production token handling.
