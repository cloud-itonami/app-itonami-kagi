# GitHub installation response to checkpoint envelope

GitHub states that an installation access token request without an explicit
repository or permissions inherits the installation's granted scope; the
response includes expiration, granted permissions and, where applicable,
repositories. Tokens expire after one hour. See the [GitHub App installation
token documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).
GitHub also documents a staged rollout of a new, variable-length token format;
this component does not require the former fixed length. See the [GitHub Apps
REST reference](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).

The experimental native component produces an explicit one-repository,
contents-write/metadata-read request body. It accepts an HTTP 201 response only
when strict JSON has exactly the expected permission keys, one selected private
repository matching the host-pinned numeric ID and full name, a bounded
printable token, and a future reported UTC expiry within one hour of the
host-provided clock. Unsupported timestamps or ambiguous response shapes fail
closed. `github-checkpoint-seal-response` composes this validation with the
recipient-encrypted checkpoint envelope and uses the reported expiry in the
signed lease context. It returns no plaintext token on failure.

On a local macOS ARM64 host, source-locked native response test groups returned
their documented full bitmasks **255 / 127**. They cover wider scope, additional
permissions or repos, incorrect ID, public repo, invalid status and token,
duplicate JSON fields, date/time bounds and variable token lengths. A
selection-check mutant returned **253** rather than 255. A separate synthetic
response → validate → seal → sign → lease-open integration returned **15**;
the same selection-check mutant returned **13**. No real token or network
operation was used. Source locks in the sibling directory contain the exact
source hashes; compiler and packager match the earlier Kagi evidence.

| Image | Source-lock SHA-256 | Signed image SHA-256 |
|---|---|---|
| response A | `3788f4cc570995bc95ad6f7836bbe32820f129b86ee4ac6b63df65a9e893e851` | `e6b672f9765b1d82765637dc648d0d9c7044f8a9fe95c3ea2f2684666ec60fa6` |
| response B | `4700578e8636320d611272c24ad36d182b896ba2c8a7fa15cb6576fff93f8236` | `4363b45a1218acd8fbec32292a11e59730c1bc33dc3ee73d4c02551298589bd1` |
| response mutant | `328ef7e7b814518af6f5c7dd7f679203fd4418cd9968dfe00183ce395886cc05` | `86f87808dcaa657e0ebc2595ff7959681659de73611abf7dc07b89cea8e98582` |
| integrated | `df0c38d9e9c00f9c6d2f5b3946cb28559a2423713e2e3df3eab4166548544fd7` | `7e2c23d10ae6fcdf656b38ef6d28e6148cd39d597b2655782ac6ac625dd988b4` |
| integrated mutant | `ccc68c4d8338c3a28896424ebcf213ba38f16bdbe91769f3b8b4fa3b181b3f2f` | `3dcb922fabb07ea8eb62bd3992b88401496d000e2b6b27aab4f1cbb9d7412eb1` |

The host must authenticate the endpoint and status, pin the installation and
repository ID, authorize recipient and issuer, protect response and token
bytes, enforce revocation/replay and generate secure randomness. This module
does not issue, revoke or deliver a real token, provide TLS or secret isolation,
or qualify a production host. An untrusted caller-supplied response or clock
does not confer authority. The strict expected shape has not been validated
against a real scoped GitHub App and could refuse a legitimate response.
