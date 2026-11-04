# Experimental GitHub checkpoint lease context

The credential envelope candidate now has a narrow `github-checkpoint-context`
and `github-checkpoint-open` profile. It binds the fixed
`cloud-itonami/itonami-bot-state` repository, contents-write/metadata-read
permission description, `bot-checkpoint` purpose, host-provided principal,
audience, nonzero 64-hex lease ID and issue/expiry times to the existing
recipient-encrypted issuer signature. The interval is at most one hour;
opening requires `issued <= now < expires` using host-provided milliseconds.
The context is reconstructed from independently trusted caller inputs rather
than accepted from an envelope as authorization.

The local macOS ARM64, source-locked native test returned full bitmasks
**7 / 63 / 63 / 63 / 127 / 63** for groups A–F. The profile tests cover a
valid signed open, before-issue and expiry boundaries, mismatched principal
and audience, malformed identifiers, ASCII label rejection, the exact one-hour
bound and i64-endpoint arithmetic. Removing the expiry comparison produced
**123** instead of 127. All keys and token bytes were synthetic. The compiler,
packager and pinned upstream source revision are as in the accompanying
credential envelope evidence; source locks are in the sibling directory.

| Image | Source-lock SHA-256 | Signed image SHA-256 |
|---|---|---|
| A | `16c6bb63b471f033440eaf605771ad14f3c4975a921af43298701b09de2c32c4` | `fe34ff8466af6ba1526219f30903afaafc89526dd07eab96add8e5ad13016f84` |
| B | `e02afc8b193e8438c2fe64ce34809b7e3d6f4c30ed4c297668dbf78cd0ab18d3` | `cb60ec7c587811da6ebf5aa38787e58806b8a885857392b49e98f29646a1a28c` |
| C | `89c2dcf6dbaa783e83c50e23147b83c91f79de0e3da83b06e340ce92ffaf2859` | `8f82b23f239a7fcde49303d2e220e1db75a39b6b4eff7128193407cbc7f7ad65` |
| D | `9f234bd4c443bb9ab4957f874093a1712d35cebf43152b4ec18f9a777a4991fd` | `5fc7fe89999815ece003466a3a1eaedc8b6b08044e5907ded55b91b9b5f2f0b6` |
| E | `7f53805e2845041634ff8d694feea4863eb574dedac72865f65162e4c65f54a7` | `63bf5a16648c384380920414aa900693b94d01027414f30758be47e67f8e2beb` |
| F | `d2f4c996297a0fbb3bad10c3001b9ff59ace0d62f88dc67011bd6c001e8f0208` | `dda3a1c60f07e0b985c963921f112c9e8be273e10fc09a0e53b73dfd6b6f6271` |
| expiry mutant | `86a310cd713ebb8b2a8c21304e91069c27e90b00466549616827c16e44ffa2d6` | `c94a431906adbaa82404ab99bc70af6dba6e64f1114484c4b66d881b669035fa` |

This candidate does not obtain or verify GitHub's actual token permissions or
expiry. A trusted host must pin and authorize issuer and recipient, obtain a
trustworthy current clock and GitHub-reported expiration, enforce revocation,
replay, secret isolation and secure random generation, and supply the expected
contract independently of the sender. No real GitHub credential, broker,
network, bot or production host was exercised. A valid signature alone does
not authorize opening, and the code is not production qualified.
