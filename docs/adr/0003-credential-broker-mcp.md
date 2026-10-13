# ADR-0003: credential broker と MCP — 人がトークンを作らない

**Status**: accepted (段階 1〜4 実装 2026-10-13) · **Date**: 2026-10-10 · **Deciders**: Jun Kawasaki

データの形（issuer / credential request / lease）は kagitaba ADR-0002 が持つ。
本書は kagi 側の振る舞い: 発行（mint）、方針（policy）、承認、MCP 面、消費。

## 背景

2026-10-10、Hermes profile をフリートのノードへ移す作業で「各ノードに GitHub の
読み取りトークンが要る」と分かった。手元にあるのは持ち主の個人トークン
（`repo` `workflow` `delete_repo`）だけで、これを 5 台に配るのは権限が大きすぎる。
最小権限のトークンを作るよう持ち主に頼んだが、答えは「トークンがわからない」だった。

これは個別の事故ではなく構造の問題:

1. **長期トークンを人が作る前提**になっている。どの権限が要るか、どの org に効くか、
   いつ失効するかを人が判断し、値を手で運ぶ。fine-grained token は org ごとに 1 本で、
   フリートでは本数が増えるほど誤りやすい。
2. **配った長期トークンは取り戻せない**（ADR-2608281100 の agent grant と同じ限界）。
   漏れれば失効まで有効。
3. **agent（Claude / Hermes）が頼む経路がない**。agent が「この repo を読みたい」と
   言えるのは人に向けた文章だけで、値は人を経由する。

## 決定

kagi を **credential broker** にする。長期の根（issuer）は vault の中から出さず、
agent には **用途・範囲・期限を絞った短命の資格情報（lease）**を発行する。
agent はそれを **MCP** で頼み、平文はモデルの文脈を通らない。

```text
人（1 回だけ）: GitHub App を 2 クリックで作成・インストール ──▶ issuer（vault 内）
agent ──MCP──▶ credential_request {github, contents:read, repos, 1h, purpose}
                     │ policy に合う → 自動発行 / 外れる → 人の承認（passkey 1 タップ）
                     ▼
        minter: issuer の鍵で 1 時間トークンを発行 ──▶ 要求者の KEM 公開鍵へ封入
                     ▼
agent の実行プロセス（git / gh / Hermes job）が自分の鍵で開く。モデルには handle だけ
```

### 1. issuer — 長期の根は vault の外へ出ない

最初の issuer は **GitHub App**。理由:

- **installation access token は最長 1 時間**で、発行時に repo と権限を
  App の権限の部分集合へ絞れる（`POST /app/installations/{id}/access_tokens`）。
  長期トークンを配らずに済む。
- **複数 org に 1 つの App をインストールできる**。fine-grained token の
  「org ごとに 1 本」が消える。
- **人の作業が 2 クリックで済む**: GitHub App Manifest flow を使う。kagi が
  manifest（名前、`contents: read` `metadata: read` `pull_requests: write` など）を
  作り、`kagi issuer setup github` が 1 つの URL を開く。人は
  「Create GitHub App」と「Install（org を選ぶ）」を押すだけ。GitHub は
  `127.0.0.1` の kagi へ code 付きで戻り、kagi が
  `POST /app-manifests/{code}/conversions` で App ID・秘密鍵 PEM・webhook secret を
  受け取り、**そのまま issuer item として封緘**する。人は値を一度も見ない・運ばない。

issuer item は owner の VMK 配下の通常の item（compartment `issuers`）。秘密鍵は
`kagi agent grant` で **minter** に指定したノードにだけ渡す（既定: ワークステーション
＋もう 1 台。単一障害点にしないため 2 台以上）。

後続の issuer 候補: Cloudflare（token 作成権限を持つ親トークンから子トークン）、
murakumo（device 鍵署名の短命トークン）、AWS STS。いずれも同じ `Issuer` 境界に乗る。

### 2. lease — 発行物は短命・封入・記録つき

`mint` は次を 1 つの原子操作として行う:

1. request を policy と照合（下記）。
2. issuer で資格情報を発行（GitHub: JWT RS256 → installation token、TTL ≤ 1h）。
3. 値を **要求者 agent の KEM 公開鍵へ封入**（既存の grant envelope と同じ形式）。
   minter 自身も封入後は保持しない。
4. **lease 記録**（秘密を含まない公開メタデータ: lease-id, issuer, 範囲, 要求者 did,
   purpose, 発行時刻, 期限, 承認者）を台帳に追記。
5. 封入物を返す。

取り消し: `kagi lease revoke <id>` は issuer 側で失効させる（GitHub:
`DELETE /installation/token`）。agent grant と違い、**発行済みの値も実際に殺せる**。
期限切れは何もしなくても死ぬ。

### 3. policy — 自動発行の範囲は人が先に決める

principal（ノード / agent）ごとの方針を owner が持つ:

```clojure
{:principal "node@joseph"
 :issuer    :github-app
 :allow     [{:repos ["cloud-itonami/*" "kotoba-lang/*"]
              :permissions {:contents :read :metadata :read}
              :max-ttl-sec 3600}]
 :approve   [{:permissions {:contents :write :pull-requests :write}
              :by :passkey}]}       ; 範囲外は人の承認が要る
```

- **allow に収まる request は自動発行**（人を起こさない）。
- **approve に当たる request は pending** になり、持ち主の端末へ通知、
  `kagi ui` か passkey（既存の WebAuthn PRF 経路）で 1 タップ承認。
- **どちらにも当たらなければ拒否**し、理由を返す（agent が範囲を絞り直せる）。

policy 自体は秘密ではないので registry と同じく vault の外（`$KAGI_HOME/policy.edn`）に
置き、変更は owner 署名つきで台帳に残す。

### 4. MCP 面 — `kagi mcp`

`kagi mcp` は stdio の MCP サーバ（kernel は kotoba-lang/org-anthropic-mcp の
`mcp.execute`）。**どのツールも長期の秘密の平文を返さない。** 返すのは handle・状態・
メタデータだけ。

| tool | 入力 | 返り値 |
|---|---|---|
| `credential_request` | provider, access（権限）, resources（repo 等）, ttl, purpose | `issued` + lease-id + handle、または `pending` + 承認 URL、または `denied` + 理由 |
| `credential_status` | lease-id | 状態・期限・承認者 |
| `credential_revoke` | lease-id | 失効結果 |
| `issuer_setup` | provider（`github`） | 人が押す URL と、完了の待ち受け |
| `policy_explain` | principal, request | どの規則で通る/止まるか（dry run） |
| `audit_tail` | principal?, n | 開示・発行・拒否の台帳 |

resources: `kagi://policy/<principal>`, `kagi://leases?active`, `kagi://issuers`。

**handle と平文の分離**: handle は「この lease の封入物」を指す ID。平文を得られるのは
要求者の秘密鍵を持つ **実行プロセス**だけで（`kagi lease open <handle>` /
git credential helper / Hermes の secrets.command helper）、それはモデルの
文脈ではない。モデルが値をログや返答に書く経路を構造的に持たない。

MCP サーバは agent の秘密鍵を持たない（ADR-2608281100 の `agent serve` と同じく
「release するだけ」）。複数の minter がある場合、request は mesh 越しに署名つきで
minter へ届き、封入物が返る。

### 5. 消費 — 1 時間の値をどう回すか

- **git**: `git config credential.helper "!kagi git-credential"`。git が操作ごとに
  資格情報を求めるたび、kagi は有効な lease を開き、期限が近ければ取り直す。
  長期トークンをどこにも書かない。
- **gh**: `kagi exec --lease github -- gh api …`（環境変数 `GH_TOKEN` をその子プロセス
  だけに渡す）。
- **Hermes profile**: secrets.command helper（gateway-hy `tools/kagi_env.hy`）が
  `hermes-env.*` に加えて lease を開く。上流は helper の結果をプロセス寿命の間
  キャッシュするので、shard host が tick 前に lease の期限を見て、期限内でなければ
  その profile の secret-source キャッシュを捨てて取り直させる。

## 影響

- 持ち主の作業は **GitHub App の作成とインストールの 2 クリックだけ**になり、
  以後の資格情報は agent が MCP で頼む。
- 配られる値はすべて **≤1 時間・範囲限定・取り消し可能**。漏れても被害は時間で閉じる。
- 長期の根（App 秘密鍵）は minter に指定した少数のノードの vault 内だけ。
  minter の侵害は根の侵害なので、minter は最小台数・passkey 承認つきで運用する。
- 発行のたびに台帳が増える（lease 1 件 ≈ 数百バイト）。期限切れ lease は日次で
  要約して畳む。

## 段階

1. kagitaba: issuer / credential-request / lease / policy の形と検証（ADR-0002）。
2. kagi: `kagi.issuer.github-app`（manifest setup、JWT、installation token、失効）、
   `kagi lease`（mint・open・revoke・台帳）、policy 照合。
3. kagi: `kagi mcp`（上表のツール）。Claude Code / Hermes の MCP 設定に登録。
4. 消費側: git credential helper、`kagi exec`、gateway-hy の lease 更新。
5. issuer の追加（Cloudflare、murakumo、AWS STS）。

## 却下した案

- **fine-grained token を人が作って kagi に入れる**: 今回まさに詰まった経路。
  org ごとに 1 本、期限管理も人。
- **持ち主の個人トークンを配る**: 権限過大（`delete_repo` `workflow`）、取り消し不能。
- **MCP ツールが平文を返す**: モデルの文脈・ログ・transcript に値が残る。
- **minter を 1 台に固定**: そのノードの停止で全ノードの発行が止まる。

## 実装メモ（2026-10-13）

- 段階 1: kagitaba `capability` `lease` `policy` `issuer`（kagitaba ADR-0002）。
- 段階 2: `kagi.issuer.github-app`（manifest flow、RS256 JWT、PKCS#1→PKCS#8、
  installation token、失効）、`kagi.lease-seal`（要求者 KEM への封入、AAD に lease id と did）、
  `kagi.broker`（mint / pending / approve / revoke、hash 連鎖台帳）。
- 段階 3: `kagi mcp`（stdio JSON-RPC）。mcp-clj kernel は使わず最小の dispatcher を
  内蔵した（依存を増やさないため。tool の形は本書の表のとおり）。
- 段階 4: `kagi git-credential`、`kagi exec`、`kagi lease request/open`（期限まで再利用）、
  ノードからの要求は `kagi lease serve` が agent の署名（ML-DSA+Ed25519、5 分以内）で受ける。
  gateway-hy は secrets.command helper で lease を開き、期限前に上流キャッシュを捨てる。
- 未実装: passkey での承認（いまは持ち主が `kagi lease approve` を打つ）、minter の複数化。
