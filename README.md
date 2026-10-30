# vuln-triage（脆弱性トリアージ・ダッシュボード）

その日・その週・その月に公開された脆弱性（CVE）の中から「今どれを先に対応すべきか」を、公開データだけを使って毎日自動で順位付けし、
日ごと・週ごと・月ごとのページとして GitHub Pages に公開する観察ツールです。手作業は入りません。

- 設計：[設計書_脆弱性トリアージ.md](設計書_脆弱性トリアージ.md)
- 構成：Python（標準ライブラリのみ）＋ GitHub Actions（ワークフロー1本）＋ GitHub Pages
- 費用：公開リポジトリ＋標準ランナー（`ubuntu-latest`）なので、Actions・Pages ともに無料枠で動きます

## 順位の付け方（概要）

| ティア | 条件 |
|---|---|
| S | CISA KEV に掲載された |
| A | PoC が公開済み、かつ EPSS ≥ 10% |
| B | PoC 公開済み、または EPSS ≥ 1% |
| C | 上記以外 |

ティア内は EPSS の高い順です。しきい値は `config.toml` で変更できます。詳しくはサイトの「この順位の付け方」ページを見てください。

## ページの見方

- **日次・週次・月次**：各ページ上部の「日次｜週次｜月次」ボタンで種類を、「期間を選ぶ」プルダウンで日・週・月を切り替えます。
  今日・今週・今月は「途中経過」で、期間が終わった後の最初の実行で確定します
- 各ページのタブ
  - **ランキング**：その期間に公開された CVE。上位20件のカードと、全件の表（100件ずつのページ送り、検索・絞り込み）
  - **再浮上**：その期間より前に公開され、期間内に KEV 追加または初めて PoC が出た CVE
  - **PoC**：その期間に初めて PoC が出た CVE（古い CVE も含む）
  - **動き**：その期間の KEV 追加と、新たに S/A ティアに入った CVE
- 概要は NVD の原文（英語）です。CVSS の深刻度は「緊急・重要・警告・注意」と表示します
- 確定した過去の日・週・月は「アーカイブ」ページから一覧できます
- 切り替えのすぐ下に、そのページのデータの**更新日時**が出ます。今日・今週・今月の更新でデータが取れなかったときは、
  同じ日・週・月で前回取れたデータを表示し、その旨を注意書きで出します（前回分は Actions のキャッシュに保存しています）

---

## GitHub 側で必要な設定

### 1. リポジトリを公開（public）にする

GitHub Pages と Actions を無料で使うため、リポジトリは公開にします。

- リポジトリの **Settings → General** を開く
- いちばん下の **Danger Zone → Change repository visibility** で **Public** にする

### 2. GitHub Pages を有効にする

- **Settings → Pages** を開く
- **Build and deployment → Source** で **GitHub Actions** を選ぶ（「Deploy from a branch」ではありません）

これだけで、ワークフローが `github-pages` 環境を作ってデプロイします。公開 URL は
`https://<ユーザー名>.github.io/<リポジトリ名>/` です（Settings → Pages の上部にも表示されます）。

### 3. Actions の権限を確認する

ワークフローは、確定した日・週・月のデータを `archive/` にコミットしてプッシュします。

- **Settings → Actions → General** を開く
- **Actions permissions** が「Allow all actions and reusable workflows」（または GitHub 公式アクションを許可する設定）になっていること
- **Workflow permissions** は初期設定（Read repository contents）のままで構いません。必要な権限（書き込み・Pages・ワークフロー再有効化）はワークフローファイルの `permissions:` で個別に指定しています

> `main` ブランチに保護ルール（プッシュ禁止など）を付けている場合は、`github-actions[bot]` のプッシュを許可してください。

### 4. （任意）NVD API キーを登録する

キーが無くても動きます。キーがあると NVD への問い合わせ間隔が 6 秒 → 約 0.7 秒になり、古い CVE の詳細（再浮上・PoC タブの CWE など）を 1 回の実行で多く取得できます。

1. NVD の申請ページ <https://nvd.nist.gov/developers/request-an-api-key> でメールアドレスなどを入力して申請する（無料）
2. 届いたメールのリンクを開いてキーを有効化する
3. リポジトリの **Settings → Secrets and variables → Actions** を開く
4. **New repository secret** を押し、Name に `NVD_API_KEY`、Secret にキーを貼り付けて **Add secret**

### 5. 手動で実行する

毎日 1 回（日本時間 5 時台ごろ）自動で動きますが、すぐに動かしたいときは手動実行できます。

1. リポジトリの **Actions** タブを開く
2. 左の一覧から **脆弱性トリアージ（毎日）** を選ぶ
3. 右側の **Run workflow** を押し、ブランチに **main**（既定ブランチ）を選んで **Run workflow** を押す
4. 実行が終わると（30 分前後。初回や月初の確定がある日は長め）、Pages の URL にサイトが公開されます

> Pages の `github-pages` 環境は、初期設定では既定ブランチからのデプロイしか許可していません。既定ブランチ以外で実行するとデプロイの手順で失敗します。

Actions タブにワークフローを有効にするかどうかの確認が出た場合は、ボタンを押して有効にしてください。

### 補足：定期実行の 60 日停止について

公開リポジトリでは、60 日間リポジトリに動きが無いと定期実行が自動で止まります。このツールでは

- 毎日、確定した日のデータがコミットされる
- 毎回の実行の最後に、ワークフローを API で有効化し直す

ので通常は止まりません。全ページに「最終更新（日本時間）」が出るので、更新が止まっていないかはそこで確認できます。
止まっていたら Actions タブで該当ワークフローを開き **Enable workflow** を押してください。

---

## ローカルでの実行・テスト

Python 3.11 以上が必要です（追加のパッケージは不要）。

テストを実行する（外部には繋がず、同梱のサンプルデータで動きます）：

```bash
python -m unittest discover -s tests -t .
```

サンプルデータでサイトを生成して確認する（`--now` で日時を指定すると、日・週・月の確定も確認できます）：

```bash
python -m triage run --sample --now 2026-12-02T10:00+09:00 --out _site
```

```bash
python -m http.server -d _site 8000
```

ブラウザで <http://localhost:8000/> を開きます（全件表は JSON を読み込むので、ファイルを直接開くのではなくサーバー経由で見てください）。
`--sample` のとき、確定データはリポジトリの `archive/` ではなく `.cache/sample-archive/` に書き出されます。

実データで動かす（NVD・CISA・FIRST・GitHub・JVN に接続できる環境が必要）：

```bash
NVD_API_KEY=（任意） python -m triage run --out _site
```

主なオプション：

| オプション | 内容 |
|---|---|
| `--sample` | 外部に繋がず、サンプルデータで動かす |
| `--now 日時` | 現在時刻を指定する（例：`2026-11-20T10:00+09:00`） |
| `--out` | サイトの出力先（既定：`_site`） |
| `--archive` | 確定データの保存先（既定：`archive`） |
| `--no-finalize` | 日・週・月の確定をしない |
| `--config` | 設定ファイル（既定：`config.toml`） |

## 設定ファイル（config.toml）

| 項目 | 内容 |
|---|---|
| `site.name` | サイト名（未決のため仮称） |
| `schedule.start_month` | 確定アーカイブを作り始める月（`2026-11`） |
| `tiers.a_epss` / `tiers.b_epss` | ティア A・B の EPSS しきい値（0.10 / 0.01） |
| `display.*` | カード件数・再浮上の件数・概要の文字数 |
| `nvd.lookup_limit` / `lookup_limit_with_key` | 古い CVE の詳細を 1 回に個別取得する上限（キーなし / あり） |
| 各データ源の `interval` | 呼び出し間隔（秒） |

## ファイル構成

```
config.toml                 設定
triage/                     収集・判定・ページ生成（Python）
  sources/                  データ源ごとの取得（NVD・KEV・EPSS・PoC・JVN）
  build.py                  日次・週次・月次データの組み立て（3種類とも同じ関数）
  archive.py                日・週・月の確定
  site.py, static/          静的サイトの生成
  sample.py                 サンプルデータと、各 API を真似る取得器（テスト・動作確認用）
tests/                      テスト（unittest）
archive/daily/, weekly/, monthly/   確定した日・週・月のデータ（ワークフローがコミット）
.github/workflows/triage.yml
```

## 注意

- PoC はメタデータ（作成日時・件数）だけを扱います。PoC 本体はダウンロード・実行せず、ページにも PoC への直リンクは置きません
- JVN iPedia / MyJVN は 2026-10-29 時点でサービス停止中（再開時期未定）です。停止中は各ページに「JVN：取得失敗」「JVN確認不可」と表示され、それ以外の処理は通常どおり動きます
