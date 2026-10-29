"""静的サイト（HTML＋JS＋JSON）の生成。"""

from __future__ import annotations

import json
import shutil
from html import escape
from pathlib import Path

from .collect import SOURCES
from .tiering import TIERS

STATIC = Path(__file__).resolve().parent / "static"


def e(v) -> str:
    return escape("" if v is None else str(v), quote=True)


def nvd_link(cve: str) -> str:
    return f'<a class="cve" href="https://nvd.nist.gov/vuln/detail/{e(cve)}" rel="noopener">{e(cve)}</a>'


def nw(v) -> str:
    """折り返さない短い値（日付など）。"""
    return f'<span class="nw">{e(v)}</span>'


def pct(v) -> str:
    return "—" if v is None else f"{v * 100:.2f}%"


def delta(v) -> str:
    if v is None:
        return "—"
    pt = v * 100
    if abs(pt) < 0.005:
        return "±0"
    cls = "up" if pt > 0 else "down"
    return f'<span class="{cls}">{pt:+.2f}pt</span>'


def tier_badge(t: str) -> str:
    return f'<span class="tier tier-{e(t)}">{e(t)}</span>'


def jvn_flag(rec: dict, jvn_failed: bool) -> str:
    if rec.get("jvn") is False:
        return ' <span class="flag">JVN未掲載</span>'
    if rec.get("jvn") is None and jvn_failed:
        return ' <span class="flag">JVN確認不可</span>'
    return ""


class Site:
    def __init__(self, cfg: dict, out_dir: Path, updated_at: str, status: dict[str, str]):
        self.cfg = cfg
        self.out = Path(out_dir)
        self.updated_at = updated_at
        self.status = status
        self.name = cfg["site"]["name"]

    # ---- 共通レイアウト ----
    def page(self, rel_path: str, title: str, body: str) -> None:
        depth = rel_path.count("/")
        root = "../" * depth
        status_items = "".join(
            f'<li class="{"ok" if self.status.get(n) == "ok" else "ng"}" title="{e(self.status.get(n))}">'
            f'{e(n)}：{"取得成功" if self.status.get(n) == "ok" else "取得失敗"}</li>'
            for n in SOURCES)
        html = f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} | {e(self.name)}</title>
<meta name="description" content="{e(self.cfg["site"].get("description", ""))}">
<link rel="stylesheet" href="{root}assets/style.css">
</head>
<body>
<header class="site"><div class="wrap">
<a class="name" href="{root}index.html">{e(self.name)}</a>
<nav><a href="{root}index.html">今月</a><a href="{root}archive.html">アーカイブ</a><a href="{root}method.html">この順位の付け方</a></nav>
</div></header>
<main class="wrap">
<div class="updated">最終更新：{e(self.updated_at)}（日本時間）</div>
<ul class="sources" aria-label="今回のデータ取得状況">{status_items}</ul>
{body}
<footer>公開データ（NVD・CISA KEV・FIRST EPSS・PoC-in-GitHub・JVN iPedia）を毎日自動で集計しています。手作業による判断・コメントは入っていません。PoC へのリンクは置かず、CVE は NVD のページにリンクしています。</footer>
</main>
<script src="{root}assets/app.js"></script>
</body>
</html>
"""
        path = self.out / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")

    def write_json(self, rel_path: str, obj) -> None:
        path = self.out / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    def copy_static(self) -> None:
        dest = self.out / "assets"
        dest.mkdir(parents=True, exist_ok=True)
        for f in STATIC.iterdir():
            shutil.copy(f, dest / f.name)

    # ---- 部品 ----
    @staticmethod
    def source_notices(data: dict) -> str:
        st = data.get("sources", {})
        out = []
        if st.get("NVD", "ok") != "ok":
            out.append("NVD の取得に失敗したため、この回の一覧は不完全です。")
        if st.get("EPSS", "ok") != "ok":
            out.append("EPSS の取得に失敗したため、EPSS とティアが不正確な可能性があります。")
        if st.get("KEV", "ok") != "ok":
            out.append("CISA KEV の取得に失敗したため、KEV 掲載が反映されていません。")
        if st.get("PoC", "ok") != "ok":
            out.append("PoC-in-GitHub の取得に失敗したため、PoC 情報が反映されていません。")
        if st.get("JVN", "ok") != "ok":
            out.append("JVN iPedia の取得に失敗したため、JVN 掲載の有無は確認できていません（「JVN確認不可」と表示）。")
        return "".join(f'<div class="notice err">{e(m)}</div>' for m in out)

    @staticmethod
    def card(rank: int, r: dict, jvn_failed: bool) -> str:
        meta = [f"EPSS <b>{pct(r.get('epss'))}</b>（7日前比 {delta(r.get('epss_delta'))}）"]
        if r.get("cvss") is not None:
            meta.append(f"CVSS <b>{e(r['cvss'])}</b> {e(r.get('severity') or '')}")
        if r.get("cwe"):
            meta.append(e(", ".join(r["cwe"])))
        meta.append(f"公開 {e(r.get('published'))}")
        if r.get("kev"):
            meta.append(f"KEV追加 <b>{e(r['kev'])}</b>")
        if r.get("poc"):
            meta.append(f"PoC初出 <b>{e(r['poc'])}</b>（{e(r.get('poc_repos'))}件）")
        return (f'<article class="card"><div class="top"><span class="rank">#{rank}</span>{tier_badge(r["tier"])}'
                f'<span class="id">{nvd_link(r["id"])}</span>{jvn_flag(r, jvn_failed)}</div>'
                f'<div class="meta">{"".join(f"<span>{m}</span>" for m in meta)}</div>'
                f'<p>{e(r.get("summary"))}</p></article>')

    @staticmethod
    def table(headers: list[str], rows: list[list[str]], num_cols=()) -> str:
        if not rows:
            return '<p class="empty">該当なし</p>'
        th = "".join(f'<th class="{"num" if i in num_cols else ""}">{e(h)}</th>' for i, h in enumerate(headers))
        body = "".join(
            "<tr>" + "".join(f'<td class="{"num" if i in num_cols else ""}">{c}</td>' for i, c in enumerate(row))
            + "</tr>" for row in rows)
        return f'<div class="tablewrap"><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'

    # ---- 月次ページ ----
    def monthly(self, rel_path: str, data: dict, data_path: str, preview_note: str = "") -> None:
        depth = rel_path.count("/")
        root = "../" * depth
        jvn_failed = data.get("sources", {}).get("JVN", "ok") != "ok"
        top_n = int(self.cfg["display"].get("top_cards", 20))
        c = data["counts"]
        state = ("確定版（" + e(data.get("finalized_at", "")) + " 確定、基準日 " + e(data["as_of"]) + "）"
                 if data.get("final") else f"途中経過（基準日 {e(data['as_of'])}。月が終わると確定します）")
        stats = "".join(f'<div class="stat"><b>{c["tiers"][t]}</b><span>{tier_badge(t)} ティア</span></div>'
                        for t in TIERS)
        jm = c.get("jvn_missing")
        stats = (f'<div class="stat"><b>{c["total"]}</b><span>今月公開の新規CVE</span></div>{stats}'
                 f'<div class="stat"><b>{"—" if jm is None else jm}</b><span>JVN未掲載</span></div>')

        cards = "".join(self.card(i + 1, r, jvn_failed) for i, r in enumerate(data["main"][:top_n]))
        tier_boxes = "".join(f'<label><input type="checkbox" name="tier" value="{t}" checked> {t}</label>'
                             for t in TIERS)
        ranking = f"""
<h2>上位{top_n}件</h2>
{f'<div class="cards">{cards}</div>' if cards else '<p class="empty">該当なし</p>'}
<h2>全件（検索・絞り込み）</h2>
<div data-fulltable="{e(root + data_path)}">
<div class="filters">
<input type="search" placeholder="CVE番号・概要・CWEで検索" aria-label="検索">
<span>{tier_boxes}</span>
<label><input type="checkbox" name="jvn"> JVN未掲載のみ</label>
<span class="count"></span>
</div>
<div class="tablewrap"><table><thead><tr><th class="num">順位</th><th>ティア</th><th>CVE</th><th class="num">EPSS</th><th class="num">7日前比</th><th class="num">CVSS</th><th>CWE</th><th>KEV追加</th><th>PoC初出</th><th>公開日</th><th>概要</th></tr></thead><tbody></tbody></table></div>
<div class="more" hidden><button type="button">さらに表示</button></div>
<noscript><p class="empty">全件表の表示には JavaScript が必要です。</p></noscript>
</div>"""

        resurf_rows = [[tier_badge(r["tier"]), nvd_link(r["id"]), pct(r.get("epss")),
                        "<br>".join(f"{e(ev['type'])} {nw(ev['date'])}" for ev in r["events"]),
                        nw(r.get("published") or "—"), e(", ".join(r.get("cwe") or []) or "—"),
                        e(r.get("summary") or "（詳細未取得）")] for r in data["resurfaced"]]
        resurfaced = ('<p class="lead">今月より前に公開されたCVEのうち、今月KEVに追加された、または今月初めてPoCが出たもの。'
                      f'順位は付けず、EPSSの高い順に最大{int(self.cfg["display"].get("resurfaced_max", 20))}件。</p>'
                      + self.table(["ティア", "CVE", "EPSS", "何が起きたか", "公開日", "CWE", "概要"], resurf_rows, (2,)))

        poc_rows = [[nvd_link(r["id"]) + ("" if r["this_month"] else ' <span class="flag">古いCVE</span>'),
                     nw(r["poc"]), str(r["poc_repos"]), e(", ".join(r.get("cwe") or []) or "—"),
                     pct(r.get("epss")), nw(r.get("published") or "—")] for r in data["poc"]]
        poc = ('<p class="lead">今月PoCが初めて公開されたCVE。リンク先はNVDのCVEページです（PoCへの直リンクは置いていません）。'
               'PoC本体はダウンロード・実行していません。</p>'
               + self.table(["CVE", "PoC初出日", "リポジトリ数", "CWE", "EPSS", "公開日"], poc_rows, (2, 4)))

        body = f"""
<h1>{e(data["label"])}版 ランキング</h1>
<p class="lead">{state}。EPSS {e(data.get("epss_date") or "—")} 時点（7日前比は {e(data.get("epss_prev_date") or "—")} との差）。</p>
{preview_note}
{self.source_notices(data)}
<div class="summary-row">{stats}</div>
<div data-tabs>
<div class="tabs" role="tablist">
<button type="button" role="tab" data-tab="ranking">今月のランキング</button>
<button type="button" role="tab" data-tab="resurfaced">再浮上（{len(data["resurfaced"])}）</button>
<button type="button" role="tab" data-tab="poc">PoC（{len(data["poc"])}）</button>
</div>
<section class="tabpanel" id="ranking">{ranking}</section>
<section class="tabpanel" id="resurfaced"><h2>今月「再浮上」した古い脆弱性</h2>{resurfaced}</section>
<section class="tabpanel" id="poc"><h2>今月PoCが出たCVE</h2>{poc}</section>
</div>"""
        self.page(rel_path, f"{data['label']}版", body)
        self.write_json(data_path, data["main"])

    # ---- 週次ページ ----
    def weekly(self, rel_path: str, data: dict) -> None:
        def rows(items, date_key):
            return [[tier_badge(r["tier"]), nvd_link(r["id"]), nw(r.get(date_key) or "—"), pct(r.get("epss")),
                     nw(r.get("published") or "—"), e(", ".join(r.get("cwe") or []) or "—"),
                     e(r.get("summary") or "（詳細未取得）")] for r in items]

        n = data.get("new_cves")
        body = f"""
<h1>{e(data["label"])}</h1>
<p class="lead">確定版（{e(data.get("finalized_at", ""))} 確定）。EPSS・ティアは {e(data["as_of"])}（日曜）時点。</p>
{self.source_notices(data)}
<div class="summary-row">
<div class="stat"><b>{"—" if n is None else n}</b><span>今週公開の新規CVE</span></div>
<div class="stat"><b>{len(data["kev_added"])}</b><span>KEV追加</span></div>
<div class="stat"><b>{len(data["poc_first"])}</b><span>PoC初出</span></div>
<div class="stat"><b>{len(data["new_sa"])}</b><span>新たにS/A入り</span></div>
</div>
<h2>今週KEVに追加されたCVE</h2>
{self.table(["ティア", "CVE", "KEV追加日", "EPSS", "公開日", "CWE", "概要"], rows(data["kev_added"], "kev"), (3,))}
<h2>今週PoCが初めて出たCVE</h2>
{self.table(["ティア", "CVE", "PoC初出日", "EPSS", "公開日", "CWE", "概要"], rows(data["poc_first"], "poc"), (3,))}
<h2>今週新たにSティア・Aティアに入ったCVE</h2>
<p class="lead">週の終わり（日曜）時点でS/Aで、週の始め（前週日曜の終わり）時点ではS/Aでなかったもの。古いCVEも含みます。</p>
{self.table(["ティア", "CVE", "PoC初出日", "EPSS", "公開日", "CWE", "概要"], rows(data["new_sa"], "poc"), (3,))}
"""
        self.page(rel_path, data["label"], body)

    # ---- アーカイブ一覧 ----
    def archive(self, archives: dict[str, list[dict]]) -> None:
        months = "".join(
            f'<li><a href="monthly/{e(m["key"])}.html">{e(m["label"])}版</a>'
            f'（新規CVE {m["counts"]["total"]}件、S {m["counts"]["tiers"]["S"]}・A {m["counts"]["tiers"]["A"]}）</li>'
            for m in reversed(archives["monthly"]))
        weeks = "".join(
            f'<li><a href="weekly/{e(w["key"])}.html">{e(w["label"])}</a>'
            f'（KEV追加 {len(w["kev_added"])}・PoC初出 {len(w["poc_first"])}・新たにS/A {len(w["new_sa"])}）</li>'
            for w in reversed(archives["weekly"]))
        body = f"""
<h1>アーカイブ</h1>
<p class="lead">確定した過去の月・週の一覧。確定したデータは書き換えません。</p>
<h2>月別</h2>
{f'<ul class="plain">{months}</ul>' if months else '<p class="empty">まだ確定した月はありません。</p>'}
<h2>週次（月曜〜日曜）</h2>
{f'<ul class="plain">{weeks}</ul>' if weeks else '<p class="empty">まだ確定した週はありません。</p>'}
"""
        self.page("archive.html", "アーカイブ", body)

    # ---- この順位の付け方 ----
    def method(self) -> None:
        th = self.cfg["tiers"]
        a, b = th["a_epss"] * 100, th["b_epss"] * 100
        body = f"""
<h1>この順位の付け方</h1>
<p>重み付きの点数ではなく、まず段階（ティア）に分け、ティアの中を EPSS の高い順に並べます。手作業による判断は入れていません。</p>
<h2>ティア</h2>
{self.table(["ティア", "条件"], [
            [tier_badge("S"), "CISA KEV（悪用が確認された脆弱性カタログ）に掲載された"],
            [tier_badge("A"), f"PoC が公開済み、かつ EPSS ≥ {a:g}%"],
            [tier_badge("B"), f"PoC が公開済み、または EPSS ≥ {b:g}%"],
            [tier_badge("C"), "上記以外"],
        ])}
<ul class="plain">
<li>上から順に判定し、最初に当てはまったティアになります。</li>
<li>ティア内の並び順：EPSS の現在値の高い順。「7日前比」（7日前の EPSS との差、ポイント）も表示します。</li>
<li>「JVN未掲載」は順位には影響させず、注意フラグとして表示します。JVN が取得できなかった回は「JVN確認不可」と表示します。</li>
<li>ある時点のティアは「その時点までの KEV 追加日・PoC 初出日・その日の EPSS」だけで決まります。週次の「新たにS/A入り」はこれを使って週の始めと終わりのティアを比べています。</li>
<li>確定版（過去の月・週）は、その期間の最終日を基準日として、その日の EPSS で計算しています。</li>
</ul>
<h2>対象</h2>
<ul class="plain">
<li><b>メイン：今月のランキング</b>：今月（日本時間）に NVD で公開された CVE（取り下げ分を除く）。</li>
<li><b>再浮上</b>：今月より前に公開された CVE のうち、今月 KEV に追加された、または今月初めて PoC が出たもの。順位は付けず EPSS 順。</li>
<li>古くから KEV 掲載済み・PoC 既出の CVE は、今月なにも起きていなければどちらにも入りません。</li>
<li><b>週次</b>：月曜〜日曜（日本時間）。翌週月曜以降の最初の実行で確定します。</li>
</ul>
<h2>データ源</h2>
{self.table(["データ", "取得元", "使い方"], [
            ["新規CVE・公開日・概要・CVSS・CWE", "NVD API 2.0", "CVSS は CNA の値（Secondary）を優先し、なければ NVD の値"],
            ["悪用実績", "CISA KEV", "各 CVE の KEV 追加日（dateAdded）"],
            ["悪用予測", "FIRST EPSS", "その日の EPSS（今後30日に悪用される確率の推定）"],
            ["PoC", "nomi-sec/PoC-in-GitHub", "メタデータのみ使用。最も古い作成日時を「PoC初出日」、件数を「リポジトリ数」とする。PoC 本体はダウンロード・実行しない。存在しない CVE 番号の登録があるため、EPSS スコアがある（または NVD に掲載された）CVE だけ採用"],
            ["日本向け情報", "JVN iPedia（MyJVN API）", "JVN に掲載されているかどうか"],
        ])}
<p>データ源が一時的に取得できなかった回は、そのデータ源を「取得失敗」と表示して続行します。必須のデータ源（NVD・KEV・EPSS・PoC）が取得できなかった回は、週・月の確定を次回に見送ります。</p>
"""
        self.page("method.html", "この順位の付け方", body)


def generate(cfg: dict, out_dir: Path, live: dict, archives: dict[str, list[dict]], updated_at: str,
             status: dict[str, str]) -> None:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    site = Site(cfg, out_dir, updated_at, status)
    site.copy_static()
    start = cfg["schedule"]["start_month"]
    note = ""
    if live["key"] < start:
        y, m = start.split("-")
        note = (f'<div class="notice">開始前のプレビューです。確定版（アーカイブ）は{int(y)}年{int(m)}月版から作成します。</div>')
    site.monthly("index.html", live, f"data/current.json", note)
    for m in archives["monthly"]:
        site.monthly(f"monthly/{m['key']}.html", m, f"data/monthly/{m['key']}.json")
    for w in archives["weekly"]:
        site.weekly(f"weekly/{w['key']}.html", w)
    site.archive(archives)
    site.method()
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
