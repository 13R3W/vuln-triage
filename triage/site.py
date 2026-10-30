"""静的サイト（HTML＋JS＋JSON）の生成。"""

from __future__ import annotations

import json
import shutil
from html import escape
from pathlib import Path

from .periods import KIND_LABELS, KINDS, parse_month
from .tiering import TIERS

STATIC = Path(__file__).resolve().parent / "static"

# CVSS の深刻度の表示名（JVN と同じ呼び方）
SEVERITY_JA = {"CRITICAL": "緊急", "HIGH": "重要", "MEDIUM": "警告", "LOW": "注意", "NONE": "なし"}
# 期間を指す言葉（確定版 / 途中経過）
PERIOD_WORD = {"daily": ("この日", "今日"), "weekly": ("この週", "今週"), "monthly": ("この月", "今月")}


def e(v) -> str:
    return escape("" if v is None else str(v), quote=True)


def nvd_link(cve: str) -> str:
    return f'<a class="cve" href="https://nvd.nist.gov/vuln/detail/{e(cve)}" rel="noopener">{e(cve)}</a>'


def nw(v) -> str:
    """折り返さない短い値（日付など）。"""
    return f'<span class="nw">{e(v)}</span>'


def cwe_html(cwes) -> str:
    """CWE は1件ずつ折り返さず、件と件の間でだけ折り返す。"""
    return " ".join(nw(c) for c in cwes) if cwes else "—"


def severity_ja(sev) -> str:
    return SEVERITY_JA.get((sev or "").upper(), sev or "")


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


def page_path(kind: str, key: str) -> str:
    return f"{kind}/{key}.html"


def data_path(kind: str, key: str) -> str:
    return f"data/{kind}/{key}.json"


class Site:
    def __init__(self, cfg: dict, out_dir: Path, index: dict[str, list[dict]], tiles: str = ""):
        """index：種類ごとの期間一覧（新しい順）。各要素は {"key", "label", "final"}。"""
        self.cfg = cfg
        self.out = Path(out_dir)
        self.name = cfg["site"]["name"]
        self.index = index
        self.tiles = tiles  # 全ページ共通の件数タイル（summary_tiles）

    # ---- 共通レイアウト ----
    def page(self, rel_path: str, title: str, body: str) -> None:
        root = "../" * rel_path.count("/")
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
<nav><a href="{root}archive.html">アーカイブ</a><a href="{root}method.html">この順位の付け方</a></nav>
</div></header>
<main class="wrap">
{body}
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
    def switcher(self, root: str, kind: str, key: str) -> str:
        """日次・週次・月次の切り替えボタンと、期間を選ぶプルダウン。"""
        seg = "".join(
            f'<a data-keep-tab href="{root}{page_path(k, self.index[k][0]["key"])}"'
            f'{" class=on aria-current=true" if k == kind else ""}>{KIND_LABELS[k]}</a>'
            for k in KINDS if self.index.get(k))

        def option(p):
            sel = " selected" if p["key"] == key else ""
            mark = "" if p["final"] else "（途中経過）"
            return f'<option value="{root}{page_path(kind, p["key"])}"{sel}>{e(p["label"])}{mark}</option>'

        items = self.index.get(kind, [])
        if kind == "daily":  # 日次は月ごとにまとめる
            groups: dict[str, list[dict]] = {}
            for p in items:
                groups.setdefault(p["key"][:7], []).append(p)
            opts = "".join(f'<optgroup label="{e(parse_month(m).label)}">{"".join(option(p) for p in ps)}</optgroup>'
                           for m, ps in groups.items())
        else:
            opts = "".join(option(p) for p in items)
        return (f'<div class="switcher"><div class="seg" role="group" aria-label="集計の単位">{seg}</div>'
                f'<label class="sel">期間を選ぶ <select data-nav aria-label="期間を選ぶ">{opts}</select></label>'
                f'<noscript><a href="{root}archive.html">期間の一覧</a></noscript></div>')

    @staticmethod
    def updated_line(data: dict) -> str:
        """切り替えのすぐ下に出す、このページのデータの更新日時（と、前回分を表示しているときの注意）。"""
        if data.get("final"):
            line = f"更新日時：{e(data.get('finalized_at') or data['as_of'])}（日本時間・確定）"
        else:
            line = f"更新日時：{e(data.get('fetched_at') or '—')}（日本時間）"
        out = f'<p class="data-updated">{line}</p>'
        fb = data.get("fallback")
        if fb:
            out += (f'<div class="notice">今回（{e(fb["failed_at"])}）の取得に失敗したため、'
                    f'前回（{e(data.get("fetched_at"))}）取得したデータを表示しています。</div>')
        return out

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
        return "".join(f'<div class="notice err">{e(m)}</div>' for m in out)

    @staticmethod
    def card(rank: int, r: dict, jvn_failed: bool) -> str:
        meta = [f"EPSS <b>{pct(r.get('epss'))}</b>（7日前比 {delta(r.get('epss_delta'))}）"]
        if r.get("cvss") is not None:
            meta.append(f"CVSS <b>{e(r['cvss'])}</b> {e(severity_ja(r.get('severity')))}")
        if r.get("cwe"):
            meta.append(cwe_html(r["cwe"]))
        meta.append(f"公開 {nw(r.get('published'))}")
        if r.get("kev"):
            meta.append(f"KEV追加 <b>{nw(r['kev'])}</b>")
        if r.get("poc"):
            meta.append(f"PoC初出 <b>{nw(r['poc'])}</b>（{e(r.get('poc_repos'))}件）")
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

    # ---- 日次・週次・月次のページ（すべて同じ作り） ----
    def period_page(self, rel_path: str, data: dict, json_path: str) -> None:
        root = "../" * rel_path.count("/")
        kind = data["kind"]
        word = PERIOD_WORD[kind][0 if data.get("final") else 1]
        jvn_failed = data.get("sources", {}).get("JVN", "ok") != "ok"
        top_n = int(self.cfg["display"].get("top_cards", 20))
        mv = data["movement"]

        cards = "".join(self.card(i + 1, r, jvn_failed) for i, r in enumerate(data["main"][:top_n]))
        tier_boxes = "".join(f'<label><input type="checkbox" name="tier" value="{t}" checked> {t}</label>'
                             for t in TIERS)
        pager = '<nav class="pager" aria-label="ページ切り替え"></nav>'
        nvd_failed = data.get("sources", {}).get("NVD", "ok") != "ok"
        empty = ("NVD の取得に失敗したため、この回は表示できません（次回の実行で取り直します）"
                 if nvd_failed and not data["main"] else "該当なし")
        ranking = f"""
<p class="lead">{word}（日本時間）に公開されたCVEを、ティア→EPSSの高い順に並べています。</p>
<h2>上位{top_n}件</h2>
{f'<div class="cards">{cards}</div>' if cards else f'<p class="empty">{e(empty)}</p>'}
<h2>全件（検索・絞り込み）</h2>
<div data-fulltable="{e(root + json_path)}" data-empty="{e(empty)}">
<div class="filters">
<input type="search" placeholder="CVE番号・概要・CWEで検索" aria-label="検索">
<span>{tier_boxes}</span>
<label><input type="checkbox" name="jvn"> JVN未掲載のみ</label>
</div>
{pager}
<div class="tablewrap"><table><thead><tr><th class="num">順位</th><th>ティア</th><th>CVE</th><th class="num">EPSS</th><th class="num">7日前比</th><th class="num">CVSS</th><th>CWE</th><th>KEV追加</th><th>PoC初出</th><th>公開日</th><th>概要</th></tr></thead><tbody></tbody></table></div>
{pager}
<noscript><p class="empty">全件表の表示には JavaScript が必要です。</p></noscript>
</div>"""

        def old_flag(r):
            return "" if r.get("new", True) else ' <span class="flag">古いCVE</span>'

        resurf_rows = [[tier_badge(r["tier"]), nvd_link(r["id"]), pct(r.get("epss")),
                        "<br>".join(f"{e(ev['type'])} {nw(ev['date'])}" for ev in r["events"]),
                        nw(r.get("published") or "—"), cwe_html(r.get("cwe")),
                        e(r.get("summary") or "（詳細未取得）")] for r in data["resurfaced"]]
        resurfaced = (f'<p class="lead">{word}より前に公開されたCVEのうち、{word}KEVに追加された、または{word}初めてPoCが出たもの。'
                      f'順位は付けず、EPSSの高い順に最大{int(self.cfg["display"].get("resurfaced_max", 20))}件。</p>'
                      + self.table(["ティア", "CVE", "EPSS", "何が起きたか", "公開日", "CWE", "概要"], resurf_rows, (2,)))

        poc_rows = [[tier_badge(r["tier"]), nvd_link(r["id"]) + old_flag(r), nw(r["poc"]), str(r["poc_repos"]),
                     cwe_html(r.get("cwe")), pct(r.get("epss")), nw(r.get("published") or "—"),
                     e(r.get("summary") or "（詳細未取得）")] for r in data["poc"]]
        poc = (f'<p class="lead">{word}PoCが初めて公開されたCVE（古いCVEも含む）。リンク先はNVDのCVEページです（PoCへの直リンクは置いていません）。'
               'PoC本体はダウンロード・実行していません。</p>'
               + self.table(["ティア", "CVE", "PoC初出日", "リポジトリ数", "CWE", "EPSS", "公開日", "概要"],
                            poc_rows, (3, 5)))

        def move_rows(items, date_key):
            return [[tier_badge(r["tier"]), nvd_link(r["id"]) + old_flag(r), nw(r.get(date_key) or "—"),
                     pct(r.get("epss")), nw(r.get("published") or "—"), cwe_html(r.get("cwe")),
                     e(r.get("summary") or "（詳細未取得）")] for r in items]

        movement = f"""
<h2>{word}KEVに追加されたCVE</h2>
{self.table(["ティア", "CVE", "KEV追加日", "EPSS", "公開日", "CWE", "概要"], move_rows(mv["kev_added"], "kev"), (3,))}
<h2>{word}新たにSティア・Aティアに入ったCVE</h2>
<p class="lead">期間の終わり（{e(data["as_of"])}）時点でS/Aで、期間の始め（前日の終わり）時点ではS/Aでなかったもの。古いCVEも含みます。</p>
{self.table(["ティア", "CVE", "PoC初出日", "EPSS", "公開日", "CWE", "概要"], move_rows(mv["new_sa"], "poc"), (3,))}"""

        title = f"{data['label']}版" if kind == "monthly" else data["label"]
        body = f"""
<h1>{e(title)} ランキング</h1>
{self.source_notices(data)}
<div class="summary-row">{self.tiles}</div>
<div data-tabs>
<div class="tabs" role="tablist">
<button type="button" role="tab" data-tab="ranking">ランキング</button>
<button type="button" role="tab" data-tab="resurfaced">再浮上（{len(data["resurfaced"])}）</button>
<button type="button" role="tab" data-tab="poc">PoC（{len(data["poc"])}）</button>
<button type="button" role="tab" data-tab="movement">動き（{len(mv["kev_added"]) + len(mv["new_sa"])}）</button>
</div>
{self.switcher(root, kind, data["key"])}
{self.updated_line(data)}
<section class="tabpanel" id="ranking">{ranking}</section>
<section class="tabpanel" id="resurfaced"><h2>{word}「再浮上」した古い脆弱性</h2>{resurfaced}</section>
<section class="tabpanel" id="poc"><h2>{word}PoCが出たCVE</h2>{poc}</section>
<section class="tabpanel" id="movement">{movement}</section>
</div>"""
        self.page(rel_path, title, body)

    # ---- アーカイブ一覧 ----
    def archive(self, archives: dict[str, list[dict]]) -> None:
        def link(d):
            c = d["counts"]
            return (f'<li><a href="{page_path(d["kind"], d["key"])}">{e(d["label"])}{"版" if d["kind"] == "monthly" else ""}</a>'
                    f'（新規CVE {c["total"]}件、S {c["tiers"]["S"]}・A {c["tiers"]["A"]}、'
                    f'再浮上 {len(d["resurfaced"])}・PoC {len(d["poc"])}）</li>')

        months = "".join(link(m) for m in reversed(archives["monthly"]))
        weeks = "".join(link(w) for w in reversed(archives["weekly"]))
        groups: dict[str, list[dict]] = {}
        for d in reversed(archives["daily"]):
            groups.setdefault(d["key"][:7], []).append(d)
        days = "".join(f'<details{" open" if i == 0 else ""}><summary>{e(parse_month(m).label)}（{len(ds)}日）</summary>'
                       f'<ul class="plain">{"".join(link(d) for d in ds)}</ul></details>'
                       for i, (m, ds) in enumerate(groups.items()))

        def section(title, inner, html):
            return f"<h2>{title}</h2>" + (html if inner else f'<p class="empty">まだ確定した{title}はありません。</p>')

        body = ('<h1>アーカイブ</h1><p class="lead">確定した過去の日・週・月の一覧。確定したデータは書き換えません。</p>'
                + section("月次", months, f'<ul class="plain">{months}</ul>')
                + section("週次（月曜〜日曜）", weeks, f'<ul class="plain">{weeks}</ul>')
                + section("日次", days, days))
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
<li>ティア内の並び順：EPSS の高い順。「7日前比」（7日前の EPSS との差、ポイント）も表示します。</li>
<li>「JVN未掲載」は順位には影響させず、注意フラグとして表示します。JVN が取得できなかった回は「JVN確認不可」と表示します。</li>
<li>ある時点のティアは「その時点までの KEV 追加日・PoC 初出日・その日の EPSS」だけで決まります。「新たにS/A入り」はこれを使って期間の始めと終わりのティアを比べています。</li>
<li>確定版（過去の日・週・月）は、その期間の最終日を基準日として、その日の EPSS で計算しています。</li>
<li>CVSS の深刻度は JVN と同じ呼び方（緊急・重要・警告・注意）で表示します。概要は NVD の原文（英語）です。</li>
</ul>
<h2>集計の単位</h2>
<p>日次（日本時間の1日）・週次（月曜〜日曜）・月次の3種類を、同じ作りで公開しています。各ページのタブの下のボタンとプルダウンで切り替えられます（開いているタブのまま切り替わります）。期間が終わった後の最初の実行で確定します。</p>
{self.table(["タブ", "内容"], [
            ["ランキング", "その期間に NVD で公開された CVE（取り下げ分を除く）を、ティア→EPSS の順に並べたもの"],
            ["再浮上", "その期間より前に公開された CVE のうち、期間内に KEV に追加された、または初めて PoC が出たもの。順位は付けず EPSS 順"],
            ["PoC", "その期間に PoC が初めて出た CVE（古い CVE も含む）"],
            ["動き", "その期間に KEV に追加された CVE と、新たに S/A ティアに入った CVE（古い CVE も含む）"],
        ])}
<p>古くから KEV 掲載済み・PoC 既出の CVE は、その期間になにも起きていなければランキング・再浮上・PoC のどれにも入りません。</p>
<h2>データ源</h2>
{self.table(["データ", "取得元", "使い方"], [
            ["新規CVE・公開日・概要・CVSS・CWE", "NVD API 2.0", "CVSS は CNA の値（Secondary）を優先し、なければ NVD の値"],
            ["悪用実績", "CISA KEV", "各 CVE の KEV 追加日（dateAdded）"],
            ["悪用予測", "FIRST EPSS", "その日の EPSS（今後30日に悪用される確率の推定）"],
            ["PoC", "nomi-sec/PoC-in-GitHub", "メタデータのみ使用。最も古い作成日時を「PoC初出日」、件数を「リポジトリ数」とする。PoC 本体はダウンロード・実行しない。存在しない CVE 番号の登録があるため、EPSS スコアがある（または NVD に掲載された）CVE だけ採用"],
            ["日本向け情報", "JVN iPedia（MyJVN API）", "JVN に掲載されているかどうか"],
        ])}
<p>データ源が一時的に取得できなかった回は、今日・今週・今月のページに同じ期間の前回取得できたデータを表示します（前回分が無いときは取得失敗の注意を出します）。必須のデータ源（NVD・KEV・EPSS・PoC）が取得できなかった回は、日・週・月の確定を次回に見送ります。</p>
"""
        self.page("method.html", "この順位の付け方", body)


def summary_tiles(live: dict[str, dict]) -> str:
    """ページ上部の件数タイル。どのページでも同じ並び・同じ値（今日・今月の途中経過）にする。

    左から：今日公開・今月公開・S・A・B・JVN未掲載・KEV追加・新たにS/A入り（今日公開以外は今月の件数）。
    """
    day, month = live.get("daily"), live.get("monthly")
    if not (day and month):
        return ""
    c = month["counts"]
    jm = c.get("jvn_missing")
    # (値, 表示する見出し, マウスを載せたときの説明)
    items = [(day["counts"]["total"], "今日公開", "今日（日本時間）公開の新規CVE"),
             (c["total"], "今月公開", "今月公開の新規CVE")]
    items += [(c["tiers"][t], f"{tier_badge(t)}ティア", f"今月公開のうち {t} ティア") for t in ("S", "A", "B")]
    items += [("—" if jm is None else jm, "JVN未掲載", "今月公開のうち JVN 未掲載（JVN 取得失敗時は —）"),
              (len(month["movement"]["kev_added"]), "KEV追加", "今月 KEV に追加された CVE"),
              (len(month["movement"]["new_sa"]), "新たにS/A", "今月新たに S/A ティアに入った CVE")]
    return "".join(f'<div class="stat" title="{e(tip)}"><b>{v}</b><span>{label}</span></div>' for v, label, tip in items)


def generate(cfg: dict, out_dir: Path, live: dict[str, dict], archives: dict[str, list[dict]]) -> None:
    """live：種類ごとの途中経過（今日・今週・今月）。archives：種類ごとの確定データ。"""
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    index: dict[str, list[dict]] = {}
    pages: list[dict] = []
    for kind in KINDS:
        items = [d for d in archives.get(kind, []) if d["key"] != live.get(kind, {}).get("key")]
        if kind in live:
            items.append(live[kind])
        items.sort(key=lambda d: d["start"] if "start" in d else d["key"], reverse=True)
        index[kind] = [{"key": d["key"], "label": d["label"], "final": d.get("final", False)} for d in items]
        pages.extend(items)

    site = Site(cfg, out_dir, index, summary_tiles(live))
    site.copy_static()
    for d in pages:
        jp = data_path(d["kind"], d["key"])
        site.write_json(jp, d["main"])
        site.period_page(page_path(d["kind"], d["key"]), d, jp)
        if d is live.get("monthly"):
            site.period_page("index.html", d, jp)
    site.archive(archives)
    site.method()
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
