import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from triage import archive, periods
from triage.build import build_period
from triage.site import generate

from .helpers import CFG, jst, make_sources

NOV = periods.parse_month("2026-11")
W45 = periods.first_week("2026-11")
W46 = periods.week_of(date(2026, 11, 9))


def by_id(rows):
    return {r["id"]: r for r in rows}


def ids(rows):
    return {r["id"] for r in rows}


class MonthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        now = jst("2026-11-20T10:00")
        cls.src, _ = make_sources(now)
        cls.data = build_period(cls.src, NOV, now.date())

    def test_main_population(self):
        got = ids(self.data["main"])
        self.assertIn("CVE-2026-41002", got)      # 日本時間 11/1 23:30
        self.assertIn("CVE-2026-41003", got)      # 日本時間 11/1 01:00（UTC では 10/31）
        self.assertNotIn("CVE-2026-41004", got)   # 日本時間 10/31 23:00
        self.assertNotIn("CVE-2026-41007", got)   # 取り下げ
        self.assertNotIn("CVE-2021-44228", got)
        self.assertTrue(all(r["published"] <= "2026-11-20" for r in self.data["main"]))

    def test_tiers_and_fields(self):
        m = by_id(self.data["main"])
        self.assertEqual(m["CVE-2026-41001"]["tier"], "S")
        self.assertEqual(m["CVE-2026-41002"]["tier"], "A")
        self.assertEqual(m["CVE-2026-41003"]["tier"], "B")
        self.assertEqual(m["CVE-2026-41005"]["tier"], "C")
        self.assertEqual(m["CVE-2026-41006"]["tier"], "B")  # EPSS 未算出でも NVD 掲載済みなので PoC を採用
        self.assertEqual((m["CVE-2026-41008"]["cvss"], m["CVE-2026-41008"]["severity"]), (6.9, "MEDIUM"))
        r = m["CVE-2026-41001"]
        self.assertEqual((r["kev"], r["poc"], r["poc_repos"], r["jvn"]), ("2026-11-10", "2026-11-05", 2, True))
        self.assertIs(m["CVE-2026-41008"]["jvn"], False)
        self.assertEqual(self.data["epss_date"], "2026-11-20")
        self.assertEqual(self.data["epss_prev_date"], "2026-11-13")
        self.assertEqual((self.data["kind"], self.data["start"], self.data["end"]), ("monthly", "2026-11-01", "2026-11-30"))

    def test_order(self):
        tiers = [r["tier"] for r in self.data["main"]]
        self.assertEqual(tiers, sorted(tiers, key="SABC".index))
        for t in "SABC":
            e = [r["epss"] for r in self.data["main"] if r["tier"] == t and r["epss"] is not None]
            self.assertEqual(e, sorted(e, reverse=True))

    def test_epss_delta(self):
        m = by_id(self.data["main"])
        self.assertAlmostEqual(m["CVE-2026-41003"]["epss_delta"], 0.02)  # 11/13 は 3%、11/20 は 5%
        self.assertIsNone(m["CVE-2026-41005"]["epss_delta"])  # 7日前（11/13）はまだ公開前

    def test_resurfaced(self):
        res = by_id(self.data["resurfaced"])
        self.assertEqual(res["CVE-2026-41004"]["events"], [{"type": "KEV追加", "date": "2026-11-04"}])
        self.assertEqual(res["CVE-2024-50001"]["events"], [{"type": "PoC初出", "date": "2026-11-11"}])
        self.assertEqual(res["CVE-2024-50001"]["cwe"], ["CWE-416"])  # NVD 個別取得
        self.assertNotIn("CVE-2021-44228", res)
        self.assertNotIn("CVE-2025-30001", res)  # EPSS が上がっただけでは再浮上ではない
        self.assertNotIn("CVE-2026-999999", res)  # ゴミ登録
        e = [r["epss"] for r in self.data["resurfaced"]]
        self.assertEqual(e, sorted(e, key=lambda v: -(v or 0)))
        self.assertLessEqual(len(res), CFG["display"]["resurfaced_max"])

    def test_poc_tab(self):
        p = by_id(self.data["poc"])
        self.assertFalse(p["CVE-2024-50001"]["new"])
        self.assertTrue(p["CVE-2026-41001"]["new"])
        self.assertEqual(p["CVE-2026-41001"]["poc"], "2026-11-05")
        self.assertIn("CVE-2026-41006", p)
        self.assertNotIn("CVE-2026-999999", p)
        self.assertNotIn("CVE-2025-30001", p)  # PoC 初出は 2025年
        self.assertTrue(all(NOV.contains(r["poc"]) for r in self.data["poc"]))

    def test_movement(self):
        mv = self.data["movement"]
        self.assertTrue({"CVE-2026-41001", "CVE-2026-41004"} <= ids(mv["kev_added"]))
        new = ids(mv["new_sa"])
        self.assertTrue({"CVE-2026-41001", "CVE-2026-41002", "CVE-2026-41004", "CVE-2024-50001",
                         "CVE-2025-30001"} <= new)
        self.assertNotIn("CVE-2021-44228", new)

    def test_counts(self):
        c = self.data["counts"]
        self.assertEqual(c["total"], len(self.data["main"]))
        self.assertEqual(sum(c["tiers"].values()), c["total"])
        self.assertEqual(c["jvn_missing"], sum(1 for r in self.data["main"] if r["jvn"] is False))

    def test_record_size(self):
        size = max(len(json.dumps(r, ensure_ascii=False).encode()) for r in self.data["main"])
        self.assertLess(size, 700)  # 1件あたり数百バイト


class WeekTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src, _ = make_sources(jst("2026-11-20T10:00"))
        cls.w45 = build_period(cls.src, W45, date(2026, 11, 20), final=True)
        cls.w46 = build_period(cls.src, W46, date(2026, 11, 20), final=True)

    def test_ranking_is_only_this_week(self):
        for w, p in ((self.w45, W45), (self.w46, W46)):
            self.assertTrue(w["main"])
            self.assertTrue(all(p.contains(r["published"]) for r in w["main"]))
        self.assertIn("CVE-2026-41001", ids(self.w45["main"]))
        self.assertNotIn("CVE-2026-41002", ids(self.w45["main"]))  # 11/1 公開（日曜）は第44週
        self.assertEqual(by_id(self.w45["main"])["CVE-2026-41001"]["tier"], "A")  # 週末時点では KEV 前

    def test_w45_movement(self):
        mv = self.w45["movement"]
        self.assertEqual([r["id"] for r in mv["kev_added"]], ["CVE-2026-41004"])
        self.assertFalse(mv["kev_added"][0]["new"])
        new = {r["id"]: r["tier"] for r in mv["new_sa"]}
        self.assertEqual(new.get("CVE-2026-41001"), "A")
        self.assertEqual(new.get("CVE-2026-41004"), "S")
        self.assertNotIn("CVE-2021-44228", new)

    def test_w46_movement(self):
        mv = self.w46["movement"]
        self.assertIn("CVE-2026-41001", ids(mv["kev_added"]))
        new = {r["id"]: r["tier"] for r in mv["new_sa"]}
        self.assertNotIn("CVE-2026-41001", new)  # 週の始めに既に A だった
        self.assertEqual(new.get("CVE-2026-41002"), "A")
        self.assertEqual(new.get("CVE-2024-50001"), "A")  # 古い CVE も含む
        self.assertEqual(new.get("CVE-2025-30001"), "A")  # EPSS の上昇で A 入り
        self.assertIn("CVE-2024-50001", ids(self.w46["poc"]))
        self.assertIn("CVE-2024-50001", ids(self.w46["resurfaced"]))
        self.assertNotIn("CVE-2026-999999", ids(self.w46["poc"]))

    def test_week_spanning_months(self):
        # 第44週（10/26〜11/1）は10月と11月の両方から集める
        src, fetcher = make_sources(jst("2026-11-20T10:00"))
        w44 = build_period(src, periods.week_of(date(2026, 10, 30)), date(2026, 11, 20), final=True)
        got = ids(w44["main"])
        self.assertTrue({"CVE-2026-41002", "CVE-2026-41003", "CVE-2026-41004"} <= got)


class DayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src, cls.fetcher = make_sources(jst("2026-11-20T10:00"))
        today = date(2026, 11, 20)
        cls.days = {d: build_period(cls.src, periods.day_of(date(2026, 11, d)), today, final=True)
                    for d in (1, 3, 4, 10, 11, 12)}
        cls.today = build_period(cls.src, periods.day_of(today), today)

    def test_ranking(self):
        self.assertEqual(ids(self.days[1]["main"]) & {"CVE-2026-41002", "CVE-2026-41003"},
                         {"CVE-2026-41002", "CVE-2026-41003"})
        self.assertIn("CVE-2026-41001", ids(self.days[3]["main"]))
        for d, data in self.days.items():
            self.assertTrue(all(r["published"] == f"2026-11-{d:02d}" for r in data["main"]))
        self.assertEqual(by_id(self.days[3]["main"])["CVE-2026-41001"]["tier"], "B")  # 11/3 時点は EPSS 5%・PoC なし

    def test_resurfaced_and_poc(self):
        self.assertEqual([r["id"] for r in self.days[4]["resurfaced"]][:1], ["CVE-2026-41004"])
        self.assertIn("CVE-2024-50001", ids(self.days[11]["resurfaced"]))
        self.assertIn("CVE-2024-50001", ids(self.days[11]["poc"]))
        self.assertNotIn("CVE-2026-999999", ids(self.days[12]["poc"]))
        self.assertIn("CVE-2026-41002", ids(self.days[12]["poc"]))

    def test_movement(self):
        self.assertIn("CVE-2026-41001", ids(self.days[10]["movement"]["kev_added"]))
        self.assertIn("CVE-2025-30001", ids(self.days[10]["movement"]["new_sa"]))  # 11/10 に EPSS 30%
        self.assertNotIn("CVE-2025-30001", ids(self.days[11]["movement"]["new_sa"]))

    def test_live_today(self):
        self.assertFalse(self.today["final"])
        self.assertEqual(self.today["as_of"], "2026-11-20")
        self.assertEqual(self.today["epss_date"], "2026-11-20")

    def test_live_week_into_next_month(self):
        # 10/30 時点の今週（10/26〜11/1）は、まだ始まっていない11月を NVD に問い合わせない
        src, fetcher = make_sources(jst("2026-10-30T10:00"))
        data = build_period(src, periods.week_of(date(2026, 10, 30)), date(2026, 10, 30))
        self.assertEqual(src.status["NVD"], "ok")
        self.assertTrue(data["main"])
        starts = [p["pubStartDate"][:7] for h, p in fetcher.calls if h == "services.nvd.nist.gov" and "pubStartDate" in p]
        self.assertEqual(starts, ["2026-10"])

    def test_nvd_fetched_once_per_month(self):
        nvd_calls = [p for h, p in self.fetcher.calls if h == "services.nvd.nist.gov" and "pubStartDate" in p]
        self.assertEqual(len(nvd_calls), 1)
        self.assertTrue(nvd_calls[0]["pubStartDate"].startswith("2026-11-01"))


class FinalizeTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def run_at(self, now, **kw):
        src, fetcher = make_sources(jst(now), **kw)
        written = archive.finalize(src, self.dir, "2026-11", jst(now).date(), now)
        return src, [Path(w).name for w in written]

    def test_nothing_before_start(self):
        _, w = self.run_at("2026-10-29T10:00")
        self.assertEqual(w, [])

    def test_catch_up_and_no_overwrite(self):
        _, w = self.run_at("2026-11-10T10:00")
        self.assertEqual(w, [f"2026-11-{d:02d}.json" for d in range(1, 10)] + ["2026-W45.json"])
        before = (self.dir / "weekly" / "2026-W45.json").read_bytes()
        before_day = (self.dir / "daily" / "2026-11-03.json").read_bytes()
        # 実行が飛んで 12/2 に動いた：残りの日、W46〜W48、11月をまとめて作る
        _, w = self.run_at("2026-12-02T10:00")
        self.assertEqual(w, [f"2026-11-{d:02d}.json" for d in range(10, 31)] + ["2026-12-01.json"]
                         + ["2026-W46.json", "2026-W47.json", "2026-W48.json", "2026-11.json"])
        self.assertEqual((self.dir / "weekly" / "2026-W45.json").read_bytes(), before)
        self.assertEqual((self.dir / "daily" / "2026-11-03.json").read_bytes(), before_day)
        _, w = self.run_at("2026-12-03T10:00")
        self.assertEqual(w, ["2026-12-02.json"])
        data = json.loads((self.dir / "monthly" / "2026-11.json").read_text())
        self.assertTrue(data["final"])
        self.assertEqual((data["as_of"], data["epss_date"]), ("2026-11-30", "2026-11-30"))

    def test_finalized_is_reproducible(self):
        self.run_at("2026-12-02T10:00")
        src, _ = make_sources(jst("2026-12-20T10:00"))
        for kind, p in (("monthly", NOV), ("weekly", W46), ("daily", periods.day_of(date(2026, 11, 11)))):
            a = json.loads((self.dir / kind / f"{p.key}.json").read_text())
            b = build_period(src, p, date(2026, 12, 20), final=True)
            for k in ("main", "resurfaced", "poc", "movement"):
                self.assertEqual(a[k], b[k], (kind, k))

    def test_skip_when_required_source_fails(self):
        src, w = self.run_at("2026-11-10T10:00", fail={"www.cisa.gov"})
        self.assertEqual(w, [])
        self.assertFalse(src.required_ok())
        _, w = self.run_at("2026-11-10T10:00", fail={"services.nvd.nist.gov"})
        self.assertEqual(w, [])
        _, w = self.run_at("2026-11-11T10:00")  # 次の回で追いつく
        self.assertIn("2026-W45.json", w)
        self.assertIn("2026-11-10.json", w)

    def test_skip_when_epss_not_published(self):
        src, fetcher = make_sources(jst("2026-11-09T10:00"))
        fetcher.epss_latest = "2026-11-07"  # 日曜分の EPSS がまだ出ていない
        src.epss_latest = src.epss_client.latest_date()
        written = [Path(w).name for w in archive.finalize(src, self.dir, "2026-11", date(2026, 11, 9), "x")]
        self.assertNotIn("2026-W45.json", written)
        self.assertNotIn("2026-11-08.json", written)
        self.assertIn("2026-11-07.json", written)

    def test_jvn_down_still_finalizes(self):
        src, w = self.run_at("2026-12-02T10:00", jvn_down=True)
        self.assertIn("2026-11.json", w)
        self.assertNotEqual(src.status["JVN"], "ok")
        data = json.loads((self.dir / "monthly" / "2026-11.json").read_text())
        self.assertTrue(all(r["jvn"] is None for r in data["main"]))
        self.assertIsNone(data["counts"]["jvn_missing"])


class SiteTest(unittest.TestCase):
    def build(self, now, jvn_down=False, finalize=True):
        arch, out = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp()) / "site"
        src, _ = make_sources(now, jvn_down=jvn_down)
        if finalize:
            archive.finalize(src, arch, "2026-11", now.date(), now.strftime("%Y-%m-%d %H:%M"))
        live = {k: build_period(src, periods.of(k, now.date()), now.date()) for k in periods.KINDS}
        generate(CFG, out, live, archive.load_all(arch), now.strftime("%Y-%m-%d %H:%M"), dict(src.status))
        return out, arch

    def test_generate(self):
        out, arch = self.build(jst("2026-12-02T10:00"), jvn_down=True)
        for p in ["index.html", "archive.html", "method.html", "monthly/2026-11.html", "monthly/2026-12.html",
                  "weekly/2026-W45.html", "weekly/2026-W49.html", "daily/2026-11-03.html", "daily/2026-12-02.html",
                  "data/monthly/2026-11.json", "data/daily/2026-12-02.json", "assets/app.js", "assets/style.css"]:
            self.assertTrue((out / p).exists(), p)
        for p in out.rglob("*.html"):
            html = p.read_text()
            self.assertIn("最終更新：2026-12-02 10:00（日本時間）", html, p)
            self.assertIn("JVN：取得失敗", html, p)
        month = (out / "monthly" / "2026-11.html").read_text()
        self.assertIn("JVN確認不可", month)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-50001", month)
        self.assertNotIn("github.com/someone", month)  # PoC への直リンクは置かない
        self.assertIn("../data/monthly/2026-11.json", month)
        self.assertIn("緊急", month)  # 深刻度は日本語で表示
        self.assertNotIn("CRITICAL", month)
        self.assertNotIn("さらに表示", month)
        self.assertEqual(month.count('class="pager"'), 2)  # 全件表の上と下
        self.assertIn('data-tab="movement"', month)
        self.assertEqual(len(json.loads((out / "data" / "monthly" / "2026-11.json").read_text())),
                         json.loads((arch / "monthly" / "2026-11.json").read_text())["counts"]["total"])
        method = (out / "method.html").read_text()
        self.assertIn("EPSS ≥ 10%", method)
        self.assertIn("EPSS ≥ 1%", method)
        archive_html = (out / "archive.html").read_text()
        for link in ("weekly/2026-W45.html", "monthly/2026-11.html", "daily/2026-11-03.html"):
            self.assertIn(link, archive_html)

    def test_switcher(self):
        out, _ = self.build(jst("2026-12-02T10:00"))
        day = (out / "daily" / "2026-11-03.html").read_text()
        # 日次のプルダウン：確定した31日＋今日（途中経過）、新しい順、今のページが選択済み
        self.assertEqual(day.count('<option value="../daily/'), 32)
        self.assertLess(day.index("2026-12-02.html"), day.index("2026-11-03.html"))
        self.assertIn('<option value="../daily/2026-11-03.html" selected>', day)
        self.assertIn("2026年12月2日（水）（途中経過）", day)
        self.assertIn('<optgroup label="2026年11月">', day)
        # 日次・週次・月次のボタンは、それぞれ最新ページへ
        self.assertIn('href="../daily/2026-12-02.html" class=on', day)
        self.assertIn('href="../weekly/2026-W49.html"', day)
        self.assertIn('href="../monthly/2026-12.html"', day)
        week = (out / "weekly" / "2026-W46.html").read_text()
        self.assertEqual(week.count('<option value="../weekly/'), 5)  # W45〜W48＋W49（途中経過）
        index = (out / "index.html").read_text()
        self.assertIn('href="monthly/2026-12.html" class=on', index)

    def test_preview_before_start_and_escaping(self):
        now = jst("2026-10-29T10:00")
        out = Path(tempfile.mkdtemp()) / "site"
        src, _ = make_sources(now)
        live = {k: build_period(src, periods.of(k, now.date()), now.date()) for k in periods.KINDS}
        live["monthly"]["main"][0]["summary"] = "<script>alert(1)</script>"
        generate(CFG, out, live, {k: [] for k in periods.KINDS}, "2026-10-29 10:00", dict(src.status))
        html = (out / "index.html").read_text()
        self.assertIn("開始前のプレビュー", html)
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("開始前のプレビュー", (out / "daily" / "2026-10-29.html").read_text())
        self.assertIn("まだ確定した週次", (out / "archive.html").read_text())


if __name__ == "__main__":
    unittest.main()
