import json
import tempfile
import unittest
from pathlib import Path

from triage import archive, periods
from triage.build import build_month, build_week
from triage.site import generate

from .helpers import CFG, jst, make_sources

NOV = periods.parse_month("2026-11")


def by_id(rows):
    return {r["id"]: r for r in rows}


class MonthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        now = jst("2026-11-20T10:00")
        cls.src, _ = make_sources(now)
        cls.data = build_month(cls.src, NOV, now.date(), now=now)

    def test_main_population(self):
        ids = {r["id"] for r in self.data["main"]}
        self.assertIn("CVE-2026-41002", ids)      # 日本時間 11/1 23:30
        self.assertIn("CVE-2026-41003", ids)      # 日本時間 11/1 01:00（UTC では 10/31）
        self.assertNotIn("CVE-2026-41004", ids)   # 日本時間 10/31 23:00
        self.assertNotIn("CVE-2026-41007", ids)   # 取り下げ
        self.assertNotIn("CVE-2021-44228", ids)
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
        self.assertAlmostEqual(r["epss_delta"], 0.0)  # 11/13 と 11/20 はどちらも 0.6
        self.assertIs(m["CVE-2026-41008"]["jvn"], False)
        self.assertEqual(self.data["epss_date"], "2026-11-20")
        self.assertEqual(self.data["epss_prev_date"], "2026-11-13")

    def test_order(self):
        tiers = [r["tier"] for r in self.data["main"]]
        self.assertEqual(tiers, sorted(tiers, key="SABC".index))
        for t in "SABC":
            e = [r["epss"] for r in self.data["main"] if r["tier"] == t and r["epss"] is not None]
            self.assertEqual(e, sorted(e, reverse=True))

    def test_epss_delta(self):
        # 7日前比：最新日と7日前の差
        m = by_id(self.data["main"])
        self.assertAlmostEqual(m["CVE-2026-41003"]["epss_delta"], 0.02)  # 11/13 は 3%、11/20 は 5%
        self.assertIsNone(m["CVE-2026-41005"]["epss_delta"])  # 7日前（11/13）はまだ公開前

    def test_resurfaced(self):
        res = by_id(self.data["resurfaced"])
        self.assertIn("CVE-2026-41004", res)  # 10月公開・11月 KEV 追加
        self.assertEqual(res["CVE-2026-41004"]["events"], [{"type": "KEV追加", "date": "2026-11-04"}])
        self.assertIn("CVE-2024-50001", res)  # 古い CVE に初めて PoC
        self.assertEqual(res["CVE-2024-50001"]["cwe"], ["CWE-416"])  # NVD 個別取得
        self.assertNotIn("CVE-2021-44228", res)
        self.assertNotIn("CVE-2025-30001", res)  # EPSS が上がっただけでは再浮上ではない
        self.assertNotIn("CVE-2026-999999", res)  # ゴミ登録
        e = [r["epss"] for r in self.data["resurfaced"]]
        self.assertEqual(e, sorted(e, key=lambda v: -(v or 0)))
        self.assertLessEqual(len(res), CFG["display"]["resurfaced_max"])

    def test_poc_tab(self):
        p = by_id(self.data["poc"])
        self.assertIn("CVE-2024-50001", p)
        self.assertFalse(p["CVE-2024-50001"]["this_month"])
        self.assertEqual(p["CVE-2026-41001"]["poc"], "2026-11-05")
        self.assertIn("CVE-2026-41006", p)
        self.assertNotIn("CVE-2026-999999", p)
        self.assertNotIn("CVE-2025-30001", p)  # PoC 初出は 2025年
        self.assertTrue(all(NOV.contains(r["poc"]) for r in self.data["poc"]))

    def test_counts(self):
        c = self.data["counts"]
        self.assertEqual(c["total"], len(self.data["main"]))
        self.assertEqual(sum(c["tiers"].values()), c["total"])
        self.assertEqual(c["jvn_missing"], sum(1 for r in self.data["main"] if r["jvn"] is False))

    def test_record_size(self):
        # 1件あたり数百バイトに収まる
        size = max(len(json.dumps(r, ensure_ascii=False).encode()) for r in self.data["main"])
        self.assertLess(size, 700)


class WeekTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src, _ = make_sources(jst("2026-11-20T10:00"))
        weeks = periods.closed_weeks("2026-11", periods.parse_month("2026-11").start.replace(day=20))
        cls.w45, cls.w46 = (build_week(cls.src, w) for w in weeks)

    def test_w45(self):
        self.assertEqual([r["id"] for r in self.w45["kev_added"]], ["CVE-2026-41004"])
        self.assertIn("CVE-2026-41001", [r["id"] for r in self.w45["poc_first"]])
        new = {r["id"]: r["tier"] for r in self.w45["new_sa"]}
        self.assertEqual(new.get("CVE-2026-41001"), "A")  # 週末時点では KEV 前なので A
        self.assertEqual(new.get("CVE-2026-41004"), "S")
        self.assertNotIn("CVE-2021-44228", new)
        self.assertGreater(self.w45["new_cves"], 0)

    def test_w46(self):
        kev = [r["id"] for r in self.w46["kev_added"]]
        self.assertIn("CVE-2026-41001", kev)
        new = {r["id"]: r["tier"] for r in self.w46["new_sa"]}
        self.assertNotIn("CVE-2026-41001", new)  # 週の始めに既に A だった
        self.assertEqual(new.get("CVE-2026-41002"), "A")
        self.assertEqual(new.get("CVE-2024-50001"), "A")  # 古い CVE も含む
        self.assertEqual(new.get("CVE-2025-30001"), "A")  # EPSS の上昇で A 入り
        poc = [r["id"] for r in self.w46["poc_first"]]
        self.assertIn("CVE-2024-50001", poc)
        self.assertNotIn("CVE-2026-999999", poc)

    def test_new_cve_count_matches_nvd(self):
        w = periods.first_week("2026-11")
        recs = self.src.nvd_published(w)
        self.assertEqual(self.w45["new_cves"], len(recs))


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
        self.assertEqual(w, ["2026-W45.json"])
        before = (self.dir / "weekly" / "2026-W45.json").read_bytes()
        # 実行が飛んで 12/2 に動いた：W46〜W48 と11月をまとめて作る
        _, w = self.run_at("2026-12-02T10:00")
        self.assertEqual(w, ["2026-W46.json", "2026-W47.json", "2026-W48.json", "2026-11.json"])
        self.assertEqual((self.dir / "weekly" / "2026-W45.json").read_bytes(), before)
        _, w = self.run_at("2026-12-03T10:00")
        self.assertEqual(w, [])
        data = json.loads((self.dir / "monthly" / "2026-11.json").read_text())
        self.assertTrue(data["final"])
        self.assertEqual((data["as_of"], data["epss_date"]), ("2026-11-30", "2026-11-30"))

    def test_finalized_month_is_reproducible(self):
        _, _ = self.run_at("2026-12-02T10:00")
        a = json.loads((self.dir / "monthly" / "2026-11.json").read_text())
        src, _ = make_sources(jst("2026-12-20T10:00"))
        b = build_month(src, NOV, jst("2026-12-20T10:00").date(), final=True)
        self.assertEqual(a["main"], b["main"])
        self.assertEqual(a["resurfaced"], b["resurfaced"])

    def test_skip_when_required_source_fails(self):
        src, w = self.run_at("2026-11-10T10:00", fail={"www.cisa.gov"})
        self.assertEqual(w, [])
        self.assertFalse(src.required_ok())
        _, w = self.run_at("2026-11-10T10:00", fail={"services.nvd.nist.gov"})
        self.assertEqual(w, [])
        _, w = self.run_at("2026-11-11T10:00")  # 次の回で追いつく
        self.assertEqual(w, ["2026-W45.json"])

    def test_skip_when_epss_not_published(self):
        src, fetcher = make_sources(jst("2026-11-09T10:00"))
        fetcher.epss_latest = "2026-11-07"  # 日曜分の EPSS がまだ出ていない
        src.epss_latest = src.epss_client.latest_date()
        self.assertEqual(archive.finalize(src, self.dir, "2026-11", jst("2026-11-09T10:00").date(), "x"), [])

    def test_jvn_down_still_finalizes(self):
        src, w = self.run_at("2026-12-02T10:00", jvn_down=True)
        self.assertIn("2026-11.json", w)
        self.assertNotEqual(src.status["JVN"], "ok")
        data = json.loads((self.dir / "monthly" / "2026-11.json").read_text())
        self.assertTrue(all(r["jvn"] is None for r in data["main"]))
        self.assertIsNone(data["counts"]["jvn_missing"])


class SiteTest(unittest.TestCase):
    def test_generate(self):
        now = jst("2026-12-02T10:00")
        arch, out = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp()) / "site"
        src, _ = make_sources(now, jvn_down=True)
        archive.finalize(src, arch, "2026-11", now.date(), "2026-12-02 10:00")
        live = build_month(src, periods.month_of(now.date()), now.date(), now=now)
        generate(CFG, out, live, archive.load_all(arch), "2026-12-02 10:00", dict(src.status))
        for p in ["index.html", "archive.html", "method.html", "monthly/2026-11.html", "weekly/2026-W45.html",
                  "data/current.json", "data/monthly/2026-11.json", "assets/app.js", "assets/style.css"]:
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
        method = (out / "method.html").read_text()
        self.assertIn("EPSS ≥ 10%", method)
        self.assertIn("EPSS ≥ 1%", method)
        archive_html = (out / "archive.html").read_text()
        self.assertIn("weekly/2026-W45.html", archive_html)
        self.assertIn("monthly/2026-11.html", archive_html)
        self.assertEqual(len(json.loads((out / "data" / "monthly" / "2026-11.json").read_text())),
                         json.loads((arch / "monthly" / "2026-11.json").read_text())["counts"]["total"])

    def test_preview_before_start_and_escaping(self):
        now = jst("2026-10-29T10:00")
        out = Path(tempfile.mkdtemp()) / "site"
        src, _ = make_sources(now)
        live = build_month(src, periods.month_of(now.date()), now.date(), now=now)
        live["main"][0]["summary"] = "<script>alert(1)</script>"
        generate(CFG, out, live, {"weekly": [], "monthly": []}, "2026-10-29 10:00", dict(src.status))
        html = (out / "index.html").read_text()
        self.assertIn("開始前のプレビュー", html)
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("まだ確定した週はありません", (out / "archive.html").read_text())


if __name__ == "__main__":
    unittest.main()
