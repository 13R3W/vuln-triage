import json
import tempfile
import unittest
from pathlib import Path

from triage import index, periods
from triage.build import build_period
from triage.site import generate
from triage.sources import epss, kev

from .helpers import CFG, jst, make_sources


class IndexBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src, cls.fetcher = make_sources(jst("2026-11-20T10:00"))
        cls.files = index.build(cls.src, "2026-11-20 10:00")

    def row(self, cve):
        _, y, n = cve.split("-")
        return self.files[f"{y}.json"].get(n)

    def test_rows(self):
        # [EPSS, KEV追加日, PoC初出日, PoCリポジトリ数]、後ろの空の値は省く
        self.assertEqual(self.row("CVE-2021-44228"), [0.944, "2021-12-10", "2021-12-10", 3])
        self.assertEqual(self.row("CVE-2026-41004"), [0.45, "2026-11-04"])
        self.assertEqual(self.row("CVE-2024-50001"), [0.15, None, "2026-11-11", 1])
        self.assertEqual(self.row("CVE-2026-41003"), [0.05])

    def test_old_cves_included(self):
        # 今日・今週・今月に関係なく、昔の CVE も入る
        self.assertIn("2021.json", self.files)
        self.assertIn("2025.json", self.files)
        self.assertEqual(self.row("CVE-2025-30001"), [0.3, None, "2025-06-01", 1])

    def test_garbage_poc_and_unscored(self):
        self.assertIsNone(self.row("CVE-2026-999999"))  # PoC のゴミ登録（EPSS なし）は入れない
        self.assertIsNone(self.row("CVE-2026-41006"))   # EPSS 未算出・KEV なし

    def test_meta_and_kev(self):
        meta = self.files["meta.json"]
        self.assertEqual(meta["epss_date"], "2026-11-20")
        self.assertEqual(meta["thresholds"], {"a_epss": 0.10, "b_epss": 0.01})
        self.assertEqual(meta["years"], sorted(y[:-5] for y in self.files if y[:4].isdigit()))
        self.assertEqual(meta["count"], sum(len(v) for k, v in self.files.items() if k[:4].isdigit()))
        act = self.files["kev.json"]["CVE-2026-41004"]
        self.assertEqual(act[:2], ["2026-11-04", "2026-11-25"])
        self.assertIn("Apply mitigations", act[2])

    def test_epss_fetched_in_pages(self):
        calls = [p for h, p in self.fetcher.calls if h == "api.first.org" and p.get("epss-gt") == "0"]
        self.assertTrue(calls)


class IndexFailureTest(unittest.TestCase):
    def test_none_when_source_failed(self):
        src, _ = make_sources(jst("2026-11-20T10:00"), fail={"www.cisa.gov"})
        self.assertIsNone(index.build(src, "x"))

    def test_publish_uses_previous_when_failed(self):
        base = Path(tempfile.mkdtemp())
        cache, out = base / "cache", base / "site"
        self.assertFalse(index.publish(None, out, cache))  # 前回分も無い
        self.assertFalse((out / "data" / "index").exists())
        src, _ = make_sources(jst("2026-11-20T10:00"))
        self.assertTrue(index.publish(index.build(src, "2026-11-20 10:00"), out, cache))
        first = (out / "data" / "index" / "meta.json").read_text()
        # 次の回は失敗：前回分をそのまま置く
        out2 = base / "site2"
        self.assertTrue(index.publish(None, out2, cache))
        self.assertEqual((out2 / "data" / "index" / "meta.json").read_text(), first)
        self.assertEqual(json.loads(first)["generated_at"], "2026-11-20 10:00")


class EpssCacheTest(unittest.TestCase):
    def test_fetch_once_per_day(self):
        cache = Path(tempfile.mkdtemp()) / "epss"
        src, fetcher = make_sources(jst("2026-11-20T10:00"))
        first = index.build(src, "10:00", cache)

        def all_calls(f):
            return len([p for h, p in f.calls if h == "api.first.org" and p.get("epss-gt") == "0"])

        self.assertGreater(all_calls(fetcher), 0)
        self.assertTrue((cache / "2026-11-20.json").exists())
        # 同じ日の次の回：EPSS 全件は取り直さない（KEV・PoC は毎回最新）
        src2, fetcher2 = make_sources(jst("2026-11-20T11:00"))
        second = index.build(src2, "11:00", cache)
        self.assertEqual(all_calls(fetcher2), 0)
        self.assertEqual(second["2026.json"], first["2026.json"])
        # 日付が変わったら取り直し、古い日付の分は消す
        src3, fetcher3 = make_sources(jst("2026-11-21T10:00"))
        index.build(src3, "x", cache)
        self.assertGreater(all_calls(fetcher3), 0)
        self.assertEqual([p.name for p in cache.iterdir()], ["2026-11-21.json"])


class SourcesTest(unittest.TestCase):
    def test_kev_actions(self):
        raw = json.dumps({"vulnerabilities": [
            {"cveID": " cve-2021-44228 ", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
             "requiredAction": "Apply updates\n per vendor instructions."},
            {"cveID": "CVE-2024-1", "dateAdded": "2024-01-02"}]}).encode()
        self.assertEqual(kev.parse_actions(raw), {
            "CVE-2021-44228": ["2021-12-10", "2021-12-24", "Apply updates per vendor instructions."],
            "CVE-2024-1": ["2024-01-02", "", ""]})

    def test_epss_all_scores_paging(self):
        src, fetcher = make_sources(jst("2026-11-20T10:00"))
        c = epss.EpssClient(fetcher, dict(CFG["epss"], page_size=7))
        got = c.all_scores("2026-11-20")
        self.assertEqual(got["CVE-2021-44228"], 0.944)
        self.assertGreater(len(got), 7)
        self.assertNotIn("CVE-2026-999999", got)


class CheckPageTest(unittest.TestCase):
    def test_page(self):
        now = jst("2026-11-20T10:00")
        out = Path(tempfile.mkdtemp()) / "site"
        src, _ = make_sources(now)
        live = {k: build_period(src, periods.of(k, now.date()), now.date()) for k in periods.KINDS}
        generate(CFG, out, live, {k: [] for k in periods.KINDS})
        html = (out / "check.html").read_text()
        self.assertIn("自分の環境をチェック", html)
        self.assertIn('<input type="file" multiple>', html)
        self.assertIn("どこにも送らず", html)
        self.assertIn('src="assets/check-core.js"', html)
        self.assertIn('src="assets/check.js"', html)
        self.assertTrue((out / "assets" / "check-core.js").exists())
        # 全ページのヘッダーからたどれる
        self.assertIn('href="../check.html">自分の環境をチェック', (out / "daily" / "2026-11-20.html").read_text())
        self.assertNotIn("check.js", (out / "index.html").read_text())


if __name__ == "__main__":
    unittest.main()
