import io
import json
import tempfile
import unittest
import urllib.error
from datetime import date
from pathlib import Path
from unittest import mock

from triage import http, sample
from triage.sources import epss, jvn, kev, nvd, poc

from .helpers import CFG, jst


class NvdParseTest(unittest.TestCase):
    def item(self, metrics=None, weaknesses=None, desc="x"):
        return {"cve": {"id": "CVE-2026-1", "published": "2026-10-31T15:00:00.000",
                        "descriptions": [{"lang": "es", "value": "es"}, {"lang": "en", "value": desc}],
                        "metrics": metrics or {}, "weaknesses": weaknesses or []}}

    def test_cna_cvss_preferred(self):
        m = {"cvssMetricV31": [
            {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
            {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}}]}
        r = nvd.parse_cve(self.item(m))
        self.assertEqual((r["cvss"], r["severity"], r["cvss_source"]), (7.5, "HIGH", "CNA"))

    def test_nvd_cvss_fallback_and_v2_severity(self):
        m = {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH",
                               "cvssData": {"version": "2.0", "baseScore": 7.5}}]}
        r = nvd.parse_cve(self.item(m))
        self.assertEqual((r["cvss"], r["severity"], r["cvss_source"]), (7.5, "HIGH", "NVD"))
        self.assertIsNone(nvd.parse_cve(self.item())["cvss"])

    def test_cwe_and_summary(self):
        w = [{"type": "Primary", "description": [{"value": "CWE-77"}]},
             {"type": "Secondary", "description": [{"value": "CWE-20"}, {"value": "NVD-CWE-noinfo"}, {"value": "CWE-20"}]}]
        r = nvd.parse_cve(self.item(weaknesses=w, desc="a  b\n" + "c" * 300), summary_chars=200)
        self.assertEqual(r["cwe"], ["CWE-20"])
        self.assertTrue(r["summary"].startswith("a b c"))
        self.assertLessEqual(len(r["summary"]), 201)
        self.assertEqual(r["published"], "2026-11-01")  # UTC 15:00 → 日本時間の翌日

    def test_paging_and_lookup_cache(self):
        fetcher = sample.SampleFetcher(sample.universe(), jst("2026-12-02T10:00"))
        cfg = dict(CFG["nvd"], page_size=7)
        with tempfile.TemporaryDirectory() as d:
            client = nvd.NvdClient(fetcher, cfg, cache_dir=d)
            recs = client.published("2026-11-01T00:00:00.000+09:00", "2026-11-30T23:59:59.000+09:00")
            self.assertEqual(len(recs), len({r["id"] for r in recs}))
            self.assertGreater(len(recs), 7)
            self.assertNotIn("CVE-2026-41007", {r["id"] for r in recs})  # 取り下げ分
            got = client.lookup(["CVE-2024-50001"])
            self.assertEqual(got["CVE-2024-50001"]["cwe"], ["CWE-416"])
            n = len(fetcher.calls)
            client2 = nvd.NvdClient(fetcher, cfg, cache_dir=d)
            client2.lookup(["CVE-2024-50001"])
            self.assertEqual(len(fetcher.calls), n)  # キャッシュから読む

    def test_lookup_limit(self):
        fetcher = sample.SampleFetcher(sample.universe(), jst("2026-12-02T10:00"))
        client = nvd.NvdClient(fetcher, dict(CFG["nvd"], lookup_limit=1))
        got = client.lookup(["CVE-2024-50001", "CVE-2025-30001"])
        self.assertEqual(list(got), ["CVE-2024-50001"])
        self.assertEqual(client.lookups_skipped, 1)

    def test_api_key_interval(self):
        self.assertEqual(nvd.NvdClient(None, CFG["nvd"]).interval, 6.0)
        c = nvd.NvdClient(None, CFG["nvd"], api_key="k")
        self.assertLess(c.interval, 1.0)
        self.assertEqual(c.headers, {"apiKey": "k"})
        self.assertGreater(c.lookup_limit, nvd.NvdClient(None, CFG["nvd"]).lookup_limit)


class EpssTest(unittest.TestCase):
    def test_chunks_within_limit(self):
        c = epss.EpssClient(None, CFG["epss"])
        ids = [f"CVE-2026-{i:05d}" for i in range(1000)]
        chunks = c.chunks(ids)
        self.assertEqual(sum(len(x) for x in chunks), 1000)
        self.assertTrue(all(len(",".join(x)) <= 2000 for x in chunks))
        self.assertGreater(len(",".join(chunks[0])), 1900)

    def test_scores_are_floats_and_limit_matches(self):
        fetcher = sample.SampleFetcher(sample.universe(), jst("2026-11-20T10:00"))
        c = epss.EpssClient(fetcher, CFG["epss"])
        got = c.scores(["CVE-2026-41001", "CVE-2026-999999", "CVE-2026-41006"], "2026-11-10")
        self.assertEqual(got, {"CVE-2026-41001": 0.6})
        host, params = fetcher.calls[-1]
        self.assertEqual(params["limit"], 3)
        self.assertEqual(c.latest_date(), "2026-11-20")
        self.assertEqual(c.scores(["CVE-2026-41001"], "2026-11-05"), {"CVE-2026-41001": 0.05})

    def test_above_paging(self):
        fetcher = sample.SampleFetcher(sample.universe(), jst("2026-11-20T10:00"))
        c = epss.EpssClient(fetcher, dict(CFG["epss"], page_size=2))
        got = c.above(0.10, "2026-11-10")
        self.assertTrue({"CVE-2026-41001", "CVE-2026-41002", "CVE-2025-30001", "CVE-2024-50001"} <= got)
        self.assertNotIn("CVE-2026-41003", got)


class KevTest(unittest.TestCase):
    def test_parse(self):
        raw = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
                                              {"cveID": "cve-2024-1 ", "dateAdded": "2024-01-02"}]}).encode()
        self.assertEqual(kev.parse(raw), {"CVE-2021-44228": "2021-12-10", "CVE-2024-1": "2024-01-02"})


class PocTest(unittest.TestCase):
    def test_scan(self):
        with tempfile.TemporaryDirectory() as d:
            sample.write_poc_tree(sample.universe(), d, jst("2026-11-20T10:00"))
            (Path(d) / "2026" / "CVE-2026-1.json").write_text("not json")
            (Path(d) / "2026" / "notes.txt").write_text("x")
            got = poc.scan(d)
        self.assertEqual(got["CVE-2021-44228"]["date"], "2021-12-10")
        self.assertEqual(got["CVE-2021-44228"]["repos"], 3)
        self.assertEqual(got["CVE-2026-41001"]["dates"], ["2026-11-05", "2026-11-07"])
        self.assertIn("CVE-2026-999999", got)  # ゴミ登録は読み込み段階では残る（EPSS で除外する）
        self.assertNotIn("CVE-2026-1", got)


class JvnTest(unittest.TestCase):
    def test_fetch_paging(self):
        fetcher = sample.SampleFetcher(sample.universe(), jst("2026-11-20T10:00"))
        got = jvn.fetch(fetcher, dict(CFG["jvn"], page_size=3), date(2026, 9, 1), date(2026, 11, 20))
        self.assertTrue({"CVE-2026-41001", "CVE-2026-41002", "CVE-2026-41005"} <= got)
        self.assertNotIn("CVE-2026-41008", got)
        self.assertGreater(len([c for c in fetcher.calls if c[0] == "jvndb.jvn.jp"]), 3)

    def test_outage_page_is_error(self):
        with self.assertRaises(ValueError):
            jvn.parse_page(sample.JVN_OUTAGE.encode())

    def test_error_status(self):
        raw = (b'<?xml version="1.0"?><rdf:RDF xmlns:rdf="r" xmlns:status="s">'
               b'<status:Status retCd="1" errCd="E" errMsg="bad"/></rdf:RDF>')
        with self.assertRaises(ValueError):
            jvn.parse_page(raw)

    def test_unknown_element_names(self):
        # 要素名が想定と違っても、item 内の CVE 番号は拾える
        raw = (b'<?xml version="1.0"?><root xmlns="x"><item><foo ref="CVE-2026-0001"/>'
               b'<bar>see cve-2026-0002 and CVE-2026-0003</bar></item></root>')
        cves, items, total = jvn.parse_page(raw)
        self.assertEqual((cves, items, total), ({"CVE-2026-0001", "CVE-2026-0003"}, 1, None))


class HttpTest(unittest.TestCase):
    def test_build_url(self):
        url = http.build_url("https://x/api", {"a": "1+2", "noRejected": True, "skip": None, "cve": "A,B"})
        self.assertEqual(url, "https://x/api?a=1%2B2&noRejected&cve=A,B")

    def test_retry_then_success(self):
        sleeps = []
        f = http.HttpFetcher(retries=3, sleep=sleeps.append)
        calls = {"n": 0}

        def fake(req, timeout):
            calls["n"] += 1
            if calls["n"] < 3:
                raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)
            return io.BytesIO(b"ok")

        with mock.patch("urllib.request.urlopen", fake):
            self.assertEqual(f.get("https://example.com/x"), b"ok")
        self.assertEqual(calls["n"], 3)
        self.assertEqual(len(sleeps), 2)

    def test_gives_up(self):
        f = http.HttpFetcher(retries=2, sleep=lambda s: None)

        def fake(req, timeout):
            raise urllib.error.URLError("down")

        with mock.patch("urllib.request.urlopen", fake), self.assertRaises(http.FetchError):
            f.get("https://example.com/x")

    def test_no_retry_on_404(self):
        f = http.HttpFetcher(retries=3, sleep=lambda s: None)
        calls = {"n": 0}

        def fake(req, timeout):
            calls["n"] += 1
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)

        with mock.patch("urllib.request.urlopen", fake), self.assertRaises(http.FetchError):
            f.get("https://example.com/x")
        self.assertEqual(calls["n"], 1)

    def test_interval(self):
        t = {"now": 0.0}
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            t["now"] += s

        f = http.HttpFetcher(sleep=sleep, clock=lambda: t["now"])
        with mock.patch("urllib.request.urlopen", lambda req, timeout: io.BytesIO(b"")):
            f.get("https://a.example/x", interval=6)
            f.get("https://a.example/y", interval=6)
            f.get("https://b.example/z", interval=6)
        self.assertEqual(sleeps, [6])


if __name__ == "__main__":
    unittest.main()
