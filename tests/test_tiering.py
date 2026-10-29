import unittest

from triage.tiering import sort_key, tier_at

TH = {"a_epss": 0.10, "b_epss": 0.01}


class TierTest(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(tier_at("2026-11-20", "2026-11-10", None, None, TH), "S")
        self.assertEqual(tier_at("2026-11-20", None, "2026-11-05", 0.10, TH), "A")
        self.assertEqual(tier_at("2026-11-20", None, "2026-11-05", 0.0999, TH), "B")
        self.assertEqual(tier_at("2026-11-20", None, None, 0.5, TH), "B")  # PoC なしは EPSS が高くても B
        self.assertEqual(tier_at("2026-11-20", None, None, 0.01, TH), "B")
        self.assertEqual(tier_at("2026-11-20", None, None, 0.0099, TH), "C")
        self.assertEqual(tier_at("2026-11-20", None, None, None, TH), "C")

    def test_point_in_time(self):
        # その時点より後の KEV 追加・PoC 初出は数えない
        self.assertEqual(tier_at("2026-11-09", "2026-11-10", "2026-11-05", 0.6, TH), "A")
        self.assertEqual(tier_at("2026-11-04", "2026-11-10", "2026-11-05", 0.6, TH), "B")

    def test_poc_needs_epss_unless_valid(self):
        # PoC-in-GitHub のゴミ登録対策：EPSS が無いと PoC を採用しない
        self.assertEqual(tier_at("2026-11-20", None, "2026-11-12", None, TH), "C")
        self.assertEqual(tier_at("2026-11-20", None, "2026-11-12", None, TH, poc_valid=True), "B")

    def test_thresholds_configurable(self):
        th = {"a_epss": 0.5, "b_epss": 0.2}
        self.assertEqual(tier_at("2026-11-20", None, "2026-11-05", 0.3, th), "B")
        self.assertEqual(tier_at("2026-11-20", None, None, 0.1, th), "C")

    def test_sort(self):
        rows = [{"id": "c", "tier": "B", "epss": None}, {"id": "b", "tier": "B", "epss": 0.2},
                {"id": "a", "tier": "S", "epss": 0.01}, {"id": "d", "tier": "B", "epss": 0.5}]
        self.assertEqual([r["id"] for r in sorted(rows, key=sort_key)], ["a", "d", "b", "c"])


if __name__ == "__main__":
    unittest.main()
