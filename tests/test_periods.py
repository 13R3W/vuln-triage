import unittest
from datetime import date

from triage import periods


class PeriodTest(unittest.TestCase):
    def test_to_jst_date(self):
        self.assertEqual(periods.to_jst_date("2026-10-31T16:00:00.000"), "2026-11-01")  # タイムゾーンなし＝UTC
        self.assertEqual(periods.to_jst_date("2026-10-31T14:59:59Z"), "2026-10-31")
        self.assertEqual(periods.to_jst_date("2026-11-01T00:30:00+09:00"), "2026-11-01")
        self.assertEqual(periods.to_jst_date("2026-11-04"), "2026-11-04")
        self.assertIsNone(periods.to_jst_date(""))

    def test_month(self):
        p = periods.parse_month("2026-11")
        self.assertEqual((p.start, p.end), (date(2026, 11, 1), date(2026, 11, 30)))
        self.assertEqual(periods.month(2026, 12).end, date(2026, 12, 31))
        self.assertEqual(p.label, "2026年11月")
        self.assertEqual(p.nvd_range(), ("2026-11-01T00:00:00.000+09:00", "2026-11-30T23:59:59.000+09:00"))

    def test_first_week_is_nov2(self):
        w = periods.first_week("2026-11")
        self.assertEqual((w.key, w.start, w.end), ("2026-W45", date(2026, 11, 2), date(2026, 11, 8)))
        self.assertIn("第45週", w.label)

    def test_day(self):
        d = periods.day_of(date(2026, 11, 3))
        self.assertEqual((d.kind, d.key, d.start, d.end), ("daily", "2026-11-03", date(2026, 11, 3), date(2026, 11, 3)))
        self.assertEqual(d.label, "2026年11月3日（火）")
        self.assertEqual(d.nvd_range(), ("2026-11-03T00:00:00.000+09:00", "2026-11-03T23:59:59.000+09:00"))
        self.assertTrue(d.contains("2026-11-03"))
        self.assertFalse(d.contains("2026-11-04"))
        self.assertEqual(periods.of("weekly", date(2026, 11, 3)).key, "2026-W45")
        self.assertEqual(periods.of("monthly", date(2026, 11, 3)).key, "2026-11")

    def test_closed_days(self):
        self.assertEqual(periods.closed_days("2026-11", date(2026, 11, 1)), [])  # 当日は含まない
        self.assertEqual([d.key for d in periods.closed_days("2026-11", date(2026, 11, 3))],
                         ["2026-11-01", "2026-11-02"])
        self.assertEqual(periods.closed_days("2026-11", date(2026, 10, 29)), [])
        self.assertEqual(len(periods.closed_days("2026-11", date(2026, 12, 2))), 31)

    def test_closed_periods(self):
        # 日曜（11/8）の時点では第45週はまだ終わっていない
        self.assertEqual(periods.closed_weeks("2026-11", date(2026, 11, 8)), [])
        self.assertEqual([w.key for w in periods.closed_weeks("2026-11", date(2026, 11, 9))], ["2026-W45"])
        self.assertEqual(periods.closed_months("2026-11", date(2026, 11, 30)), [])
        self.assertEqual([m.key for m in periods.closed_months("2026-11", date(2027, 1, 3))], ["2026-11", "2026-12"])
        # 年をまたぐ週
        keys = [w.key for w in periods.closed_weeks("2026-11", date(2027, 1, 12))]
        self.assertEqual(keys[-2:], ["2026-W53", "2027-W01"])
        # 開始月より前は作らない
        self.assertEqual(periods.closed_months("2026-11", date(2026, 10, 29)), [])


if __name__ == "__main__":
    unittest.main()
