import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from triage import live, periods
from triage.__main__ import main
from triage.build import build_period

from .helpers import jst, make_sources

OK = {"NVD": "ok", "KEV": "ok", "EPSS": "ok", "PoC": "ok", "JVN": "ok"}
NG = dict(OK, NVD="取得失敗（IncompleteRead）")


def fake(kind, key, total):
    return {"kind": kind, "key": key, "label": key, "counts": {"total": total}, "main": [{"id": f"CVE-{total}"}]}


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_success_saves_and_prunes(self):
        live.apply({"daily": fake("daily", "2026-11-19", 1)}, True, "2026-11-19 10:00", OK, self.dir)
        out = live.apply({"daily": fake("daily", "2026-11-20", 2)}, True, "2026-11-20 10:00", OK, self.dir)
        self.assertEqual(out["daily"]["fetched_at"], "2026-11-20 10:00")
        self.assertNotIn("fallback", out["daily"])
        self.assertEqual(sorted(p.name for p in (self.dir / "daily").iterdir()), ["2026-11-20.json"])

    def test_failure_uses_previous_of_same_period(self):
        live.apply({"weekly": fake("weekly", "2026-W47", 100)}, True, "2026-11-20 10:00", OK, self.dir)
        out = live.apply({"weekly": fake("weekly", "2026-W47", 0)}, False, "2026-11-20 15:00", NG, self.dir)
        w = out["weekly"]
        self.assertEqual(w["counts"]["total"], 100)
        self.assertEqual(w["fetched_at"], "2026-11-20 10:00")
        self.assertEqual(w["fallback"]["failed_at"], "2026-11-20 15:00")
        self.assertIn("取得失敗", w["fallback"]["status"]["NVD"])
        # 失敗した回は保存分を上書きしない（次も同じ前回分を使える）
        again = live.apply({"weekly": fake("weekly", "2026-W47", 0)}, False, "2026-11-20 18:00", NG, self.dir)
        self.assertEqual(again["weekly"]["counts"]["total"], 100)

    def test_failure_without_previous_keeps_current(self):
        live.apply({"daily": fake("daily", "2026-11-20", 5), "monthly": fake("monthly", "2026-11", 50)},
                   True, "2026-11-20 10:00", OK, self.dir)
        # 日が変わって最初の実行で失敗：日次は前回分なし、月次は同じ月の前回分あり
        out = live.apply({"daily": fake("daily", "2026-11-21", 0), "monthly": fake("monthly", "2026-11", 0)},
                         False, "2026-11-21 05:00", NG, self.dir)
        self.assertEqual(out["daily"]["counts"]["total"], 0)
        self.assertEqual(out["daily"]["fetched_at"], "2026-11-21 05:00")
        self.assertNotIn("fallback", out["daily"])
        self.assertEqual(out["monthly"]["counts"]["total"], 50)
        self.assertIn("fallback", out["monthly"])

    def test_real_period_data_roundtrip(self):
        now = jst("2026-11-20T10:00")
        src, _ = make_sources(now)
        data = {k: build_period(src, periods.of(k, now.date()), now.date()) for k in periods.KINDS}
        live.apply(data, True, "2026-11-20 10:00", OK, self.dir)
        back = live.load(self.dir, "monthly", "2026-11")
        self.assertEqual(back["main"], data["monthly"]["main"])


class EndToEndTest(unittest.TestCase):
    def run_cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            main(["run", "--sample", "--no-finalize", "--out", str(self.site), "--live-cache", str(self.cache),
                  "--archive", str(self.arch), *args])
        return out.getvalue()

    def setUp(self):
        base = Path(tempfile.mkdtemp())
        self.site, self.cache, self.arch = base / "site", base / "live", base / "archive"

    def test_second_run_failure_shows_first_run_data(self):
        self.run_cli("--now", "2026-11-20T10:00+09:00")
        first = (self.site / "monthly" / "2026-11.html").read_text()
        self.assertIn("更新日時：2026-11-20 10:00（日本時間）", first)
        self.assertNotIn("取得に失敗したため、前回", first)

        log = self.run_cli("--now", "2026-11-20T15:00+09:00", "--sample-fail", "services.nvd.nist.gov")
        self.assertIn("取得失敗のため 2026-11-20 10:00 取得分を表示", log)
        html = (self.site / "monthly" / "2026-11.html").read_text()
        self.assertIn("更新日時：2026-11-20 10:00（日本時間）", html)
        self.assertIn("今回（2026-11-20 15:00）の取得に失敗したため、前回（2026-11-20 10:00）取得したデータを表示しています。", html)
        self.assertIn("CVE-2026-41001", html)  # 前回のランキングが出ている
        self.assertIn("最終更新：2026-11-20 15:00", html)  # ヘッダーは今回の実行時刻
        self.assertIn("NVD：取得失敗", html)  # ヘッダーの取得状況は今回の状態
        self.assertNotIn("この回は表示できません", html)
        # 切り替え（ボタン・プルダウン）はタブ（ランキング〜動き）の下、更新日時はそのすぐ下
        self.assertLess(html.index('data-tab="movement"'), html.index('class="switcher"'))
        self.assertLess(html.index('class="switcher"'), html.index('class="data-updated"'))
        self.assertLess(html.index('class="data-updated"'), html.index('id="ranking"'))

    def test_failure_on_new_day_without_previous(self):
        self.run_cli("--now", "2026-11-20T10:00+09:00")
        self.run_cli("--now", "2026-11-21T05:00+09:00", "--sample-fail", "services.nvd.nist.gov")
        day = (self.site / "daily" / "2026-11-21.html").read_text()
        self.assertIn("この回は表示できません", day)
        self.assertIn("更新日時：2026-11-21 05:00（日本時間）", day)
        month = (self.site / "monthly" / "2026-11.html").read_text()
        self.assertIn("前回（2026-11-20 10:00）取得したデータを表示しています", month)

    def test_finalized_page_shows_finalized_time(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            main(["run", "--sample", "--out", str(self.site), "--live-cache", str(self.cache),
                  "--archive", str(self.arch), "--now", "2026-11-10T05:17+09:00"])
        html = (self.site / "weekly" / "2026-W45.html").read_text()
        self.assertIn("更新日時：2026-11-10 05:17（日本時間・確定）", html)


if __name__ == "__main__":
    unittest.main()
