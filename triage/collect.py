"""データ源の取得をまとめ、失敗したデータ源を記録する。

各データ源が一時的に落ちていても止まらないよう、取得はここで例外を受け止め、
その回だけ「取得失敗」として記録して続行する。
"""

from __future__ import annotations

import sys
from datetime import date, timedelta

from . import periods
from .sources import epss as epss_src
from .sources import jvn as jvn_src
from .sources import kev as kev_src
from .sources import nvd as nvd_src

SOURCES = ("NVD", "KEV", "EPSS", "PoC", "JVN")
# これらのどれかが失敗した回は、日・週・月の確定をしない（次の実行で追いつく）
REQUIRED = ("NVD", "KEV", "EPSS", "PoC")


class Sources:
    def __init__(self, cfg: dict, fetcher, poc_loader, api_key: str | None = None, cache_dir=None, now=None):
        self.cfg = cfg
        self.fetcher = fetcher
        self.poc_loader = poc_loader
        self.thresholds = cfg["tiers"]
        summary_chars = int(cfg["display"].get("summary_chars", 200))
        self.nvd = nvd_src.NvdClient(fetcher, cfg["nvd"], api_key=api_key, cache_dir=cache_dir,
                                     summary_chars=summary_chars)
        self.epss_client = epss_src.EpssClient(fetcher, cfg["epss"])
        self.status: dict[str, str] = {name: "ok" for name in SOURCES}
        self.kev: dict[str, str] = {}
        self.poc: dict[str, dict] = {}
        self.epss_latest: str | None = None
        self.now = now  # 途中経過の期間で、NVD の検索範囲の終わりをここまでにする
        self.records: dict[str, dict] = {}  # NVD から得た CVE の詳細（同じ回の中で使い回す）
        self._month_recs: dict[str, list[dict] | None] = {}  # 月ごとの公開分（NVD は月単位で1回だけ取る）
        self._epss_cache: dict[tuple[str, str | None], float | None] = {}
        self._above_cache: dict[tuple[float, str], set[str]] = {}
        self._jvn_cache: dict[tuple[date, date], set[str] | None] = {}

    # ---- 失敗の記録 ----
    def fail(self, name: str, err: Exception) -> None:
        if self.status[name] == "ok":
            self.status[name] = f"取得失敗（{err}）"
        print(f"[warn] {name}: {err}", file=sys.stderr)

    def ok(self, name: str) -> bool:
        return self.status[name] == "ok"

    def required_ok(self) -> bool:
        return all(self.ok(n) for n in REQUIRED)

    # ---- 毎回まとめて取るもの ----
    def load(self) -> None:
        try:
            self.kev = kev_src.fetch(self.fetcher, self.cfg["kev"])
        except Exception as e:  # noqa: BLE001
            self.fail("KEV", e)
        try:
            self.poc = self.poc_loader()
        except Exception as e:  # noqa: BLE001
            self.fail("PoC", e)
        try:
            self.epss_latest = self.epss_client.latest_date()
        except Exception as e:  # noqa: BLE001
            self.fail("EPSS", e)

    # ---- NVD ----
    def _month(self, month) -> list[dict]:
        if month.key not in self._month_recs:
            recs = None
            if self.now is not None and month.start > self.now.date():
                recs = []  # まだ始まっていない月（今週が翌月にまたがる場合など）は問い合わせない
            elif self.ok("NVD"):
                try:
                    recs = self.nvd.published(*month.nvd_range(self.now))
                except Exception as e:  # noqa: BLE001
                    self.fail("NVD", e)
            self._month_recs[month.key] = recs
            for r in recs or []:
                self.records[r["id"]] = r
        return self._month_recs[month.key] or []

    def published_in(self, period) -> list[dict]:
        """period（日本時間）に公開された CVE（取り下げ分を除く）。

        NVD は月単位でまとめて1回だけ取り、日・週はその中から公開日で絞る。
        """
        out = []
        m = periods.month_of(period.start)
        while m.start <= period.end:
            out.extend(r for r in self._month(m) if period.contains(r["published"]))
            m = periods.month_of(m.end + timedelta(days=1))
        return out

    def details(self, ids) -> dict[str, dict]:
        """CVE の詳細（概要・CVSS・CWE・公開日）。この回で取得済みのものは使い回す。"""
        ids = list(dict.fromkeys(ids))
        missing = [c for c in ids if c not in self.records]
        if missing and self.ok("NVD"):
            try:
                self.records.update(self.nvd.lookup(missing))
            except Exception as e:  # noqa: BLE001
                self.fail("NVD", e)
        return {c: self.records[c] for c in ids if c in self.records}

    # ---- EPSS ----
    def epss(self, ids, day: str | None) -> dict[str, float]:
        """{CVE番号: EPSS}（day の値。None は最新）。スコアが無い CVE は含まれない。"""
        ids = set(ids)
        todo = [c for c in ids if (c, day) not in self._epss_cache]
        if todo and self.ok("EPSS"):
            try:
                got = self.epss_client.scores(todo, day)
            except Exception as e:  # noqa: BLE001
                self.fail("EPSS", e)
            else:
                for c in todo:
                    self._epss_cache[(c, day)] = got.get(c)
        out = {}
        for c in ids:
            v = self._epss_cache.get((c, day))
            if v is not None:
                out[c] = v
        return out

    def epss_above(self, threshold: float, day: str) -> set[str]:
        key = (threshold, day)
        if key not in self._above_cache:
            if not self.ok("EPSS"):
                return set()
            try:
                self._above_cache[key] = self.epss_client.above(threshold, day)
            except Exception as e:  # noqa: BLE001
                self.fail("EPSS", e)
                return set()
        return self._above_cache[key]

    # ---- JVN ----
    def jvn(self, start: date, end: date) -> set[str] | None:
        """JVN iPedia に載っている CVE 番号。取得失敗なら None（＝掲載有無は不明）。"""
        key = (start, end)
        if key not in self._jvn_cache:
            if not self.ok("JVN"):
                return None
            try:
                self._jvn_cache[key] = jvn_src.fetch(self.fetcher, self.cfg["jvn"], start, end)
            except Exception as e:  # noqa: BLE001
                self.fail("JVN", e)
                self._jvn_cache[key] = None
        return self._jvn_cache[key]


def days_before(day: str, n: int) -> str:
    return (date.fromisoformat(day) - timedelta(days=n)).isoformat()
