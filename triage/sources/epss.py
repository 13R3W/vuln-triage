"""FIRST EPSS API。"""

from __future__ import annotations

import json


class EpssClient:
    def __init__(self, fetcher, cfg: dict):
        self.fetcher = fetcher
        self.base = cfg["base_url"]
        self.interval = float(cfg.get("interval", 1.0))
        self.max_chars = int(cfg.get("max_param_chars", 2000))
        self.page_size = int(cfg.get("page_size", 10000))

    def _get(self, params: dict) -> dict:
        data = json.loads(self.fetcher.get(self.base, params, interval=self.interval))
        if str(data.get("status-code", 200)) != "200":
            raise ValueError(f"EPSS status {data.get('status-code')}")
        return data

    def latest_date(self) -> str:
        data = self._get({"limit": 1})
        return data["data"][0]["date"]

    def chunks(self, ids) -> list[list[str]]:
        """cve パラメータ（カンマ区切り）が max_param_chars 以内に収まるように分ける。"""
        out, cur, length = [], [], 0
        for cve in ids:
            add = len(cve) + (1 if cur else 0)
            if cur and length + add > self.max_chars:
                out.append(cur)
                cur, length = [], 0
                add = len(cve)
            cur.append(cve)
            length += add
        if cur:
            out.append(cur)
        return out

    def scores(self, ids, date: str | None = None) -> dict[str, float]:
        """{CVE番号: EPSS}。EPSS スコアが無い CVE は結果に含まれない。"""
        out: dict[str, float] = {}
        for chunk in self.chunks(sorted(set(ids))):
            data = self._get({"cve": ",".join(chunk), "date": date, "limit": len(chunk)})
            for row in data.get("data", []):
                out[row["cve"]] = float(row["epss"])
        return out

    def above(self, threshold: float, date: str) -> set[str]:
        """その日 EPSS が threshold 以上だった CVE 全件。"""
        out: set[str] = set()
        offset = 0
        while True:
            data = self._get({"epss-gt": f"{max(threshold - 1e-9, 0):.9f}", "date": date,
                              "limit": self.page_size, "offset": offset})
            rows = data.get("data", [])
            out.update(r["cve"] for r in rows if float(r["epss"]) >= threshold)
            offset += len(rows)
            if not rows or offset >= int(data.get("total", 0)):
                return out
