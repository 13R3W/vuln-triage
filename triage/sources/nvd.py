"""NVD API 2.0：CVE の一覧・公開日・概要・CVSS・CWE。"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..periods import to_jst_date

# 同じ種類（CNA／NVD）の中では新しい版を優先する
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def pick_cvss(metrics: dict) -> dict | None:
    """CNA の値（type: Secondary）を優先し、なければ NVD の値（Primary）。"""
    for wanted in ("Secondary", "Primary"):
        for key in CVSS_KEYS:
            for m in metrics.get(key) or []:
                if m.get("type") != wanted:
                    continue
                data = m.get("cvssData") or {}
                score = data.get("baseScore")
                if score is None:
                    continue
                severity = data.get("baseSeverity") or m.get("baseSeverity")
                return {"score": score, "severity": severity, "version": data.get("version"),
                        "source": "CNA" if wanted == "Secondary" else "NVD"}
    return None


def pick_cwe(weaknesses: list) -> list[str]:
    out: list[str] = []
    for wanted in ("Secondary", "Primary"):
        for w in weaknesses or []:
            if w.get("type") != wanted:
                continue
            for d in w.get("description") or []:
                v = d.get("value", "")
                if v.startswith("CWE-") and v not in out:
                    out.append(v)
        if out:
            break
    return out


def parse_cve(item: dict, summary_chars: int = 200) -> dict:
    cve = item.get("cve", item)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    desc = " ".join(desc.split())
    if len(desc) > summary_chars:
        desc = desc[:summary_chars].rstrip() + "…"
    cvss = pick_cvss(cve.get("metrics") or {})
    return {
        "id": cve["id"],
        "published": to_jst_date(cve.get("published", "")),
        "summary": desc,
        "cvss": cvss["score"] if cvss else None,
        "severity": cvss["severity"] if cvss else None,
        "cvss_version": cvss["version"] if cvss else None,
        "cvss_source": cvss["source"] if cvss else None,
        "cwe": pick_cwe(cve.get("weaknesses") or []),
    }


class NvdClient:
    def __init__(self, fetcher, cfg: dict, api_key: str | None = None, cache_dir: str | Path | None = None,
                 summary_chars: int = 200):
        self.fetcher = fetcher
        self.base = cfg["base_url"]
        self.page_size = int(cfg.get("page_size", 2000))
        self.interval = float(cfg["interval_with_key"] if api_key else cfg["interval_no_key"])
        self.headers = {"apiKey": api_key} if api_key else {}
        self.lookup_limit = int(cfg.get("lookup_limit_with_key", 1000) if api_key else cfg.get("lookup_limit", 150))
        self.cache_days = float(cfg.get("cache_days", 14))
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.summary_chars = summary_chars
        self.lookups_done = 0
        self.lookups_skipped = 0

    def _get(self, params: dict) -> dict:
        raw = self.fetcher.get(self.base, params, headers=self.headers, interval=self.interval)
        return json.loads(raw)

    def published(self, start: str, end: str) -> list[dict]:
        """pubStartDate〜pubEndDate（最大120日）に公開された CVE（取り下げ分を除く）。"""
        out, index = [], 0
        while True:
            data = self._get({"pubStartDate": start, "pubEndDate": end, "resultsPerPage": self.page_size,
                              "startIndex": index, "noRejected": True})
            items = data.get("vulnerabilities") or []
            out.extend(parse_cve(v, self.summary_chars) for v in items)
            index += len(items)
            if not items or index >= int(data.get("totalResults", 0)):
                return out

    def count(self, start: str, end: str) -> int:
        data = self._get({"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 1,
                          "startIndex": 0, "noRejected": True})
        return int(data.get("totalResults", 0))

    # ---- 個別取得（キャッシュつき） ----
    def _cache_path(self, cve_id: str) -> Path | None:
        return self.cache_dir / f"{cve_id}.json" if self.cache_dir else None

    def _cached(self, cve_id: str) -> dict | None:
        p = self._cache_path(cve_id)
        if not p or not p.exists():
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - obj.get("fetched_at", 0) > self.cache_days * 86400:
            return None
        return obj.get("record")

    def lookup(self, ids) -> dict[str, dict]:
        """CVE 番号ごとに詳細を取得する。1回の実行での取得件数には上限がある。"""
        out: dict[str, dict] = {}
        for cve_id in ids:
            if cve_id in out:
                continue
            rec = self._cached(cve_id)
            if rec is None:
                if self.lookups_done >= self.lookup_limit:
                    self.lookups_skipped += 1
                    continue
                self.lookups_done += 1
                data = self._get({"cveId": cve_id})
                items = data.get("vulnerabilities") or []
                if not items:
                    continue
                rec = parse_cve(items[0], self.summary_chars)
                p = self._cache_path(cve_id)
                if p:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"fetched_at": time.time(), "record": rec}, ensure_ascii=False),
                                 encoding="utf-8")
            out[cve_id] = rec
        return out
