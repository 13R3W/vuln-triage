"""CISA KEV（悪用が確認された脆弱性カタログ）。"""

from __future__ import annotations

import json


def parse(raw: bytes) -> dict[str, str]:
    data = json.loads(raw)
    out = {}
    for v in data.get("vulnerabilities", []):
        cve, added = v.get("cveID"), v.get("dateAdded")
        if cve and added:
            out[cve.strip().upper()] = added[:10]
    return out


def fetch(fetcher, cfg: dict) -> dict[str, str]:
    """毎回全件を取得し、{CVE番号: KEV追加日} を返す。"""
    return parse(fetcher.get(cfg["url"]))
