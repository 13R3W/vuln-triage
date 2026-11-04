"""CISA KEV（悪用が確認された脆弱性カタログ）。"""

from __future__ import annotations

import json


def parse(raw: bytes) -> dict[str, str]:
    """{CVE番号: KEV追加日}"""
    data = json.loads(raw)
    out = {}
    for v in data.get("vulnerabilities", []):
        cve, added = v.get("cveID"), v.get("dateAdded")
        if cve and added:
            out[cve.strip().upper()] = added[:10]
    return out


def parse_actions(raw: bytes) -> dict[str, list[str]]:
    """{CVE番号: [KEV追加日, 対応期限, 求められる対応]}（「自分の環境をチェック」で対策として表示する）"""
    data = json.loads(raw)
    out = {}
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if cve and v.get("dateAdded"):
            out[cve] = [v["dateAdded"][:10], (v.get("dueDate") or "")[:10], " ".join((v.get("requiredAction") or "").split())]
    return out

