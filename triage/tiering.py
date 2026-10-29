"""順位付けルール（ティア）。

ティアは「その時点までの KEV 追加日・PoC 初出日・その日の EPSS」だけから決まるので、
過去の任意の時点について再計算できる。
"""

from __future__ import annotations

TIERS = ("S", "A", "B", "C")
TIER_ORDER = {t: i for i, t in enumerate(TIERS)}


def tier_at(at: str, kev_date: str | None, poc_date: str | None, epss: float | None,
            thresholds: dict, poc_valid: bool | None = None) -> str:
    """at（YYYY-MM-DD）時点のティア。

    poc_valid：PoC を採用してよいか。省略時は「EPSS スコアがある」ことを条件にする
    （PoC-in-GitHub には存在しない CVE 番号のゴミ登録があるため）。
    """
    kev = bool(kev_date) and kev_date <= at
    if poc_valid is None:
        poc_valid = epss is not None
    poc = bool(poc_date) and poc_date <= at and poc_valid
    score = epss or 0.0
    if kev:
        return "S"
    if poc and score >= thresholds["a_epss"]:
        return "A"
    if poc or score >= thresholds["b_epss"]:
        return "B"
    return "C"


def sort_key(rec: dict):
    """ティア順 → ティア内は EPSS の高い順（EPSS なしは最後）→ CVE 番号。"""
    epss = rec.get("epss")
    return (TIER_ORDER[rec["tier"]], epss is None, -(epss or 0.0), rec["id"])
