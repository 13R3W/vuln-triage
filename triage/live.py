"""途中経過（今日・今週・今月）の前回成功分の保持。

途中経過はコミットしない（設計書 5.1）。代わりに、取得に成功した回のデータを
`.cache/live/<種類>/<期間>.json` に保存しておき（Actions のキャッシュで次回に持ち越す）、
取得に失敗した回は、同じ期間の前回成功分を表示する。
"""

from __future__ import annotations

import json
from pathlib import Path

from .archive import write_json


def _path(cache_dir: Path, kind: str, key: str) -> Path:
    return Path(cache_dir) / kind / f"{key}.json"


def load(cache_dir: Path, kind: str, key: str) -> dict | None:
    p = _path(cache_dir, kind, key)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def apply(live: dict[str, dict], ok: bool, stamp: str, status: dict[str, str], cache_dir: Path) -> dict[str, dict]:
    """ok（必須データ源がすべて取得成功）なら保存し、失敗なら同じ期間の前回成功分に差し替える。"""
    out = {}
    for kind, data in live.items():
        data["fetched_at"] = stamp
        if ok:
            d = Path(cache_dir) / kind
            if d.is_dir():
                for old in d.glob("*.json"):  # 今の期間以外の保存分は不要
                    if old.stem != data["key"]:
                        old.unlink()
            write_json(_path(cache_dir, kind, data["key"]), data)
            out[kind] = data
            continue
        prev = load(cache_dir, kind, data["key"])
        if prev is None:  # 同じ期間の成功分が無い（日・週・月が変わって最初の実行など）
            out[kind] = data
            continue
        prev["fallback"] = {"failed_at": stamp, "status": dict(status)}
        out[kind] = prev
    return out
