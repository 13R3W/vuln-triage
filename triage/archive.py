"""確定した日・週・月をアーカイブファイルに書き出す。

- 期間が終わった後の最初の実行で作る。実行が飛んだ日があっても、無いファイルはすべて作る
- 既にあるファイルは書き換えない
- 開始月より前の日・週・月は作らない
- 必須のデータ源（NVD・KEV・EPSS・PoC）のどれかが取得失敗した回は確定しない
- その期間の最終日の EPSS がまだ公開されていなければ確定しない（次回に回す）
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

from . import periods
from .build import build_period
from .collect import Sources


def path_for(archive_dir: Path, period) -> Path:
    return Path(archive_dir) / period.kind / f"{period.key}.json"


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def pending(archive_dir: Path, start_month: str, today: date) -> list:
    closed = (periods.closed_days(start_month, today) + periods.closed_weeks(start_month, today)
              + periods.closed_months(start_month, today))
    return [p for p in closed if not path_for(archive_dir, p).exists()]


def finalize(src: Sources, archive_dir: Path, start_month: str, today: date, finalized_at: str) -> list[str]:
    """未確定の日・週・月を確定し、新しく書いたファイル名の一覧を返す。"""
    written = []
    for p in pending(archive_dir, start_month, today):
        if not src.required_ok():
            print(f"[info] {p.key}: 必須データ源の取得失敗のため確定を見送り", file=sys.stderr)
            break
        if not src.epss_latest or src.epss_latest < p.end.isoformat():
            print(f"[info] {p.key}: {p.end} の EPSS が未公開のため確定を見送り", file=sys.stderr)
            continue
        data = build_period(src, p, today, final=True)
        if not src.required_ok():
            print(f"[info] {p.key}: 取得途中で失敗したため確定を見送り", file=sys.stderr)
            break
        data["finalized_at"] = finalized_at
        path = path_for(archive_dir, p)
        write_json(path, data)
        written.append(str(path))
        print(f"[info] 確定: {path}", file=sys.stderr)
    return written


def load_all(archive_dir: Path) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {k: [] for k in periods.KINDS}
    for kind in out:
        d = Path(archive_dir) / kind
        if d.is_dir():
            for f in sorted(d.glob("*.json")):
                out[kind].append(json.loads(f.read_text(encoding="utf-8")))
    return out
