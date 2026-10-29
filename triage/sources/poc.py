"""nomi-sec/PoC-in-GitHub のメタデータ（PoC 初出日・リポジトリ数）。

PoC 本体はダウンロード・実行しない。リポジトリの `年/CVE-ID.json`（PoC リポジトリの情報の配列）だけを読む。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from ..periods import to_jst_date

CVE_FILE = re.compile(r"^(CVE-\d{4}-\d{4,})\.json$", re.IGNORECASE)


def clone(repo_url: str, dest: str | Path) -> Path:
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--depth", "1", "--quiet", repo_url, str(dest)], check=True, timeout=600)
    return dest


def scan(root: str | Path) -> dict[str, dict]:
    """{CVE番号: {"date": 初出日(JST), "repos": リポジトリ数, "dates": 各リポジトリの作成日(JST, 昇順)}}"""
    out: dict[str, dict] = {}
    for year_dir in Path(root).iterdir():
        if not (year_dir.is_dir() and year_dir.name.isdigit()):
            continue
        for f in year_dir.iterdir():
            m = CVE_FILE.match(f.name)
            if not m:
                continue
            try:
                entries = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(entries, list) or not entries:
                continue
            dates = [d for d in (to_jst_date(e.get("created_at", "")) for e in entries if isinstance(e, dict)) if d]
            if dates:
                dates.sort()
                out[m.group(1).upper()] = {"date": dates[0], "repos": len(dates), "dates": dates}
    return out
