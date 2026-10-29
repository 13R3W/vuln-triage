"""設定ファイル（config.toml）の読み込み。"""

from __future__ import annotations

import tomllib
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config.toml"


def load(path: str | Path | None = None) -> dict:
    with open(path or DEFAULT_PATH, "rb") as f:
        return tomllib.load(f)
