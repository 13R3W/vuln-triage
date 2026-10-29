"""コマンドライン：python -m triage run [オプション]

  --sample        外部データ源に繋がず、同梱のサンプルデータで動かす（動作確認用）
  --now           現在時刻を指定する（例：2026-11-20T10:00+09:00）。確定処理の確認用
  --out           サイトの出力先（既定：_site）
  --archive       確定データの保存先（既定：archive。--sample のときは .cache/sample-archive）
  --no-finalize   週・月の確定をしない
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from . import archive, config, periods
from .build import build_month
from .collect import Sources
from .http import HttpFetcher
from .site import generate
from .sources import poc as poc_src

ROOT = Path(__file__).resolve().parent.parent


def parse_now(value: str | None) -> datetime:
    if not value:
        return periods.now_jst()
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=periods.JST)
    return dt.astimezone(periods.JST)


def make_sources(cfg: dict, args, now: datetime) -> Sources:
    if args.sample:
        from . import sample
        fetcher = sample.SampleFetcher(sample.universe(), now)
        tmp = Path(tempfile.mkdtemp(prefix="poc-sample-"))
        sample.write_poc_tree(sample.universe(), tmp, now)
        return Sources(cfg, fetcher, lambda: poc_src.scan(tmp), cache_dir=None)

    http = cfg["http"]
    fetcher = HttpFetcher(retries=int(http["retries"]), timeout=float(http["timeout"]), user_agent=http["user_agent"])
    cache = ROOT / ".cache"

    def load_poc():
        return poc_src.scan(poc_src.clone(cfg["poc"]["repo_url"], cache / "PoC-in-GitHub"))

    return Sources(cfg, fetcher, load_poc, api_key=os.environ.get("NVD_API_KEY") or None, cache_dir=cache / "nvd")


def run(args) -> int:
    cfg = config.load(args.config)
    now = parse_now(args.now)
    today = now.date()
    archive_dir = Path(args.archive or (ROOT / ".cache" / "sample-archive" if args.sample else ROOT / "archive"))
    stamp = now.strftime("%Y-%m-%d %H:%M")

    src = make_sources(cfg, args, now)
    src.load()  # 1. データ源の取得（KEV・PoC・EPSS の最新日）

    written = []
    if not args.no_finalize:  # 2. 未確定の週・月を確定
        written = archive.finalize(src, archive_dir, cfg["schedule"]["start_month"], today, stamp)

    live = build_month(src, periods.month_of(today), today, now=now)  # 3. 今月分
    generate(cfg, Path(args.out), live, archive.load_all(archive_dir), stamp, dict(src.status))

    print(f"今月（{live['key']}）：新規CVE {live['counts']['total']}件 {live['counts']['tiers']}")
    print(f"確定：{len(written)}件 {' '.join(Path(w).name for w in written)}")
    print("データ源：" + " / ".join(f"{k}={v}" for k, v in src.status.items()))
    if src.nvd.lookups_skipped:
        print(f"NVD 個別取得の上限により {src.nvd.lookups_skipped} 件の詳細を次回以降に回しました")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m triage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="データを取得し、確定処理とサイト生成を行う")
    r.add_argument("--config", default=None)
    r.add_argument("--out", default=str(ROOT / "_site"))
    r.add_argument("--archive", default=None)
    r.add_argument("--now", default=None)
    r.add_argument("--sample", action="store_true")
    r.add_argument("--no-finalize", action="store_true")
    args = ap.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
