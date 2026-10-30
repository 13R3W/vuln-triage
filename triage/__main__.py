"""コマンドライン：python -m triage run [オプション]

  --sample        外部データ源に繋がず、同梱のサンプルデータで動かす（動作確認用）
  --now           現在時刻を指定する（例：2026-11-20T10:00+09:00）。確定処理の確認用
  --out           サイトの出力先（既定：_site）
  --archive       確定データの保存先（既定：archive。--sample のときは .cache/sample-archive）
  --no-finalize   日・週・月の確定をしない
  --live-cache    途中経過の前回成功分の保存先（既定：.cache/live。--sample のときは .cache/sample-live）
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from . import archive, config, live as live_cache, periods
from .build import build_period
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
        fetcher = sample.SampleFetcher(sample.universe(), now, fail=set(args.sample_fail or []))
        tmp = Path(tempfile.mkdtemp(prefix="poc-sample-"))
        sample.write_poc_tree(sample.universe(), tmp, now)
        return Sources(cfg, fetcher, lambda: poc_src.scan(tmp), cache_dir=None, now=now)

    http = cfg["http"]
    fetcher = HttpFetcher(retries=int(http["retries"]), timeout=float(http["timeout"]), user_agent=http["user_agent"])
    cache = ROOT / ".cache"

    def load_poc():
        return poc_src.scan(poc_src.clone(cfg["poc"]["repo_url"], cache / "PoC-in-GitHub"))

    return Sources(cfg, fetcher, load_poc, api_key=os.environ.get("NVD_API_KEY") or None, cache_dir=cache / "nvd",
                   now=now)


def run(args) -> int:
    cfg = config.load(args.config)
    now = parse_now(args.now)
    today = now.date()
    archive_dir = Path(args.archive or (ROOT / ".cache" / "sample-archive" if args.sample else ROOT / "archive"))
    stamp = now.strftime("%Y-%m-%d %H:%M")

    src = make_sources(cfg, args, now)
    src.load()  # 1. データ源の取得（KEV・PoC・EPSS の最新日）

    written = []
    if not args.no_finalize:  # 2. 未確定の日・週・月を確定
        written = archive.finalize(src, archive_dir, cfg["schedule"]["start_month"], today, stamp)

    # 3. 今日・今週・今月（途中経過）を計算してページ生成
    live = {k: build_period(src, periods.of(k, today), today) for k in periods.KINDS}
    # 取得に失敗した回は、同じ日・週・月の前回成功分を表示する
    live_dir = Path(args.live_cache or (ROOT / ".cache" / ("sample-live" if args.sample else "live")))
    live = live_cache.apply(live, src.required_ok(), stamp, dict(src.status), live_dir)
    generate(cfg, Path(args.out), live, archive.load_all(archive_dir))

    for k, d in live.items():
        note = f"（取得失敗のため {d['fetched_at']} 取得分を表示）" if d.get("fallback") else ""
        print(f"{d['label']}（途中経過）：新規CVE {d['counts']['total']}件 {d['counts']['tiers']}{note}")
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
    r.add_argument("--live-cache", default=None)
    # 動作確認用：--sample のとき、指定したホストへの取得を失敗させる（例：services.nvd.nist.gov）
    r.add_argument("--sample-fail", action="append", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
