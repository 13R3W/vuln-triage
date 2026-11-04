"""全CVEのトリアージ索引（「自分の環境をチェック」用）。

見る人が渡したファイルの CVE を、今日・今週・今月に限らず昔のものも含めて優先度順に並べるため、
KEV に載っている・PoC がある・EPSS がある CVE 全件（約30万件）について、ティアの判定に必要な値だけを
CVE の年ごとのファイルにして Pages に置く。ティアの判定は見る人のブラウザで行う（tiering.py と同じ規則）。

  data/index/meta.json   作成日時・EPSS の日付・しきい値・年の一覧
  data/index/kev.json    {CVE番号: [KEV追加日, 対応期限, 求められる対応]}
  data/index/<年>.json   {CVE番号の年より後ろ: [EPSS, KEV追加日, PoC初出日, PoCリポジトリ数]}（後ろの空の値は省く）

取得に失敗した回は、前回作った索引（.cache/index）をそのまま使う。
EPSS 全件の取得は約3分かかるが、EPSS は1日1回しか更新されないので、日付ごとに保存して
（.cache/index-epss/<日付>.json）その日の2回目以降の実行では取り直さない。KEV・PoC は毎回最新を使う。
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from .collect import Sources


def epss_all(src: Sources, epss_cache: Path | None) -> dict[str, float] | None:
    """その日の EPSS 全件。同じ日付の保存分があればそれを使う。"""
    day = src.epss_latest
    path = Path(epss_cache) / f"{day}.json" if epss_cache else None
    if path and path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    try:
        scores = src.epss_client.all_scores(day)
    except Exception as e:  # noqa: BLE001
        src.fail("EPSS", e)
        return None
    if path and scores:
        if path.parent.exists():
            shutil.rmtree(path.parent)  # 古い日付の分は消す
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(scores, separators=(",", ":")), encoding="utf-8")
    return scores


def build(src: Sources, generated_at: str, epss_cache: Path | None = None) -> dict[str, dict] | None:
    """{ファイル名: 中身}。KEV・PoC・EPSS のどれかが取れていなければ None。"""
    if not (src.ok("KEV") and src.ok("PoC") and src.ok("EPSS") and src.epss_latest):
        return None
    scores = epss_all(src, epss_cache)
    if not scores:
        return None
    # PoC-in-GitHub のゴミ登録対策：PoC は EPSS スコアがある（＝実在する）CVE だけ採用（tiering.py と同じ）
    ids = set(scores) | set(src.kev)
    years: dict[str, dict[str, list]] = {}
    for cve in ids:
        parts = cve.split("-")
        if len(parts) != 3 or parts[0] != "CVE":
            continue
        poc = src.poc.get(cve) if cve in scores else None
        row = [round(scores[cve], 5) if cve in scores else None, src.kev.get(cve),
               poc["date"] if poc else None, poc["repos"] if poc else 0]
        while row and not row[-1]:
            row.pop()
        years.setdefault(parts[1], {})[parts[2]] = row
    th = src.thresholds
    files: dict[str, dict] = {f"{y}.json": years[y] for y in years}
    files["kev.json"] = src.kev_actions
    files["meta.json"] = {"generated_at": generated_at, "epss_date": src.epss_latest,
                          "thresholds": {"a_epss": th["a_epss"], "b_epss": th["b_epss"]},
                          "years": sorted(years), "count": sum(len(v) for v in years.values())}
    return files


def publish(files: dict[str, dict] | None, out_dir: Path, cache_dir: Path) -> bool:
    """索引を out_dir/data/index に書く。今回作れなかったときは前回分（cache_dir）を使う。書けたら True。"""
    dest = Path(out_dir) / "data" / "index"
    cache_dir = Path(cache_dir)
    if files:
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.mkdir(parents=True)
        for name, obj in files.items():
            (cache_dir / name).write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")),
                                          encoding="utf-8")
    elif not (cache_dir / "meta.json").exists():
        print("[warn] 全CVE索引：今回作れず、前回分も無いため置かない", file=sys.stderr)
        return False
    else:
        print("[info] 全CVE索引：今回作れなかったため前回分を使う", file=sys.stderr)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(cache_dir, dest)
    return True
