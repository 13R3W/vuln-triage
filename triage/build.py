"""日次・週次・月次のデータを組み立てる。

どの期間も同じ関数・同じ形式で作る。同じ関数で「今日・今週・今月（途中経過）」と
「確定（期間終了後）」の両方を作る。確定のときは基準日を期間の最終日にし、その日の EPSS を
使うので、後から取り直しても同じ結果になる。
"""

from __future__ import annotations

from datetime import date, timedelta

from .collect import Sources, days_before
from .tiering import TIERS, sort_key, tier_at


def _details_fields(rec: dict | None) -> dict:
    rec = rec or {}
    return {
        "published": rec.get("published"),
        "summary": rec.get("summary"),
        "cvss": rec.get("cvss"),
        "severity": rec.get("severity"),
        "cwe": rec.get("cwe") or [],
    }


def _event_fields(src: Sources, cve: str, as_of: str) -> dict:
    kev = src.kev.get(cve)
    poc = src.poc.get(cve)
    # 基準日より後に作られた PoC リポジトリは数えない（確定データを後から再計算しても同じになるように）
    repos = sum(1 for d in poc.get("dates", [poc["date"]] * poc["repos"]) if d <= as_of) if poc else 0
    return {
        "kev": kev if kev and kev <= as_of else None,
        "poc": poc["date"] if repos else None,
        "poc_repos": repos,
    }


def build_period(src: Sources, period, today: date, final: bool = False) -> dict:
    """period に公開された CVE のランキング・再浮上・PoC・動きをまとめる。"""
    cfg = src.cfg
    th = src.thresholds
    as_of = period.end.isoformat() if final else min(period.end, today).isoformat()
    epss_day = as_of if final else src.epss_latest
    prev_day = days_before(epss_day, 7) if epss_day else None

    # ---- ランキング：期間内（日本時間）に公開された CVE ----
    recs = src.published_in(period)
    ids = [r["id"] for r in recs]
    now_scores = src.epss(ids, epss_day) if epss_day else {}
    prev_scores = src.epss(ids, prev_day) if prev_day else {}
    jvn_start = period.start - timedelta(days=int(cfg["jvn"].get("lookback_days", 60)))
    jvn = src.jvn(jvn_start, date.fromisoformat(as_of))

    main = []
    for r in recs:
        ev = _event_fields(src, r["id"], as_of)
        e = now_scores.get(r["id"])
        p = prev_scores.get(r["id"])
        main.append({
            "id": r["id"], **_details_fields(r), **ev,
            "epss": e,
            "epss_delta": round(e - p, 5) if e is not None and p is not None else None,
            # NVD に載っている＝実在する CVE なので、EPSS 未算出でも PoC を採用する
            "tier": tier_at(as_of, ev["kev"], ev["poc"], e, th, poc_valid=True),
            "jvn": None if jvn is None else r["id"] in jvn,
        })
    main.sort(key=sort_key)
    period_ids = set(ids)
    start = period.start.isoformat()

    # ---- 再浮上：期間より前に公開され、期間内に KEV 追加 or PoC 初出 ----
    kev_in = {c for c, d in src.kev.items() if period.contains(d) and d <= as_of}
    poc_in = {c for c, p in src.poc.items() if period.contains(p["date"]) and p["date"] <= as_of}
    # 期間内に公開されていない＝期間より前に公開された CVE（期間より後の公開分は除く）
    others = {c for c in (kev_in | poc_in) - period_ids
              if not (c in src.records and (src.records[c]["published"] or "") > as_of)}
    other_scores = src.epss(others, epss_day) if epss_day and others else {}
    # PoC だけの候補は、EPSS スコアがあるもの（＝実在する CVE）だけ採用
    resurf_ids = [c for c in others if c in kev_in or c in other_scores]
    resurf_ids.sort(key=lambda c: (-(other_scores.get(c) or 0.0), c))
    resurf_ids = resurf_ids[: int(cfg["display"].get("resurfaced_max", 20))]

    # ---- PoC：期間内に PoC が初めて出た CVE（古い CVE も含む） ----
    poc_ids = [c for c in poc_in if c in period_ids or c in other_scores]
    poc_ids.sort(key=lambda c: (src.poc[c]["date"], src.poc[c]["repos"], c), reverse=True)

    # ---- 動き：期間内の KEV 追加と、新たに S/A に入った CVE ----
    ref = (period.start - timedelta(days=1)).isoformat()  # 期間の始め＝前日の終わり

    def sa_set(kev_cut, poc_cut, epss_date):
        s = {c for c, d in src.kev.items() if d <= kev_cut}
        if epss_date:
            s |= {c for c in src.epss_above(th["a_epss"], epss_date)
                  if c in src.poc and src.poc[c]["date"] <= poc_cut}
        return s

    sa_end = sa_set(as_of, as_of, epss_day)
    sa_ref = sa_set(ref, ref, ref if epss_day and ref <= epss_day else None)
    if epss_day and ref <= epss_day and src.epss_above(th["a_epss"], epss_day) \
            and not src.epss_above(th["a_epss"], ref):
        # 期間開始前の一覧が空だと全件が「新たにA入り」になってしまうので、取得失敗として扱う
        src.fail("EPSS", ValueError(f"{ref} の EPSS 一覧を取得できない"))
        sa_ref = sa_end
    new_sa = sorted(sa_end - sa_ref)
    move_ids = sorted(kev_in) + new_sa
    move_scores = dict(now_scores)
    move_scores.update(other_scores)
    missing = [c for c in move_ids if c not in move_scores]
    if missing and epss_day:
        move_scores.update(src.epss(missing, epss_day))

    details = src.details(resurf_ids + [c for c in move_ids + poc_ids if c not in period_ids])
    main_by_id = {r["id"]: r for r in main}

    def row(c, scores):
        if c in main_by_id:
            return dict(main_by_id[c])
        ev = _event_fields(src, c, as_of)
        e = scores.get(c)
        return {"id": c, **_details_fields(details.get(c)), **ev, "epss": e,
                "tier": tier_at(as_of, ev["kev"], ev["poc"], e, th)}

    resurfaced = []
    for c in resurf_ids:
        r = row(c, other_scores)
        r["events"] = ([{"type": "KEV追加", "date": r["kev"]}] if c in kev_in else []) + \
                      ([{"type": "PoC初出", "date": r["poc"]}] if c in poc_in else [])
        resurfaced.append(r)

    poc_list = []
    for c in poc_ids:
        r = row(c, other_scores)
        poc_list.append({"id": c, "poc": src.poc[c]["date"], "poc_repos": r["poc_repos"],
                         "cwe": r.get("cwe") or [], "published": r.get("published"), "tier": r["tier"],
                         "epss": r.get("epss"), "summary": r.get("summary"), "new": c in period_ids})

    kev_rows = sorted((row(c, move_scores) for c in kev_in), key=lambda r: (r["kev"], r["id"]))
    for r in kev_rows:
        r["new"] = r["id"] in period_ids
    sa_rows = sorted((row(c, move_scores) for c in new_sa), key=sort_key)
    for r in sa_rows:
        r["new"] = r["id"] in period_ids

    counts = {t: 0 for t in TIERS}
    for r in main:
        counts[r["tier"]] += 1
    return {
        "kind": period.kind,
        "key": period.key,
        "label": period.label,
        "start": start,
        "end": period.end.isoformat(),
        "final": final,
        "as_of": as_of,
        "epss_date": epss_day,
        "epss_prev_date": prev_day,
        "thresholds": {"a_epss": th["a_epss"], "b_epss": th["b_epss"]},
        "sources": dict(src.status),
        "counts": {"total": len(main), "tiers": counts,
                   "jvn_missing": None if jvn is None else sum(1 for r in main if r["jvn"] is False)},
        "main": main,
        "resurfaced": resurfaced,
        "poc": poc_list,
        "movement": {"kev_added": kev_rows, "new_sa": sa_rows},
    }
