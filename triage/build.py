"""月次・週次のデータを組み立てる。

同じ関数で「今月（途中経過）」と「確定（期間終了後）」の両方を作る。確定のときは
基準日を期間の最終日にし、その日の EPSS を使うので、後から取り直しても同じ結果になる。
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


def build_month(src: Sources, period, today: date, now=None, final: bool = False) -> dict:
    cfg = src.cfg
    th = src.thresholds
    as_of = period.end.isoformat() if final else min(period.end, today).isoformat()
    epss_day = as_of if final else src.epss_latest
    prev_day = days_before(epss_day, 7) if epss_day else None

    # ---- メイン：今月公開された CVE ----
    recs = src.nvd_published(period, None if final else now)
    ids = [r["id"] for r in recs]
    now_scores = src.epss(ids, epss_day) if epss_day else {}
    prev_scores = src.epss(ids, prev_day) if prev_day else {}
    jvn_start = period.start - timedelta(days=int(cfg["jvn"].get("lookback_days", 60)))
    jvn = src.jvn(jvn_start, date.fromisoformat(as_of) if final else today)

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
    month_ids = set(ids)

    # ---- 再浮上：今月より前に公開され、今月 KEV 追加 or 今月 PoC 初出 ----
    kev_in = {c for c, d in src.kev.items() if period.contains(d) and d <= as_of}
    poc_in = {c for c, p in src.poc.items() if period.contains(p["date"]) and p["date"] <= as_of}
    others = (kev_in | poc_in) - month_ids
    other_scores = src.epss(others, epss_day) if epss_day and others else {}
    # PoC だけの候補は、EPSS スコアがあるもの（＝実在する CVE）だけ採用
    resurf_ids = [c for c in others if c in kev_in or c in other_scores]
    resurf_ids.sort(key=lambda c: (-(other_scores.get(c) or 0.0), c))
    resurf_ids = resurf_ids[: int(cfg["display"].get("resurfaced_max", 20))]

    # ---- PoC タブ：今月 PoC が初めて出た CVE（古い CVE も含む） ----
    poc_ids = [c for c in poc_in if c in month_ids or c in other_scores]
    poc_ids.sort(key=lambda c: (src.poc[c]["date"], src.poc[c]["repos"], c), reverse=True)

    details = src.details(resurf_ids + [c for c in poc_ids if c not in month_ids])
    main_by_id = {r["id"]: r for r in main}

    resurfaced = []
    for c in resurf_ids:
        ev = _event_fields(src, c, as_of)
        e = other_scores.get(c)
        events = []
        if c in kev_in:
            events.append({"type": "KEV追加", "date": ev["kev"]})
        if c in poc_in:
            events.append({"type": "PoC初出", "date": ev["poc"]})
        resurfaced.append({"id": c, **_details_fields(details.get(c)), **ev, "epss": e,
                           "tier": tier_at(as_of, ev["kev"], ev["poc"], e, th), "events": events})

    poc_list = []
    for c in poc_ids:
        base = main_by_id.get(c)
        rec = base or {"id": c, **_details_fields(details.get(c)), **_event_fields(src, c, as_of),
                       "epss": other_scores.get(c)}
        poc_list.append({"id": c, "poc": src.poc[c]["date"], "poc_repos": rec["poc_repos"],
                         "cwe": rec.get("cwe") or [], "published": rec.get("published"),
                         "epss": rec.get("epss"), "summary": rec.get("summary"),
                         "this_month": c in month_ids})

    counts = {t: 0 for t in TIERS}
    for r in main:
        counts[r["tier"]] += 1
    return {
        "kind": "monthly",
        "key": period.key,
        "label": period.label,
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
    }


def build_week(src: Sources, period) -> dict:
    """確定した週（月曜〜日曜）のまとめ。"""
    th = src.thresholds
    end = period.end.isoformat()
    ref = (period.start - timedelta(days=1)).isoformat()  # 週の始め時点＝前週日曜の終わり

    kev_in = sorted(c for c, d in src.kev.items() if period.contains(d))
    poc_cand = [c for c, p in src.poc.items() if period.contains(p["date"])]
    scores = src.epss(set(kev_in) | set(poc_cand), end)
    poc_in = sorted(c for c in poc_cand if c in scores)

    def s_set(day):
        return {c for c, d in src.kev.items() if d <= day}

    def a_set(day):
        return {c for c in src.epss_above(th["a_epss"], day)
                if c in src.poc and src.poc[c]["date"] <= day}

    s_end, a_end = s_set(end), a_set(end)
    if a_end and not src.epss_above(th["a_epss"], ref):
        # 前週末の一覧が空だと全件が「新たにA入り」になってしまうので、取得失敗として扱う
        src.fail("EPSS", ValueError(f"{ref} の EPSS 一覧を取得できない"))
    new_sa = sorted((s_end | a_end) - (s_set(ref) | a_set(ref)))
    scores.update(src.epss(set(new_sa) - set(scores), end))

    details = src.details(kev_in + poc_in + new_sa)

    def row(c, extra=None):
        ev = _event_fields(src, c, end)
        e = scores.get(c)
        return {"id": c, **_details_fields(details.get(c)), **ev, "epss": e,
                "tier": tier_at(end, ev["kev"], ev["poc"], e, th), **(extra or {})}

    rows_new = [row(c) for c in new_sa]
    rows_new.sort(key=sort_key)
    return {
        "kind": "weekly",
        "key": period.key,
        "label": period.label,
        "final": True,
        "as_of": end,
        "epss_date": end,
        "thresholds": {"a_epss": th["a_epss"], "b_epss": th["b_epss"]},
        "sources": dict(src.status),
        "new_cves": src.nvd_count(period),
        "kev_added": sorted((row(c) for c in kev_in), key=lambda r: (r["kev"], r["id"])),
        "poc_first": sorted((row(c) for c in poc_in), key=lambda r: (r["poc"], r["id"])),
        "new_sa": rows_new,
    }
