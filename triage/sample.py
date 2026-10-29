"""サンプルデータと、各データ源の API を真似る取得器（外部に繋がらない環境での動作確認・テスト用）。

NVD・CISA KEV・FIRST EPSS・JVN の応答を、実際の API と同じ形式（ページング・日付指定を含む）で返す。
PoC-in-GitHub は、同じ形式のディレクトリ（年/CVE-ID.json）を一時フォルダに書き出して使う。
"""

from __future__ import annotations

import json
import random
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .http import FetchError
from .periods import JST

# 手で作った、確認したい性質を持つ CVE（テストで期待値を固定している）
HANDMADE = [
    # 11月公開。PoC 11/5、EPSS が 11/6 に上がり A 入り（第45週）、11/10 に KEV 追加で S
    {"id": "CVE-2026-41001", "published": "2026-11-03T02:00:00.000", "kev": "2026-11-10",
     "poc": ["2026-11-05T09:00:00Z", "2026-11-07T01:00:00Z"], "epss": [("2026-11-03", 0.05), ("2026-11-06", 0.6)],
     "cvss": [("cvssMetricV31", "Secondary", 9.8, "CRITICAL")], "cwe": ["CWE-78"], "jvn": "2026-11-06",
     "desc": "OS command injection in the management interface of Example Gateway allows unauthenticated remote code execution."},
    # 日本時間では 11/1 23:30 公開（UTC では 11/1 14:30）。PoC 11/12、EPSS 20% → A（第46週に新たにA入り）
    {"id": "CVE-2026-41002", "published": "2026-11-01T14:30:00.000",
     "poc": ["2026-11-12T03:00:00Z"], "epss": [("2026-11-02", 0.2)],
     "cvss": [("cvssMetricV31", "Primary", 8.8, "HIGH")], "cwe": ["CWE-502"], "jvn": "2026-11-05",
     "desc": "Deserialization of untrusted data in Example CMS plugin leads to remote code execution."},
    # UTC 10/31 16:00 ＝ 日本時間 11/1 01:00 → 11月公開に入る（月の境界）。EPSS 3% → B
    {"id": "CVE-2026-41003", "published": "2026-10-31T16:00:00.000", "epss": [("2026-11-01", 0.03), ("2026-11-17", 0.05)],
     "cvss": [("cvssMetricV31", "Secondary", 7.5, "HIGH")], "cwe": ["CWE-22"], "jvn": "2026-11-04",
     "desc": "Path traversal in Example File Server allows reading arbitrary files."},
    # UTC 10/31 14:00 ＝ 日本時間 10/31 23:00 → 10月公開。11/4 に KEV 追加 → 11月の「再浮上」
    {"id": "CVE-2026-41004", "published": "2026-10-31T14:00:00.000", "kev": "2026-11-04",
     "epss": [("2026-10-31", 0.08), ("2026-11-04", 0.45)],
     "cvss": [("cvssMetricV31", "Secondary", 9.1, "CRITICAL")], "cwe": ["CWE-287"],
     "desc": "Authentication bypass in Example VPN appliance."},
    # 11月公開、何も無い → C（JVN 掲載あり）
    {"id": "CVE-2026-41005", "published": "2026-11-15T00:00:00.000", "epss": [("2026-11-15", 0.002)],
     "cvss": [("cvssMetricV31", "Secondary", 5.3, "MEDIUM")], "cwe": ["CWE-79"], "jvn": "2026-11-16",
     "desc": "Stored cross-site scripting in Example Wiki."},
    # 11月公開、PoC はあるが EPSS 未算出 → NVD 掲載済みなので PoC を採用して B
    {"id": "CVE-2026-41006", "published": "2026-11-16T05:00:00.000", "poc": ["2026-11-17T00:00:00Z"],
     "epss": [], "cvss": [], "cwe": [],
     "desc": "Heap overflow in Example Image Library."},
    # 取り下げ（Rejected）→ 一覧に出ない
    {"id": "CVE-2026-41007", "published": "2026-11-10T00:00:00.000", "rejected": True, "epss": [],
     "cvss": [], "cwe": [], "desc": "** REJECT ** Duplicate."},
    # CNA が CVSS 4.0、NVD が 3.1 → CNA の 4.0 を採用。EPSS 1.2% → B、JVN 未掲載
    {"id": "CVE-2026-41008", "published": "2026-11-05T00:00:00.000", "epss": [("2026-11-05", 0.012)],
     "cvss": [("cvssMetricV40", "Secondary", 6.9, "MEDIUM"), ("cvssMetricV31", "Primary", 9.8, "CRITICAL")],
     "cwe": ["CWE-89"], "desc": "SQL injection in Example Shop search endpoint."},
    # 古くから KEV・PoC 既出（Log4Shell）→ 今月なにも起きていないのでどこにも入らない
    {"id": "CVE-2021-44228", "published": "2021-12-10T10:15:00.000", "kev": "2021-12-10",
     "poc": ["2021-12-10T02:00:00Z", "2021-12-11T00:00:00Z", "2021-12-12T00:00:00Z"],
     "epss": [("2021-12-10", 0.944)], "cvss": [("cvssMetricV31", "Primary", 10.0, "CRITICAL")],
     "cwe": ["CWE-502", "CWE-917"], "desc": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."},
    # 古い CVE に 11/11 初めて PoC → 再浮上・PoC タブ・第46週の新たにA入り
    {"id": "CVE-2024-50001", "published": "2024-03-01T00:00:00.000", "poc": ["2026-11-11T08:00:00Z"],
     "epss": [("2024-03-01", 0.15)], "cvss": [("cvssMetricV31", "Secondary", 8.1, "HIGH")], "cwe": ["CWE-416"],
     "desc": "Use after free in Example Browser engine."},
    # 古い CVE。PoC は以前からあり、11/10 に EPSS が 30% に上がる → 第46週に新たにA入り（再浮上には入らない）
    {"id": "CVE-2025-30001", "published": "2025-05-01T00:00:00.000", "poc": ["2025-06-01T00:00:00Z"],
     "epss": [("2025-05-01", 0.05), ("2026-11-10", 0.3)], "cvss": [("cvssMetricV31", "Secondary", 7.8, "HIGH")],
     "cwe": ["CWE-269"], "desc": "Privilege escalation in Example Endpoint Agent."},
]
# PoC-in-GitHub にだけある、存在しない CVE 番号（ゴミ登録）。EPSS が無いので採用されない
GARBAGE_POC = {"CVE-2026-999999": ["2026-11-12T00:00:00Z"]}

CWES = ["CWE-79", "CWE-89", "CWE-20", "CWE-787", "CWE-125", "CWE-22", "CWE-352", "CWE-416", "CWE-862", "CWE-434"]
PRODUCTS = ["Example Router", "Example Mail Server", "Example PDF Reader", "Example HR Suite", "Example IoT Camera",
            "Example Database", "Example Web Framework", "Example Backup Agent"]


def universe(seed: int = 7) -> list[dict]:
    """手作りの CVE に、画面確認用の CVE（2026年10〜12月公開）を足したもの。毎回同じ内容になる。"""
    rng = random.Random(seed)
    out = [dict(x) for x in HANDMADE]
    start = datetime(2026, 10, 1)
    for i in range(140):
        pub = start + timedelta(minutes=rng.randrange(0, 90 * 24 * 60))
        pub_d = pub.date()
        base = min(rng.lognormvariate(-5.5, 1.6), 0.97)
        epss = [(pub_d.isoformat(), round(base, 5))]
        if rng.random() < 0.3:
            later = pub_d + timedelta(days=rng.randrange(1, 20))
            epss.append((later.isoformat(), round(min(base * rng.uniform(1.5, 20), 0.97), 5)))
        poc = None
        if rng.random() < 0.15:
            poc = [(pub + timedelta(days=rng.randrange(0, 15), hours=rng.randrange(24))).strftime("%Y-%m-%dT%H:%M:%SZ")
                   for _ in range(rng.randrange(1, 5))]
        kev = (pub_d + timedelta(days=rng.randrange(0, 20))).isoformat() if rng.random() < 0.04 else None
        score = round(rng.uniform(3.0, 10.0), 1)
        sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        cwe = rng.choice(CWES)
        out.append({
            "id": f"CVE-2026-{50000 + i}", "published": pub.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "kev": kev, "poc": poc, "epss": epss,
            "cvss": [("cvssMetricV31", rng.choice(["Secondary", "Primary"]), score, sev)],
            "cwe": [cwe],
            "jvn": (pub_d + timedelta(days=rng.randrange(1, 10))).isoformat() if rng.random() < 0.5 else None,
            "desc": f"A {cwe} weakness in {rng.choice(PRODUCTS)} {rng.randrange(1, 9)}.{rng.randrange(10)} "
                    f"may allow an attacker to compromise the affected system (sample data).",
        })
    return out


def _utc(published: str) -> datetime:
    return datetime.fromisoformat(published).replace(tzinfo=timezone.utc)


def _epss_at(entry: dict, day: str) -> float | None:
    if _utc(entry["published"]).date().isoformat() > day:
        return None
    val = None
    for since, score in entry.get("epss") or []:
        if since <= day:
            val = score
    return val


def write_poc_tree(entries: list[dict], root: str | Path, now: datetime | None = None) -> Path:
    """PoC-in-GitHub と同じ形（年/CVE-ID.json、PoC リポジトリ情報の配列）で書き出す。"""
    root = Path(root)
    pocs = {e["id"]: e["poc"] for e in entries if e.get("poc")}
    pocs.update(GARBAGE_POC)
    for cve, created in pocs.items():
        items = []
        for n, c in enumerate(created):
            if now and datetime.fromisoformat(c.replace("Z", "+00:00")) > now:
                continue
            items.append({"id": 100000 + n, "name": f"{cve}-poc{n}", "full_name": f"someone{n}/{cve}-poc",
                          "html_url": f"https://github.com/someone{n}/{cve}-poc", "created_at": c,
                          "stargazers_count": n})
        if items:
            d = root / cve.split("-")[1]
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{cve}.json").write_text(json.dumps(items), encoding="utf-8")
    (root / "README.md").write_text("sample", encoding="utf-8")
    return root


JVN_OUTAGE = """<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><title>サービス停止中</title></head>
<body><h1>サービス停止中</h1><p>現在、JVN iPedia / MyJVN サービスをご利用いただけません。</p></body></html>"""


class SampleFetcher:
    """HttpFetcher と同じ get() を持ち、サンプルデータから各 API の応答を作る。

    fail：取得失敗させたいホスト名の集合（例：{"api.first.org"}）
    jvn_down：JVN を「サービス停止中」の HTML 応答にする
    """

    def __init__(self, entries: list[dict], now: datetime, fail=(), jvn_down: bool = False):
        self.now = now.astimezone(timezone.utc)
        self.entries = [e for e in entries if _utc(e["published"]) <= self.now]
        self.fail = set(fail)
        self.jvn_down = jvn_down
        self.epss_latest = self.now.date().isoformat()
        self.calls: list[tuple[str, dict]] = []

    def get(self, base: str, params: dict | None = None, headers: dict | None = None, interval: float = 0.0) -> bytes:
        params = dict(params or {})
        host = urlsplit(base).netloc
        self.calls.append((host, params))
        if host in self.fail:
            raise FetchError(f"{host}: サンプルで失敗させています")
        if host == "services.nvd.nist.gov":
            return self._nvd(params)
        if host == "www.cisa.gov":
            return self._kev()
        if host == "api.first.org":
            return self._epss(params)
        if host == "jvndb.jvn.jp":
            return JVN_OUTAGE.encode() if self.jvn_down else self._jvn(params)
        raise FetchError(f"{host}: 未知のホスト")

    # ---- NVD ----
    @staticmethod
    def _nvd_item(e: dict) -> dict:
        metrics: dict = {}
        for key, typ, score, sev in e.get("cvss") or []:
            ver = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0"}.get(key, "2.0")
            metrics.setdefault(key, []).append({
                "source": "cna@example.com" if typ == "Secondary" else "nvd@nist.gov", "type": typ,
                "cvssData": {"version": ver, "baseScore": score, "baseSeverity": sev}})
        weaknesses = [{"source": "cna@example.com", "type": "Secondary",
                       "description": [{"lang": "en", "value": c} for c in e.get("cwe") or []]}] if e.get("cwe") else []
        return {"cve": {"id": e["id"], "published": e["published"], "lastModified": e["published"],
                        "vulnStatus": "Rejected" if e.get("rejected") else "Awaiting Analysis",
                        "descriptions": [{"lang": "en", "value": e["desc"]}, {"lang": "es", "value": "(es)"}],
                        "metrics": metrics, "weaknesses": weaknesses}}

    def _nvd(self, p: dict) -> bytes:
        if "cveId" in p:
            hits = [e for e in self.entries if e["id"] == p["cveId"]]
            total = len(hits)
            page = hits
        else:
            start = datetime.fromisoformat(p["pubStartDate"])
            end = datetime.fromisoformat(p["pubEndDate"])
            if end - start > timedelta(days=120):
                raise FetchError("services.nvd.nist.gov: HTTP 404（期間が120日を超えています）")
            hits = [e for e in self.entries if start <= _utc(e["published"]) <= end
                    and not (p.get("noRejected") and e.get("rejected"))]
            hits.sort(key=lambda e: (e["published"], e["id"]))
            total = len(hits)
            i, n = int(p.get("startIndex", 0)), min(int(p.get("resultsPerPage", 2000)), 2000)
            page = hits[i:i + n]
        return json.dumps({"resultsPerPage": len(page), "startIndex": int(p.get("startIndex", 0)),
                           "totalResults": total, "format": "NVD_CVE", "version": "2.0",
                           "vulnerabilities": [self._nvd_item(e) for e in page]}).encode()

    # ---- KEV ----
    def _kev(self) -> bytes:
        today = self.now.date().isoformat()
        vulns = [{"cveID": e["id"], "dateAdded": e["kev"], "vendorProject": "Example"}
                 for e in self.entries if e.get("kev") and e["kev"] <= today]
        return json.dumps({"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": today,
                           "count": len(vulns), "vulnerabilities": vulns}).encode()

    # ---- EPSS ----
    def _epss(self, p: dict) -> bytes:
        day = p.get("date") or self.epss_latest
        rows = []
        if day <= self.epss_latest:
            if "cve" in p:
                wanted = set(p["cve"].split(","))
                if len(p["cve"]) > 2000:
                    raise FetchError("api.first.org: HTTP 414")
                cands = [e for e in self.entries if e["id"] in wanted]
            else:
                cands = self.entries
            for e in cands:
                s = _epss_at(e, day)
                if s is None:
                    continue
                if "epss-gt" in p and not s > float(p["epss-gt"]):
                    continue
                rows.append({"cve": e["id"], "epss": f"{s:.9f}", "percentile": "0.500000000", "date": day})
        rows.sort(key=lambda r: (-float(r["epss"]), r["cve"]))
        total = len(rows)
        off, lim = int(p.get("offset", 0)), int(p.get("limit", 100))
        return json.dumps({"status": "OK", "status-code": 200, "version": "1.0", "access": "public",
                           "total": total, "offset": off, "limit": lim, "data": rows[off:off + lim]}).encode()

    # ---- JVN ----
    def _jvn(self, p: dict) -> bytes:
        start = date(int(p["dateFirstPublishedStartY"]), int(p["dateFirstPublishedStartM"]),
                     int(p["dateFirstPublishedStartD"])).isoformat()
        end = date(int(p["dateFirstPublishedEndY"]), int(p["dateFirstPublishedEndM"]),
                   int(p["dateFirstPublishedEndD"])).isoformat()
        hits = sorted((e for e in self.entries if e.get("jvn") and start <= e["jvn"] <= end
                       and e["jvn"] <= self.now.date().isoformat()), key=lambda e: (e["jvn"], e["id"]))
        first, size = int(p.get("startItem", 1)), int(p.get("maxCountItem", 50))
        page = hits[first - 1:first - 1 + size]
        items = "".join(
            f'<item rdf:about="https://jvndb.jvn.jp/ja/contents/{e["jvn"][:4]}/JVNDB-{e["jvn"][:4]}-{n:06d}.html">'
            f'<title>サンプル製品における脆弱性</title><link>https://jvndb.jvn.jp/</link>'
            f'<sec:identifier>JVNDB-{e["jvn"][:4]}-{n:06d}</sec:identifier>'
            f'<sec:references source="NVD" id="{e["id"]}">https://nvd.nist.gov/vuln/detail/{e["id"]}</sec:references>'
            f'<dcterms:issued>{e["jvn"]}T10:00+09:00</dcterms:issued></item>'
            for n, e in enumerate(page, start=first))
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"'
            ' xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/" xmlns:dcterms="http://purl.org/dc/terms/"'
            ' xmlns:status="http://jvndb.jvn.jp/myjvn/Status">'
            '<channel rdf:about="https://jvndb.jvn.jp/apis/myjvn"><title>JVNDB</title></channel>'
            f'{items}'
            f'<status:Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="0" retMax="50" errCd=""'
            f' errMsg="" totalRes="{len(hits)}" totalResRet="{len(page)}" firstRes="{first}"/>'
            '</rdf:RDF>')
        return xml.encode()


def sample_now() -> datetime:
    return datetime(2026, 11, 20, 10, 0, tzinfo=JST)
