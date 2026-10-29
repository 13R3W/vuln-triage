"""JVN iPedia（MyJVN API getVulnOverviewList, feed=hnd）。

XML の要素名・名前空間に依存しないよう、各ページの本文から CVE 番号を正規表現で取り出す。
件数は status 要素（ローカル名 Status）の totalRes 属性があれば使い、無ければ1ページ分に満たない時点で終える。
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import date

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_page(raw: bytes) -> tuple[set[str], int, int | None]:
    """(CVE番号の集合, そのページの項目数, 全件数 or None)"""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise ValueError(f"JVN: XML ではない応答（{e}）") from None
    total = None
    items = 0
    cves: set[str] = set()
    for el in root.iter():
        name = _local(el.tag)
        if name == "Status":
            attrs = {_local(k): v for k, v in el.attrib.items()}
            if attrs.get("retCd") not in (None, "0"):
                raise ValueError(f"JVN: エラー応答 {attrs.get('errCd')} {attrs.get('errMsg')}")
            if attrs.get("totalRes", "").isdigit():
                total = int(attrs["totalRes"])
        elif name == "item":
            items += 1
            for sub in el.iter():
                for text in [sub.text or "", *sub.attrib.values()]:
                    cves.update(m.upper() for m in CVE_RE.findall(text))
    return cves, items, total


def fetch(fetcher, cfg: dict, start: date, end: date) -> set[str]:
    """発行日（初回公開日）が start〜end の JVN iPedia 項目に含まれる CVE 番号。"""
    size = int(cfg.get("page_size", 50))
    interval = float(cfg.get("interval", 0.5))
    out: set[str] = set()
    start_item = 1
    while True:
        params = {
            "method": "getVulnOverviewList", "feed": "hnd", "lang": "ja",
            "rangeDatePublic": "n", "rangeDatePublished": "n", "rangeDateFirstPublished": "n",
            "dateFirstPublishedStartY": start.year, "dateFirstPublishedStartM": start.month,
            "dateFirstPublishedStartD": start.day,
            "dateFirstPublishedEndY": end.year, "dateFirstPublishedEndM": end.month,
            "dateFirstPublishedEndD": end.day,
            "startItem": start_item, "maxCountItem": size,
        }
        cves, items, total = parse_page(fetcher.get(cfg["base_url"], params, interval=interval))
        out |= cves
        start_item += items
        if items == 0 or (total is not None and start_item > total) or (total is None and items < size):
            return out
