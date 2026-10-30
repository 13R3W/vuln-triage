"""HTTP 取得（リトライ・送信間隔の制御つき）。

データ源ごとの呼び出し間隔は呼び出し側が `interval` で指定する。テストやサンプル実行では
同じインターフェース（get）を持つ別の取得器に差し替える。
"""

from __future__ import annotations

import http.client
import time
import urllib.error
import urllib.parse
import urllib.request


class FetchError(Exception):
    pass


def build_url(base: str, params: dict | None) -> str:
    if not params:
        return base
    parts = []
    for k, v in params.items():
        if v is None:
            continue
        if v is True:  # 値なしのフラグ（例：NVD の noRejected）
            parts.append(urllib.parse.quote(k))
        else:
            parts.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v), safe=',')}")
    return base + ("&" if "?" in base else "?") + "&".join(parts)


class HttpFetcher:
    def __init__(self, retries: int = 3, timeout: float = 60, user_agent: str = "vuln-triage",
                 sleep=time.sleep, clock=time.monotonic):
        self.retries = retries
        self.timeout = timeout
        self.user_agent = user_agent
        self._sleep = sleep
        self._clock = clock
        self._last: dict[str, float] = {}

    def _wait(self, key: str, interval: float) -> None:
        last = self._last.get(key)
        if last is not None:
            remain = interval - (self._clock() - last)
            if remain > 0:
                self._sleep(remain)
        self._last[key] = self._clock()

    def get(self, base: str, params: dict | None = None, headers: dict | None = None,
            interval: float = 0.0) -> bytes:
        url = build_url(base, params)
        host = urllib.parse.urlsplit(base).netloc
        hdrs = {"User-Agent": self.user_agent, **(headers or {})}
        error = None
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(min(2 ** attempt, 30))
            self._wait(host, interval)
            try:
                req = urllib.request.Request(url, headers=hdrs)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as e:
                error = f"HTTP {e.code}"
                if 400 <= e.code < 500 and e.code not in (403, 408, 429):
                    break
            except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as e:
                # HTTPException：受信の途中切断（IncompleteRead）や相手からの切断（RemoteDisconnected）など
                error = f"{type(e).__name__}: {e}"
        raise FetchError(f"{host}: {error}")
