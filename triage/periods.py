"""日本時間（JST）の日・週（月曜〜日曜）・月の扱い。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

JST = timezone(timedelta(hours=9), "JST")
WEEKDAYS = "月火水木金土日"
KINDS = ("daily", "weekly", "monthly")
KIND_LABELS = {"daily": "日次", "weekly": "週次", "monthly": "月次"}


def now_jst() -> datetime:
    return datetime.now(JST)


def to_jst_date(value: str) -> str | None:
    """ISO 8601 の日時文字列を日本時間の日付（YYYY-MM-DD）にする。タイムゾーンなしは UTC とみなす。"""
    if not value:
        return None
    s = value.strip().replace("Z", "+00:00")
    if len(s) == 10:
        return s
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(JST).date().isoformat()


@dataclass(frozen=True)
class Period:
    kind: str  # "daily" | "weekly" | "monthly"
    key: str  # "2026-11-03" | "2026-W45" | "2026-11"
    start: date
    end: date  # 最終日（この日を含む）

    @property
    def label(self) -> str:
        if self.kind == "monthly":
            return f"{self.start.year}年{self.start.month}月"
        if self.kind == "daily":
            return f"{self.start.year}年{self.start.month}月{self.start.day}日（{WEEKDAYS[self.start.weekday()]}）"
        year, week = self.key.split("-W")
        return (f"{year}年第{int(week)}週（{self.start.month}/{self.start.day}〜"
                f"{self.end.month}/{self.end.day}）")

    def contains(self, d: str | None) -> bool:
        return bool(d) and self.start.isoformat() <= d <= self.end.isoformat()

    def nvd_range(self, now: datetime | None = None) -> tuple[str, str]:
        """NVD の pubStartDate / pubEndDate（日本時間で区切る）。"""
        start = f"{self.start.isoformat()}T00:00:00.000+09:00"
        end_dt = datetime.combine(self.end, datetime.max.time(), JST)
        if now is not None and now < end_dt:
            end_dt = now
        end = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000+09:00")
        return start, end


def day_of(d: date) -> Period:
    return Period("daily", d.isoformat(), d, d)


def month(year: int, mon: int) -> Period:
    start = date(year, mon, 1)
    nxt = date(year + (mon == 12), mon % 12 + 1, 1)
    return Period("monthly", f"{year:04d}-{mon:02d}", start, nxt - timedelta(days=1))


def month_of(d: date) -> Period:
    return month(d.year, d.month)


def parse_month(key: str) -> Period:
    y, m = key.split("-")
    return month(int(y), int(m))


def week_of(d: date) -> Period:
    start = d - timedelta(days=d.weekday())
    iso = start.isocalendar()
    return Period("weekly", f"{iso.year:04d}-W{iso.week:02d}", start, start + timedelta(days=6))


def first_week(start_month: str) -> Period:
    m = parse_month(start_month)
    d = m.start + timedelta(days=(7 - m.start.weekday()) % 7)
    return week_of(d)


def of(kind: str, d: date) -> Period:
    """d を含む、その種類の期間。"""
    return {"daily": day_of, "weekly": week_of, "monthly": month_of}[kind](d)


def closed_days(start_month: str, today: date) -> list[Period]:
    """開始月の1日から、昨日までの各日。"""
    out = []
    d = parse_month(start_month).start
    while d < today:
        out.append(day_of(d))
        d += timedelta(days=1)
    return out


def closed_months(start_month: str, today: date) -> list[Period]:
    """開始月から、今日より前に終わった月までの一覧。"""
    out = []
    p = parse_month(start_month)
    while p.end < today:
        out.append(p)
        p = month_of(p.end + timedelta(days=1))
    return out


def closed_weeks(start_month: str, today: date) -> list[Period]:
    """最初の週から、今日より前に終わった週までの一覧。"""
    out = []
    p = first_week(start_month)
    while p.end < today:
        out.append(p)
        p = week_of(p.end + timedelta(days=1))
    return out
