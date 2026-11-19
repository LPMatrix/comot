"""Clocks. Injectable so deadlines and overdue logic are testable."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

Clock = Callable[[], datetime]


def system_clock() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class ManualClock:
    """A clock you move by hand. Used in tests and the demo."""

    def __init__(self, start: datetime | None = None):
        self._now = (start or datetime(2027, 6, 1, 9, 0, tzinfo=timezone.utc)).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, **kwargs: float) -> datetime:
        self._now += timedelta(**kwargs)
        return self._now


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)
