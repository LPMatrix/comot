"""Anchoring the audit log's head outside the store.

A hash chain alone cannot stop someone with write access from rewriting the
whole chain from the first changed entry onward. Publishing the head hash
somewhere they cannot reach, now and then, closes that gap: a rewritten log no
longer matches what was published.

An anchor says "after log entry ``seq``, the chain head was ``head``".
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol, Sequence

from .hashing import GENESIS
from .log import LogEntry


@dataclass(frozen=True)
class Anchor:
    seq: int  # number of log entries covered, so 0 means an empty log
    head: str
    time: str
    sink: str  # where it was published, for example "file:anchors.jsonl"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Anchor":
        return cls(seq=int(d["seq"]), head=d["head"], time=d["time"], sink=d.get("sink", ""))


class AnchorSink(Protocol):
    """Somewhere outside the store that keeps anchors safe from the store's writers."""

    def publish(self, anchor: Anchor) -> str:
        """Publish the anchor and return a reference to where it went."""
        ...


class FileAnchorSink:
    """Appends anchors to a JSON Lines file.

    The file only helps if its writers differ from the store's writers: put it
    on another machine, a write-once volume, or somewhere public such as a
    repository the board can see. It is flushed to disk before publish returns.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def publish(self, anchor: Anchor) -> str:
        line = json.dumps(anchor.to_dict(), sort_keys=True) + "\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        return f"file:{self.path}"


def read_anchor_file(path: str | Path) -> list[Anchor]:
    anchors: list[Anchor] = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                anchors.append(Anchor.from_dict(json.loads(line)))
            except (ValueError, KeyError) as e:
                raise ValueError(f"{path}:{n}: not a valid anchor ({e})") from None
    return anchors


def verify_anchors(entries: Sequence[LogEntry], anchors: Iterable[Anchor]) -> list[str]:
    """Check a log against anchors published earlier. Empty means they all agree."""
    problems: list[str] = []
    for a in anchors:
        where = f"anchor at entry {a.seq} ({a.time})"
        if a.seq == 0:
            if a.head != GENESIS:
                problems.append(f"{where}: an empty log must have the genesis head")
        elif a.seq > len(entries):
            problems.append(f"{where}: log has only {len(entries)} entries, so it was truncated")
        elif entries[a.seq - 1].hash != a.head:
            problems.append(f"{where}: log was rewritten at or before this entry")
    return problems
