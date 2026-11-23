"""Hash-chained, append-only audit log.

The log holds pseudonymous ids and a hash of each event's payload. It never
holds names, phone numbers or recording content; the payload itself
lives in the object it describes.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .hashing import GENESIS, hash_obj

EVENT_TYPES: frozenset[str] = frozenset(
    {
        "participant_created",
        "consent_recorded",
        "consent_changed",
        "artifact_registered",
        "registration_refused",
        "training_check",
        "withdrawal_received",
        "action_created",
        "action_completed",
        "action_overdue",
        "receipt_issued",
        "anchor_published",
        "identity_stored",
        "identity_read",
        "identity_deleted",
        "access_denied",
        "access_policy_set",
        "signing_key_rotated",
        "vault_key_rotated",
    }
)


@dataclass(frozen=True)
class LogEntry:
    seq: int
    time: str
    actor_id: str
    event_type: str
    object_id: str
    payload_hash: str
    prev_hash: str
    hash: str

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("hash")
        return d

    def compute_hash(self) -> str:
        return hash_obj(self.body())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[LogEntry] = []

    @property
    def head(self) -> str:
        return self.entries[-1].hash if self.entries else GENESIS

    def append(self, *, time: str, actor_id: str, event_type: str, object_id: str, payload: Any) -> LogEntry:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type {event_type!r}")
        partial = LogEntry(
            seq=len(self.entries) + 1,
            time=time,
            actor_id=actor_id,
            event_type=event_type,
            object_id=object_id,
            payload_hash=hash_obj(payload),
            prev_hash=self.head,
            hash="",
        )
        entry = LogEntry(**{**partial.body(), "hash": partial.compute_hash()})
        self.entries.append(entry)
        return entry

    def of_type(self, event_type: str) -> list[LogEntry]:
        return [e for e in self.entries if e.event_type == event_type]


def verify_entries(entries: Iterable[LogEntry]) -> list[str]:
    """Return a list of problems found in a log. Empty means the chain is intact."""
    problems: list[str] = []
    prev = GENESIS
    for i, e in enumerate(entries, start=1):
        if e.seq != i:
            problems.append(f"log entry {i}: seq is {e.seq}")
        if e.prev_hash != prev:
            problems.append(f"log entry {i}: prev_hash does not match the entry before it")
        if e.compute_hash() != e.hash:
            problems.append(f"log entry {i}: contents do not match hash")
        prev = e.hash
    return problems
