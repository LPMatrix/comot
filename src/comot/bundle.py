"""Verify an exported bundle or a store without trusting the service that made it.

Anyone can check the two hash chains and compare the log with anchors that were
published earlier. Checking the signature needs the key.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .anchor import Anchor, verify_anchors
from .consent import ConsentRecord
from .hashing import GENESIS, canonical, hash_obj
from .log import LogEntry, verify_entries
from .receipt import HmacSigner


def verify_consent_chain(records: Sequence[ConsentRecord]) -> list[str]:
    """Hashes match, the chain links, and versions count up for each consent."""
    problems: list[str] = []
    prev = GENESIS
    versions: dict[str, int] = {}
    for i, rec in enumerate(records, start=1):
        if rec.prev_hash != prev:
            problems.append(f"consent record {i}: prev_hash does not match the record before it")
        if rec.compute_hash() != rec.hash:
            problems.append(f"consent record {i}: contents do not match hash")
        if rec.version != versions.get(rec.consent_id, 0) + 1:
            problems.append(f"consent record {i}: version {rec.version} is out of order for {rec.consent_id}")
        versions[rec.consent_id] = rec.version
        prev = rec.hash
    return problems


def verify_consents_against_log(records: Sequence[ConsentRecord], entries: Sequence[LogEntry]) -> list[str]:
    """Every consent record has a log entry that vouches for it."""
    logged = {(e.object_id, e.payload_hash) for e in entries if e.event_type in ("consent_recorded", "consent_changed")}
    return [
        f"consent record {i}: no matching audit log entry"
        for i, rec in enumerate(records, start=1)
        if (rec.consent_id, hash_obj(rec.to_dict())) not in logged
    ]


def verify_state(
    records: Sequence[ConsentRecord], entries: Sequence[LogEntry], anchors: Iterable[Anchor] = ()
) -> list[str]:
    """All integrity checks that need no key."""
    return (
        verify_consent_chain(records)
        + verify_entries(entries)
        + verify_consents_against_log(records, entries)
        + verify_anchors(entries, anchors)
    )


def verify_bundle(
    bundle: Mapping[str, Any], key: bytes | None = None, anchors: Iterable[Anchor] | None = None
) -> list[str]:
    """Return problems found. An empty list means the bundle is intact.

    ``anchors`` should come from somewhere the bundle's maker cannot write, such
    as a published anchor file. Anchors carried inside the bundle are checked
    too, but whoever rewrote the log could have rewritten those as well.
    """
    records = [ConsentRecord.from_dict(raw) for raw in bundle["consents"]]
    entries = [LogEntry(**e) for e in bundle["log"]]
    carried = [Anchor.from_dict(a) for a in bundle.get("anchors", [])]
    problems = verify_state(records, entries, carried + list(anchors or []))
    if entries and bundle.get("log_head") != entries[-1].hash:
        problems.append("log_head does not match the last log entry")
    if key is not None:
        body = {k: v for k, v in bundle.items() if k != "signature"}
        if not HmacSigner(key).verify(canonical(body), bundle.get("signature", "")):
            problems.append("signature does not match the bundle contents")
    return problems


def load_bundle(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
