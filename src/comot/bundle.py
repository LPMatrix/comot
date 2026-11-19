"""Verify an exported bundle without trusting the service that made it.

Anyone can check the two hash chains. Checking the signature needs the key.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .consent import ConsentRecord
from .hashing import GENESIS, canonical, hash_obj
from .log import LogEntry, verify_entries
from .receipt import HmacSigner


def verify_bundle(bundle: Mapping[str, Any], key: bytes | None = None) -> list[str]:
    """Return problems found. An empty list means the bundle is intact."""
    problems: list[str] = []

    # 1. Consent records: hashes match, chain links, versions count up.
    prev = GENESIS
    versions: dict[str, int] = {}
    records: list[ConsentRecord] = []
    for i, raw in enumerate(bundle["consents"], start=1):
        rec = ConsentRecord.from_dict(raw)
        records.append(rec)
        if rec.prev_hash != prev:
            problems.append(f"consent record {i}: prev_hash does not match the record before it")
        if rec.compute_hash() != rec.hash:
            problems.append(f"consent record {i}: contents do not match hash")
        if rec.version != versions.get(rec.consent_id, 0) + 1:
            problems.append(f"consent record {i}: version {rec.version} is out of order for {rec.consent_id}")
        versions[rec.consent_id] = rec.version
        prev = rec.hash

    # 2. Audit log chain.
    entries = [LogEntry(**e) for e in bundle["log"]]
    problems += verify_entries(entries)
    if entries and bundle.get("log_head") != entries[-1].hash:
        problems.append("log_head does not match the last log entry")

    # 3. Every consent record has a log entry that vouches for it.
    logged = {(e.object_id, e.payload_hash) for e in entries if e.event_type in ("consent_recorded", "consent_changed")}
    for i, rec in enumerate(records, start=1):
        if (rec.consent_id, hash_obj(rec.to_dict())) not in logged:
            problems.append(f"consent record {i}: no matching audit log entry")

    # 4. Signature, when we have the key.
    if key is not None:
        body = {k: v for k, v in bundle.items() if k != "signature"}
        if not HmacSigner(key).verify(canonical(body), bundle.get("signature", "")):
            problems.append("signature does not match the bundle contents")
    return problems


def load_bundle(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
