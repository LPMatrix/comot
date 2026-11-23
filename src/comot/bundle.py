"""Verify an exported bundle or a store without trusting the service that made it.

Anyone can check the two hash chains, compare the log with anchors that were
published earlier, and check that every artifact, edge, withdrawal, action,
receipt and refusal in the bundle is exactly what the audit log recorded. Checking
the signature needs a key: the shared secret for an HMAC signer, or just the
public key for an Ed25519 one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .anchor import Anchor, verify_anchors
from .consent import ConsentRecord
from .hashing import GENESIS, canonical, hash_obj
from .log import LogEntry, verify_entries
from .signing import Ed25519Verifier, HmacSigner, SigningError, Verifier, split_signature


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


# What completing each kind of action does to the copy it was about.
_STATUS_AFTER = {"delete": "deleted", "retire": "retired", "exclude": "retired", "retrain": "active"}


def objects_from(artifacts, edges, withdrawals, actions, receipts, refusals) -> dict[str, list[dict[str, Any]]]:
    """The plain-dict form of the stored objects that ``verify_objects`` checks."""
    return {
        "artifacts": [a.public_dict() for a in artifacts],
        "edges": [e.to_dict() for e in edges],
        "withdrawals": [w.to_dict() for w in withdrawals],
        "actions": [a.to_dict() for a in actions],
        "receipts": [r.to_dict() for r in receipts],
        "refusals": list(refusals),
    }


def verify_objects(
    entries: Sequence[LogEntry],
    *,
    artifacts: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    withdrawals: Sequence[Mapping[str, Any]],
    actions: Sequence[Mapping[str, Any]],
    receipts: Sequence[Mapping[str, Any]],
    refusals: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Every stored object is what the audit log recorded, and nothing is missing or extra.

    The log holds a hash of each object as it was written. Here each object's current
    form is hashed again and compared, an object's current status is rebuilt from the
    logged actions, and the objects and the logged events are matched one to one.
    """
    problems: list[str] = []
    last: dict[tuple[str, str], LogEntry] = {}  # (event type, object id) -> latest entry
    for e in entries:
        last[(e.event_type, e.object_id)] = e

    def of_type(*types: str) -> set[str]:
        return {oid for (t, oid) in last if t in types}

    def match(kind: str, objects, id_key: str, event: str, normalise=lambda o: o) -> None:
        ids = {o[id_key] for o in objects}
        for oid in sorted(of_type(event) - ids):
            problems.append(f"{kind} {oid}: the audit log records it but it is missing")
        for o in objects:
            entry = last.get((event, o[id_key]))
            if entry is None:
                problems.append(f"{kind} {o[id_key]}: not in the audit log")
            elif hash_obj(normalise(o)) != entry.payload_hash:
                problems.append(f"{kind} {o[id_key]}: does not match what the audit log recorded")

    # Artifacts, with the edges that point into them, as they were registered.
    into: dict[str, list[Mapping[str, Any]]] = {}
    for edge in edges:
        into.setdefault(edge["child_id"], []).append(edge)
    known = {a["artifact_id"] for a in artifacts}
    for edge in edges:
        if edge["child_id"] not in known or edge["parent_id"] not in known:
            problems.append(f"edge {edge['parent_id']} -> {edge['child_id']}: points at an unknown artifact")
    match(
        "artifact", artifacts, "artifact_id", "artifact_registered",
        lambda a: {"artifact": {**a, "status": "active"}, "edges": into.get(a["artifact_id"], [])},
    )

    # Actions: the latest logged state of each one.
    action_ids = {a["action_id"] for a in actions}
    for oid in sorted(of_type("action_created") - action_ids):
        problems.append(f"action {oid}: the audit log records it but it is missing")
    for a in actions:
        latest = [last.get((t, a["action_id"])) for t in ("action_created", "action_overdue", "action_completed")]
        entry = max((e for e in latest if e is not None), key=lambda e: e.seq, default=None)
        if entry is None:
            problems.append(f"action {a['action_id']}: not in the audit log")
        elif hash_obj(a) != entry.payload_hash:
            problems.append(f"action {a['action_id']}: does not match the last state the audit log recorded")

    # Each copy's status is what its logged actions imply.
    by_action = {a["action_id"]: a for a in actions}
    by_artifact = {a["artifact_id"]: a for a in artifacts}
    status = {aid: "active" for aid in by_artifact}
    for e in entries:
        act = by_action.get(e.object_id) if e.event_type in ("action_created", "action_completed") else None
        art = by_artifact.get(act["artifact_id"]) if act else None
        if art is None:
            continue
        if e.event_type == "action_created" and art["type"] == "model_version":
            status[art["artifact_id"]] = "tainted"
        elif e.event_type == "action_completed" and act["kind"] in _STATUS_AFTER:
            status[art["artifact_id"]] = _STATUS_AFTER[act["kind"]]
    for aid, art in by_artifact.items():
        if art["status"] != status[aid]:
            problems.append(f"artifact {aid}: status is {art['status']!r} but its logged actions give {status[aid]!r}")

    # Receipts, and which one each withdrawal points at.
    match("receipt", receipts, "receipt_id", "receipt_issued")
    latest_receipt: dict[str, str] = {}
    withdrawal_of = {r["receipt_id"]: r["withdrawal_id"] for r in receipts}
    for e in entries:
        if e.event_type == "receipt_issued" and e.object_id in withdrawal_of:
            latest_receipt[withdrawal_of[e.object_id]] = e.object_id
    # A withdrawal is logged before its receipt exists, so it is compared without one.
    match("withdrawal", withdrawals, "withdrawal_id", "withdrawal_received", lambda w: {**w, "receipt_id": None})
    for w in withdrawals:
        if w["receipt_id"] != latest_receipt.get(w["withdrawal_id"]):
            problems.append(f"withdrawal {w['withdrawal_id']}: points at the wrong receipt")

    match("refusal", refusals, "refusal_id", "registration_refused")
    return problems


def verify_state(
    records: Sequence[ConsentRecord],
    entries: Sequence[LogEntry],
    anchors: Iterable[Anchor] = (),
    objects: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> list[str]:
    """All integrity checks that need no key. ``objects`` adds the check of every stored object."""
    problems = (
        verify_consent_chain(records)
        + verify_entries(entries)
        + verify_consents_against_log(records, entries)
        + verify_anchors(entries, anchors)
    )
    if objects is not None:
        problems += verify_objects(entries, **objects)
    return problems


BUNDLE_FORMAT = "comot-bundle/1"


def _as_verifier(verifier: Any) -> Verifier:
    if isinstance(verifier, bytes):
        return HmacSigner(verifier)  # a shared HMAC key
    if isinstance(verifier, str):
        return Ed25519Verifier.from_text(verifier)  # a public key written ed25519:<hex>
    return verifier


def verify_bundle(
    bundle: Mapping[str, Any], verifier: Any = None, anchors: Iterable[Anchor] | None = None
) -> list[str]:
    """Return problems found. An empty list means the bundle is intact.

    ``verifier`` checks the signature: HMAC key bytes, a public key written
    ``ed25519:<hex>``, or any signer, verifier or key ring. ``anchors`` should
    come from somewhere the bundle's maker cannot write, such as a published
    anchor file. Anchors carried inside the bundle are checked too, but whoever
    rewrote the log could have rewritten those as well.
    """
    if bundle.get("format") != BUNDLE_FORMAT:
        return [f"unsupported bundle format {bundle.get('format')!r}; expected {BUNDLE_FORMAT!r}"]
    records = [ConsentRecord.from_dict(raw) for raw in bundle["consents"]]
    entries = [LogEntry(**e) for e in bundle["log"]]
    carried = [Anchor.from_dict(a) for a in bundle.get("anchors", [])]
    objects = {k: bundle[k] for k in ("artifacts", "edges", "withdrawals", "actions", "receipts", "refusals")}
    problems = verify_state(records, entries, carried + list(anchors or []), objects)
    if entries and bundle.get("log_head") != entries[-1].hash:
        problems.append("log_head does not match the last log entry")
    if verifier is not None:
        try:
            checker = _as_verifier(verifier)
        except SigningError as e:
            return problems + [f"cannot use the verification key: {e}"]
        body = {k: v for k, v in bundle.items() if k != "signature"}
        signature = bundle.get("signature", "")
        if not checker.verify(canonical(body), signature):
            parts = split_signature(signature)
            if parts is not None and parts[1] not in checker.key_ids:
                problems.append(f"signed with key {parts[1]}, which this verifier does not hold")
            else:
                problems.append("signature does not match the bundle contents")
        for r in bundle["receipts"]:  # each receipt carries its own signature too
            body = {k: v for k, v in r.items() if k != "signature"}
            if not checker.verify(canonical(body), r.get("signature", "")):
                problems.append(f"receipt {r['receipt_id']}: signature does not match")
    return problems


def load_bundle(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
