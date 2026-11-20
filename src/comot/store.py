"""Storage behind Comot.

``NullStore`` keeps nothing, so ``Comot()`` stays a pure in-memory object for
tests and notebooks. ``SqliteStore`` keeps everything in one SQLite file.

Rules the SQLite store enforces itself, so they hold even if the Python layer
has a bug:

* every public Comot operation is one transaction, committed or rolled back whole;
* consent versions, log entries, lineage edges, receipts, refusals, anchors and
  participants are append-only: triggers abort any UPDATE or DELETE.

Triggers stop mistakes and casual edits. They do not stop someone with write
access to the file from dropping them, which is what the hash chains and the
published anchors are for.

One writer at a time is safe. A second process may read and write too: each
operation takes SQLite's write lock first and reloads if another process got
there before it.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .anchor import Anchor
from .consent import ConsentRecord
from .lineage import Artifact, LineageEdge
from .log import LogEntry
from .receipt import Receipt
from .withdrawal import Action, Withdrawal

SCHEMA_VERSION = 2


class StoreError(Exception):
    """The store cannot be opened or is unusable."""


@dataclass
class StoreState:
    """Everything a store holds, in creation order."""

    participants: list[tuple[str, str]] = field(default_factory=list)  # (participant_id, code)
    consents: list[ConsentRecord] = field(default_factory=list)
    log: list[LogEntry] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    edges: list[LineageEdge] = field(default_factory=list)
    withdrawals: list[Withdrawal] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    receipts: list[Receipt] = field(default_factory=list)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    anchors: list[Anchor] = field(default_factory=list)


class NullStore:
    """Keeps nothing. The default, so Comot works in memory with no setup."""

    persistent = False

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def load(self) -> StoreState:
        return StoreState()

    def log_length(self) -> int:
        return 0

    def get_meta(self, key: str) -> str | None:
        return None

    def set_meta(self, key: str, value: str) -> None:
        pass

    def add_participant(self, participant_id: str, code: str) -> None: ...
    def add_consent(self, record: ConsentRecord) -> None: ...
    def add_log(self, entry: LogEntry) -> None: ...
    def upsert_artifact(self, artifact: Artifact) -> None: ...
    def add_edge(self, edge: LineageEdge) -> None: ...
    def upsert_withdrawal(self, withdrawal: Withdrawal) -> None: ...
    def upsert_action(self, action: Action) -> None: ...
    def add_receipt(self, receipt: Receipt) -> None: ...
    def add_refusal(self, refusal: dict[str, Any]) -> None: ...
    def add_anchor(self, anchor: Anchor) -> None: ...
    def close(self) -> None: ...


_APPEND_ONLY = ("participants", "consents", "log_entries", "edges", "receipts", "refusals", "anchors")

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE participants (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    participant_id TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL UNIQUE
);

CREATE TABLE consents (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    consent_id TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    script_version TEXT NOT NULL,
    language TEXT NOT NULL,
    choices TEXT NOT NULL,
    capture_method TEXT NOT NULL,
    chw_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    teach_back_score TEXT,
    is_minor INTEGER NOT NULL,
    guardian_consent INTEGER,
    assent INTEGER,
    guardian_verification TEXT,
    transfer_risk_explained INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    UNIQUE (consent_id, version)
);

CREATE TABLE log_entries (
    seq INTEGER PRIMARY KEY,
    time TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE
);

CREATE TABLE artifacts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    content_hash TEXT,
    storage_uri TEXT,
    holder TEXT NOT NULL,
    sharded INTEGER NOT NULL,
    participant_id TEXT,
    project_id TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    destination_country TEXT,
    transfer_basis TEXT
);
CREATE INDEX artifacts_content_hash ON artifacts (content_hash);
CREATE INDEX artifacts_owner ON artifacts (participant_id, project_id);

CREATE TABLE edges (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id TEXT NOT NULL,
    child_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX edges_parent ON edges (parent_id);
CREATE INDEX edges_child ON edges (child_id);

CREATE TABLE withdrawals (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    withdrawal_id TEXT NOT NULL UNIQUE,
    participant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    channel TEXT NOT NULL,
    received_at TEXT NOT NULL,
    consent_id TEXT NOT NULL,
    already_gone TEXT NOT NULL,
    receipt_id TEXT
);

CREATE TABLE actions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL UNIQUE,
    withdrawal_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    due_at TEXT NOT NULL,
    done_at TEXT,
    done_by TEXT,
    evidence TEXT,
    escalated INTEGER NOT NULL
);
CREATE INDEX actions_withdrawal ON actions (withdrawal_id);
CREATE INDEX actions_open ON actions (done_at);

CREATE TABLE receipts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    withdrawal_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    scope TEXT NOT NULL,
    items TEXT NOT NULL,
    limits TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE refusals (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    refusal_id TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL
);

CREATE TABLE anchors (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    log_seq INTEGER NOT NULL,
    head TEXT NOT NULL,
    time TEXT NOT NULL,
    sink TEXT NOT NULL
);
"""


def _bool(v: Any) -> bool | None:
    return None if v is None else bool(v)


def _int(v: bool | None) -> int | None:
    return None if v is None else int(v)


class SqliteStore:
    persistent = True

    def __init__(self, path: str | Path):
        self.path = Path(path)
        new = not self.path.exists()
        self._db = sqlite3.connect(self.path, isolation_level=None)  # we manage transactions
        self._db.row_factory = sqlite3.Row
        if new:
            try:
                os.chmod(self.path, 0o600)  # holds sensitive records
            except OSError:
                pass
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._depth = 0
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            self._create()
        elif version != SCHEMA_VERSION:
            self._db.close()
            raise StoreError(f"{self.path} has schema version {version}; this Comot expects {SCHEMA_VERSION}")

    def _create(self) -> None:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA.split(";\n"):
                if statement.strip():
                    self._db.execute(statement)
            for table in _APPEND_ONLY:
                for verb in ("UPDATE", "DELETE"):
                    self._db.execute(
                        f"CREATE TRIGGER {table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                        f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
                    )
            self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def close(self) -> None:
        self._db.close()

    # ------------------------------------------------------------ transactions

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One atomic unit. Nested uses join the outermost one."""
        if self._depth == 0:
            self._db.execute("BEGIN IMMEDIATE")  # take the write lock before reading anything
        self._depth += 1
        try:
            yield
        except BaseException:
            self._depth -= 1
            if self._depth == 0 and self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise
        else:
            self._depth -= 1
            if self._depth == 0:
                self._db.execute("COMMIT")

    # -------------------------------------------------------------------- meta

    def get_meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # ------------------------------------------------------------------ writes

    def add_participant(self, participant_id: str, code: str) -> None:
        self._db.execute("INSERT INTO participants (participant_id, code) VALUES (?, ?)", (participant_id, code))

    def add_consent(self, r: ConsentRecord) -> None:
        self._db.execute(
            "INSERT INTO consents (consent_id, participant_id, project_id, version, script_version, language,"
            " choices, capture_method, chw_id, device_id, teach_back_score, is_minor, guardian_consent, assent,"
            " guardian_verification, transfer_risk_explained, created_at, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                r.consent_id, r.participant_id, r.project_id, r.version, r.script_version, r.language,
                json.dumps(r.choices, sort_keys=True), r.capture_method, r.chw_id, r.device_id,
                r.teach_back_score, int(r.is_minor), _int(r.guardian_consent), _int(r.assent),
                r.guardian_verification, int(r.transfer_risk_explained), r.created_at, r.prev_hash, r.hash,
            ),
        )

    def add_log(self, e: LogEntry) -> None:
        self._db.execute(
            "INSERT INTO log_entries (seq, time, actor_id, event_type, object_id, payload_hash, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (e.seq, e.time, e.actor_id, e.event_type, e.object_id, e.payload_hash, e.prev_hash, e.hash),
        )

    def upsert_artifact(self, a: Artifact) -> None:
        self._db.execute(
            "INSERT INTO artifacts (artifact_id, type, content_hash, storage_uri, holder, sharded, participant_id,"
            " project_id, created_by, created_at, status, destination_country, transfer_basis)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(artifact_id) DO UPDATE SET status = excluded.status",
            (
                a.artifact_id, a.type, a.content_hash, a.storage_uri, a.holder, int(a.sharded),
                a.participant_id, a.project_id, a.created_by, a.created_at, a.status,
                a.destination_country, a.transfer_basis,
            ),
        )

    def add_edge(self, e: LineageEdge) -> None:
        self._db.execute(
            "INSERT INTO edges (parent_id, child_id, purpose, created_by, created_at) VALUES (?,?,?,?,?)",
            (e.parent_id, e.child_id, e.purpose, e.created_by, e.created_at),
        )

    def upsert_withdrawal(self, w: Withdrawal) -> None:
        self._db.execute(
            "INSERT INTO withdrawals (withdrawal_id, participant_id, project_id, scope, channel, received_at,"
            " consent_id, already_gone, receipt_id) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(withdrawal_id) DO UPDATE SET receipt_id = excluded.receipt_id",
            (
                w.withdrawal_id, w.participant_id, w.project_id, json.dumps(w.scope), w.channel,
                w.received_at, w.consent_id, json.dumps(w.already_gone), w.receipt_id,
            ),
        )

    def upsert_action(self, a: Action) -> None:
        self._db.execute(
            "INSERT INTO actions (action_id, withdrawal_id, artifact_id, kind, due_at, done_at, done_by, evidence,"
            " escalated) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(action_id) DO UPDATE SET done_at = excluded.done_at, done_by = excluded.done_by,"
            " evidence = excluded.evidence, escalated = excluded.escalated",
            (a.action_id, a.withdrawal_id, a.artifact_id, a.kind, a.due_at, a.done_at, a.done_by, a.evidence, int(a.escalated)),
        )

    def add_receipt(self, r: Receipt) -> None:
        self._db.execute(
            "INSERT INTO receipts (receipt_id, withdrawal_id, issued_at, scope, items, limits, signature)"
            " VALUES (?,?,?,?,?,?,?)",
            (r.receipt_id, r.withdrawal_id, r.issued_at, json.dumps(r.scope), json.dumps(r.items), json.dumps(r.limits), r.signature),
        )

    def add_refusal(self, refusal: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO refusals (refusal_id, body) VALUES (?, ?)", (refusal["refusal_id"], json.dumps(refusal))
        )

    def add_anchor(self, a: Anchor) -> None:
        self._db.execute(
            "INSERT INTO anchors (log_seq, head, time, sink) VALUES (?,?,?,?)", (a.seq, a.head, a.time, a.sink)
        )

    # ------------------------------------------------------------------- reads

    def log_length(self) -> int:
        return self._db.execute("SELECT COALESCE(MAX(seq), 0) FROM log_entries").fetchone()[0]

    def load(self) -> StoreState:
        q = lambda sql: self._db.execute(sql).fetchall()  # noqa: E731
        state = StoreState()
        state.participants = [(r["participant_id"], r["code"]) for r in q("SELECT * FROM participants ORDER BY seq")]
        for r in q("SELECT * FROM consents ORDER BY seq"):
            state.consents.append(
                ConsentRecord(
                    consent_id=r["consent_id"], participant_id=r["participant_id"], project_id=r["project_id"],
                    version=r["version"], script_version=r["script_version"], language=r["language"],
                    choices=json.loads(r["choices"]), capture_method=r["capture_method"], chw_id=r["chw_id"],
                    device_id=r["device_id"], teach_back_score=r["teach_back_score"], is_minor=bool(r["is_minor"]),
                    guardian_consent=_bool(r["guardian_consent"]), assent=_bool(r["assent"]),
                    guardian_verification=r["guardian_verification"],
                    transfer_risk_explained=bool(r["transfer_risk_explained"]),
                    created_at=r["created_at"], prev_hash=r["prev_hash"], hash=r["hash"],
                )
            )
        state.log = [
            LogEntry(r["seq"], r["time"], r["actor_id"], r["event_type"], r["object_id"], r["payload_hash"], r["prev_hash"], r["hash"])
            for r in q("SELECT * FROM log_entries ORDER BY seq")
        ]
        state.artifacts = [
            Artifact(
                artifact_id=r["artifact_id"], type=r["type"], content_hash=r["content_hash"],
                storage_uri=r["storage_uri"], holder=r["holder"], sharded=bool(r["sharded"]),
                participant_id=r["participant_id"], project_id=r["project_id"], created_by=r["created_by"],
                created_at=r["created_at"], status=r["status"],
                destination_country=r["destination_country"], transfer_basis=r["transfer_basis"],
            )
            for r in q("SELECT * FROM artifacts ORDER BY seq")
        ]
        state.edges = [
            LineageEdge(r["parent_id"], r["child_id"], r["purpose"], r["created_by"], r["created_at"])
            for r in q("SELECT * FROM edges ORDER BY seq")
        ]
        state.withdrawals = [
            Withdrawal(
                withdrawal_id=r["withdrawal_id"], participant_id=r["participant_id"], project_id=r["project_id"],
                scope=json.loads(r["scope"]), channel=r["channel"], received_at=r["received_at"],
                consent_id=r["consent_id"], already_gone=json.loads(r["already_gone"]), receipt_id=r["receipt_id"],
            )
            for r in q("SELECT * FROM withdrawals ORDER BY seq")
        ]
        state.actions = [
            Action(
                action_id=r["action_id"], withdrawal_id=r["withdrawal_id"], artifact_id=r["artifact_id"],
                kind=r["kind"], due_at=r["due_at"], done_at=r["done_at"], done_by=r["done_by"],
                evidence=r["evidence"], escalated=bool(r["escalated"]),
            )
            for r in q("SELECT * FROM actions ORDER BY seq")
        ]
        state.receipts = [
            Receipt(
                receipt_id=r["receipt_id"], withdrawal_id=r["withdrawal_id"], issued_at=r["issued_at"],
                scope=json.loads(r["scope"]), items=json.loads(r["items"]), limits=json.loads(r["limits"]),
                signature=r["signature"],
            )
            for r in q("SELECT * FROM receipts ORDER BY seq")
        ]
        state.refusals = [json.loads(r["body"]) for r in q("SELECT * FROM refusals ORDER BY seq")]
        state.anchors = [Anchor(r["log_seq"], r["head"], r["time"], r["sink"]) for r in q("SELECT * FROM anchors ORDER BY seq")]
        return state
