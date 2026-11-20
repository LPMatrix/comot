"""The Comot service object: consent, lineage, withdrawal and the audit log in one place.

Comot keeps its working state in memory and writes every change through to a
store. With no store it is a pure in-memory object. With ``Comot.open(path)`` it
is backed by one SQLite file. A FastAPI and PostgreSQL service is a later step;
the rules here are what it will wrap.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .access import AccessDenied, AccessPolicy, Actor
from .anchor import Anchor, AnchorSink
from .bundle import verify_state
from .clock import Clock, iso, parse, system_clock
from .consent import CAPTURE_METHODS, PURPOSES, USES, ConsentRecord, check_guardian_verification, normalize_choices
from .errors import ComotError, ConsentError, ConsentRefused, StoreIntegrityError, TrainingBlocked, UnknownObject
from .hashing import GENESIS, canonical, sha256_hex
from .ids import new_code, new_id
from .lineage import ARTIFACT_TYPES, INTERNAL, Artifact, LineageEdge, LineageGraph, check_transfer
from .log import AuditLog
from .receipt import (
    LIMIT_MODEL_WEIGHTS,
    LIMIT_PUBLISHED_RESULTS,
    HmacSigner,
    Receipt,
    sign_body,
)
from .store import NullStore, SqliteStore, StoreError
from .vault import IdentityVault
from .withdrawal import CHANNELS, Action, Withdrawal, WithdrawalPolicy, plan_actions

# Statuses after which a copy no longer exists or must not be built on.
_GONE = ("deleted", "retired")


@dataclass
class UseDecision:
    allowed: bool
    blockers: list[tuple[str, str]] = field(default_factory=list)  # (artifact_id, reason)


@dataclass
class TrainingCheck:
    run_id: str
    ok: bool
    allowed: list[str]
    blocked: list[tuple[str, str]]


class Comot:
    def __init__(
        self,
        clock: Clock = system_clock,
        signer: HmacSigner | None = None,
        policy: WithdrawalPolicy | None = None,
        store: NullStore | SqliteStore | None = None,
        vault: IdentityVault | None = None,
        verify: bool = True,
        access: AccessPolicy | None = None,
    ):
        self.clock = clock
        self.access = access
        self.signer = signer or HmacSigner()
        self.policy = policy or WithdrawalPolicy()
        self.store = store or NullStore()
        self.vault = vault
        self._depth = 0
        self._reset()
        if self.store.persistent:
            self._check_signer()
            self._load(verify=verify)
        self._record_policy()

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        signer: HmacSigner,
        clock: Clock = system_clock,
        policy: WithdrawalPolicy | None = None,
        vault: IdentityVault | None = None,
        verify: bool = True,
        access: AccessPolicy | None = None,
    ) -> "Comot":
        """Open, or create, a Comot backed by one SQLite file.

        A signer is required, because receipts signed earlier must still verify
        and a fresh random key would silently break that. Use
        ``HmacSigner(load_key_file(...))``. With ``verify`` (the default) the
        hash chains and stored anchors are checked, and a store that fails
        raises ``StoreIntegrityError``. With ``access`` every call needs an
        ``Actor`` whose roles allow it.
        """
        return cls(
            clock=clock,
            signer=signer,
            policy=policy,
            store=SqliteStore(path),
            vault=vault,
            verify=verify,
            access=access,
        )

    def close(self) -> None:
        self.store.close()

    def _reset(self) -> None:
        self.log = AuditLog()
        self.graph = LineageGraph()
        self.consents: list[ConsentRecord] = []  # one chain, in creation order
        self.withdrawals: dict[str, Withdrawal] = {}
        self.actions: dict[str, Action] = {}
        self.receipts: dict[str, Receipt] = {}
        self.refusals: list[dict[str, Any]] = []
        self._participants: dict[str, str] = {}  # participant_id -> code
        self._by_code: dict[str, str] = {}
        self._latest: dict[tuple[str, str], ConsentRecord] = {}
        self.anchors: list[Anchor] = []

    # ------------------------------------------------------------------ helpers

    def _now(self) -> str:
        return iso(self.clock())

    def _log(self, actor_id: str, event_type: str, object_id: str, payload: Any) -> None:
        entry = self.log.append(
            time=self._now(), actor_id=actor_id, event_type=event_type, object_id=object_id, payload=payload
        )
        self.store.add_log(entry)

    # ------------------------------------------------------------------ access

    def _authorize(self, actor: Actor | str | None, operation: str, *, optional: bool = False) -> str:
        """Check that the actor may do this, and return their id.

        Without an access policy any named actor may do anything, as before.
        With one, only an ``Actor`` whose roles grant the operation may. A
        refusal is logged, and raised after that is committed.
        """
        if self.access is None:
            if isinstance(actor, Actor):
                return actor.id
            if isinstance(actor, str) and actor.strip():
                return actor
            if actor is None and optional:
                return "anonymous"
            raise ValueError("an actor is required")
        if isinstance(actor, Actor) and self.access.allows(actor, operation):
            return actor.id
        if isinstance(actor, Actor):
            who, roles, why = actor.id, sorted(actor.roles), f"{actor.id} may not {operation}"
        else:
            who = actor if isinstance(actor, str) and actor.strip() else "unauthenticated"
            roles = []
            why = f"{operation} needs an authenticated Actor when an access policy is set"
        with self._txn():
            self._log(who, "access_denied", operation, {"operation": operation, "roles": roles})
        raise AccessDenied(why, actor_id=who, operation=operation)

    def _record_policy(self) -> None:
        """Log which access policy is in force, whenever it differs from the last one logged."""
        if self.access is None:
            return
        object_id = f"policy:{self.access.hash()}"
        with self._txn():
            last = next((e for e in reversed(self.log.entries) if e.event_type == "access_policy_set"), None)
            if last is None or last.object_id != object_id:
                self._log("system", "access_policy_set", object_id, self.access.to_dict())

    # -------------------------------------------------------------- persistence

    def _check_signer(self) -> None:
        """A store remembers a fingerprint of its signing key and refuses a different one."""
        fp = sha256_hex(b"comot-signer-fingerprint" + self.signer.key)
        with self.store.transaction():
            known = self.store.get_meta("signer_fingerprint")
            if known is None:
                self.store.set_meta("signer_fingerprint", fp)
            elif known != fp:
                raise StoreError("this store was created with a different signing key")

    def _load(self, *, verify: bool = False) -> None:
        """Rebuild working state from the store."""
        state = self.store.load()
        if verify:
            problems = verify_state(state.consents, state.log, state.anchors)
            if problems:
                raise StoreIntegrityError(problems)
        self._reset()
        for pid, code in state.participants:
            self._participants[pid] = code
            self._by_code[code] = pid
        self.consents = list(state.consents)
        for rec in self.consents:
            self._latest[(rec.participant_id, rec.project_id)] = rec
        self.log.entries = list(state.log)
        into: dict[str, list[LineageEdge]] = {}
        for e in state.edges:
            into.setdefault(e.child_id, []).append(e)
        for a in state.artifacts:  # creation order, so parents always exist first
            self.graph.add(a, into.get(a.artifact_id, []))
        self.withdrawals = {w.withdrawal_id: w for w in state.withdrawals}
        self.actions = {a.action_id: a for a in state.actions}
        self.receipts = {r.receipt_id: r for r in state.receipts}
        self.refusals = list(state.refusals)
        self.anchors = list(state.anchors)

    def refresh(self) -> None:
        """Reload if another process has written since we last looked."""
        if self.store.persistent and self.store.log_length() != len(self.log.entries):
            self._load()

    @contextmanager
    def _txn(self) -> Iterator[None]:
        """One atomic operation: all of its writes commit together or not at all.

        If it fails, memory is rebuilt from what was committed, so the two never
        disagree. Nested uses join the outermost one.
        """
        outermost = self._depth == 0
        start = len(self.log.entries)
        self._depth += 1
        try:
            with self.store.transaction():
                if outermost:
                    self.refresh()  # we hold the write lock now, so this is current
                    start = len(self.log.entries)
                yield
        except BaseException as e:
            # A plain validation error before any write leaves memory untouched.
            # Anything else may have changed memory the database did not keep.
            wrote = outermost and len(self.log.entries) != start
            if outermost and self.store.persistent and (wrote or not isinstance(e, (ComotError, ValueError))):
                self._load()
            raise
        finally:
            self._depth -= 1

    # ------------------------------------------------------------- participants

    def create_participant(self, *, actor: Actor | str) -> tuple[str, str]:
        """Create a pseudonymous participant. Returns (participant_id, spoken code).

        No name or phone number is stored here. Those belong in the separate
        identity vault (see ``store_identity``).
        """
        actor_id = self._authorize(actor, "create_participant")
        with self._txn():
            pid = new_id("p")
            code = new_code(self._by_code)
            self._participants[pid] = code
            self._by_code[code] = pid
            self.store.add_participant(pid, code)
            self._log(actor_id, "participant_created", pid, {"participant_id": pid})
        return pid, code

    def participant_for_code(self, code: str) -> str:
        try:
            return self._by_code[code]
        except KeyError:
            raise UnknownObject("unknown participant code") from None

    # ----------------------------------------------------------------- consent

    def latest_consent(self, participant_id: str, project_id: str) -> ConsentRecord | None:
        return self._latest.get((participant_id, project_id))

    def record_consent(
        self,
        participant_id: str,
        project_id: str,
        answers: dict[str, bool | None],
        *,
        script_version: str,
        language: str,
        capture_method: str,
        device_id: str,
        actor: Actor | str,
        teach_back_score: str | None = None,
        is_minor: bool = False,
        guardian_consent: bool | None = None,
        assent: bool | None = None,
        guardian_verification: str | None = None,
        transfer_risk_explained: bool = False,
    ) -> ConsentRecord:
        """Record a participant's choices as a new, append-only consent version.

        A missing or None answer counts as "no". A change that takes a use
        away must go through ``withdraw`` so every copy gets an action. The
        actor is recorded as the person who captured it.

        For a participant under 18, ``guardian_verification`` says how the age and
        the guardian's consent were checked (see ``GUARDIAN_VERIFICATION``).
        ``transfer_risk_explained`` records that the participant was told the
        risks of copies going to a country without adequate protection, which a
        copy sent abroad on the strength of consent depends on.
        """
        actor_id = self._authorize(actor, "record_consent")
        if capture_method not in CAPTURE_METHODS[:4]:
            raise ConsentError(f"capture_method must be one of {CAPTURE_METHODS[:4]}")
        choices = normalize_choices(answers)
        if is_minor and any(choices.values()) and not (guardian_consent is True and assent is True):
            raise ConsentError("a participant under 18 needs both guardian consent and the young person's assent")
        if not is_minor and (guardian_consent is not None or assent is not None):
            raise ConsentError("guardian consent and assent apply to participants under 18 only")
        check_guardian_verification(guardian_consent, guardian_verification)
        if not isinstance(transfer_risk_explained, bool):
            raise ConsentError("transfer_risk_explained must be True or False")

        with self._txn():  # what follows depends on current state, so read it under the lock
            if participant_id not in self._participants:
                raise UnknownObject(f"unknown participant {participant_id!r}")
            previous = self._latest.get((participant_id, project_id))
            if previous is not None:
                taken_away = [u for u in USES if previous.choices[u] and not choices[u]]
                if taken_away:
                    raise ConsentError(f"use withdraw() to take away {taken_away}, so every copy gets an action")
            return self._append_consent(
                previous,
                participant_id=participant_id,
                project_id=project_id,
                script_version=script_version,
                language=language,
                choices=choices,
                capture_method=capture_method,
                chw_id=actor_id,
                device_id=device_id,
                teach_back_score=teach_back_score,
                is_minor=is_minor,
                guardian_consent=guardian_consent,
                assent=assent,
                guardian_verification=guardian_verification,
                transfer_risk_explained=transfer_risk_explained,
                actor_id=actor_id,
            )

    def _append_consent(self, previous: ConsentRecord | None, *, actor_id: str, **fields: Any) -> ConsentRecord:
        with self._txn():
            record = ConsentRecord.build(
                consent_id=previous.consent_id if previous else new_id("c"),
                version=previous.version + 1 if previous else 1,
                created_at=self._now(),
                prev_hash=self.consents[-1].hash if self.consents else GENESIS,
                **fields,
            )
            self.consents.append(record)
            self._latest[(record.participant_id, record.project_id)] = record
            self.store.add_consent(record)
            self._log(
                actor_id,
                "consent_recorded" if record.version == 1 else "consent_changed",
                record.consent_id,
                record.to_dict(),
            )
        return record

    # ----------------------------------------------------------------- lineage

    def register_recording(
        self,
        participant_id: str,
        project_id: str,
        *,
        content: bytes | None = None,
        content_hash: str | None = None,
        storage_uri: str | None = None,
        actor: Actor | str,
    ) -> Artifact:
        """Register a raw recording. It needs a consent record that accepts recording."""
        created_by = self._authorize(actor, "register_recording")
        refused: ConsentRefused | None = None
        with self._txn():
            consent = self.latest_consent(participant_id, project_id)
            if consent is None or not consent.allows("record"):
                blockers = [(participant_id, "no consent to record")]
                self._refuse(created_by, "recording", [], "record", blockers)
                refused = ConsentRefused("this participant has not consented to recording", blockers)
            else:
                artifact = self._add_artifact(
                    "recording",
                    [],
                    [],
                    content=content,
                    content_hash=content_hash,
                    storage_uri=storage_uri,
                    holder=INTERNAL,
                    sharded=False,
                    participant_id=participant_id,
                    project_id=project_id,
                    created_by=created_by,
                    destination_country=None,
                    transfer_basis=None,
                )
        if refused:  # raised after the transaction, so the logged refusal is kept
            raise refused
        return artifact

    def register(
        self,
        type: str,
        parents: Sequence[str],
        purpose: str,
        *,
        content: bytes | None = None,
        content_hash: str | None = None,
        storage_uri: str | None = None,
        holder: str = INTERNAL,
        sharded: bool = False,
        destination_country: str | None = None,
        transfer_basis: str | None = None,
        actor: Actor | str,
    ) -> Artifact:
        """Register a derived copy. This is the one call a data team makes.

        Refused, and the refusal logged, if the consent behind any parent does
        not allow the intended use.

        A copy held outside (``holder`` is not internal) also needs
        ``destination_country`` (a two-letter code) and ``transfer_basis`` (see
        ``TRANSFER_BASES``), which are recorded as the basis for the transfer. If
        the basis is ``consent_after_risk_notice``, every source participant must
        have been told the risks of transfer abroad.
        """
        created_by = self._authorize(actor, "register")
        if type not in ARTIFACT_TYPES or type == "recording":
            raise ValueError(f"type must be one of {[t for t in ARTIFACT_TYPES if t != 'recording']}")
        if purpose not in PURPOSES:
            raise ValueError(f"purpose must be one of {PURPOSES}")
        if not parents:
            raise ValueError("a derived copy needs at least one parent")
        check_transfer(holder, destination_country, transfer_basis)

        # Some uses are implied by what is being made or where it goes.
        required = [purpose]
        if type == "model_version" and "model_training" not in required:
            required.append("model_training")
        if holder != INTERNAL and "external_share" not in required:
            required.append("external_share")

        refused: ConsentRefused | None = None
        with self._txn():
            blockers: list[tuple[str, str]] = []
            for parent in parents:
                for use in required:
                    blockers += self._check_use(parent, use).blockers
            if transfer_basis == "consent_after_risk_notice" and destination_country != "NG":
                for parent in parents:
                    for r in self.graph.source_recordings(parent):
                        rec = self.graph.artifacts[r]
                        consent = self.latest_consent(rec.participant_id or "", rec.project_id or "")
                        if consent is None or not consent.transfer_risk_explained:
                            blockers.append((r, "participant was not told the risks of a transfer abroad"))
            if blockers:
                blockers = sorted(set(blockers))
                self._refuse(created_by, type, list(parents), purpose, blockers)
                refused = ConsentRefused(f"consent does not allow this {type} to be made for {required}", blockers)
            else:
                edges = [(parent, use) for parent in parents for use in required]
                artifact = self._add_artifact(
                    type,
                    [p for p, _ in edges],
                    [u for _, u in edges],
                    content=content,
                    content_hash=content_hash,
                    storage_uri=storage_uri,
                    holder=holder,
                    sharded=sharded,
                    participant_id=None,
                    project_id=None,
                    created_by=created_by,
                    destination_country=destination_country,
                    transfer_basis=transfer_basis,
                )
        if refused:  # raised after the transaction, so the logged refusal is kept
            raise refused
        return artifact

    def _add_artifact(
        self,
        type: str,
        edge_parents: list[str],
        edge_purposes: list[str],
        *,
        content: bytes | None,
        content_hash: str | None,
        storage_uri: str | None,
        holder: str,
        sharded: bool,
        participant_id: str | None,
        project_id: str | None,
        created_by: str,
        destination_country: str | None,
        transfer_basis: str | None,
    ) -> Artifact:
        if content is not None:
            content_hash = sha256_hex(content)
        now = self._now()
        artifact = Artifact(
            artifact_id=new_id("a"),
            type=type,
            content_hash=content_hash,
            storage_uri=storage_uri,
            holder=holder,
            sharded=sharded,
            participant_id=participant_id,
            project_id=project_id,
            created_by=created_by,
            created_at=now,
            destination_country=destination_country,
            transfer_basis=transfer_basis,
        )
        edges = [
            LineageEdge(parent_id=p, child_id=artifact.artifact_id, purpose=u, created_by=created_by, created_at=now)
            for p, u in zip(edge_parents, edge_purposes)
        ]
        with self._txn():
            self.graph.add(artifact, edges)
            self.store.upsert_artifact(artifact)
            for e in edges:
                self.store.add_edge(e)
            self._log(
                created_by,
                "artifact_registered",
                artifact.artifact_id,
                {"artifact": artifact.to_dict(), "edges": [e.to_dict() for e in edges]},
            )
        return artifact

    def _refuse(self, actor: str, type: str, parents: list[str], purpose: str, blockers: list[tuple[str, str]]) -> None:
        refusal = {
            "refusal_id": new_id("x"),
            "time": self._now(),
            "type": type,
            "parents": parents,
            "purpose": purpose,
            "blockers": [list(b) for b in blockers],
        }
        with self._txn():
            self.refusals.append(refusal)
            self.store.add_refusal(refusal)
            self._log(actor, "registration_refused", refusal["refusal_id"], refusal)

    def find_by_hash(self, content_hash: str) -> list[Artifact]:
        """Match a file found later to a registered artifact."""
        return [a for a in self.graph.artifacts.values() if a.content_hash == content_hash]

    # -------------------------------------------------------------- use checks

    def _open_action_artifacts(self) -> set[str]:
        return {a.artifact_id for a in self.actions.values() if a.done_at is None}

    def check_use(self, artifact_id: str, purpose: str, *, actor: Actor | str | None = None) -> UseDecision:
        """May this artifact be used for this purpose? The strictest consent wins.

        Walks back to every source recording. Blocked if any one of those
        people has not accepted the use, if any copy on the way is gone, or if a
        withdrawal still has an open action on a copy on the way. The actor is
        only needed when an access policy is set.
        """
        self._authorize(actor, "check_use", optional=True)
        return self._check_use(artifact_id, purpose)

    def _check_use(self, artifact_id: str, purpose: str) -> UseDecision:
        if purpose not in PURPOSES:
            raise ValueError(f"purpose must be one of {PURPOSES}")
        if self._depth == 0:
            self.refresh()  # another process may have recorded a withdrawal
        chain = self.graph.ancestors(artifact_id, include_self=True)
        blockers: list[tuple[str, str]] = []
        open_actions = self._open_action_artifacts()
        for a in chain:
            artifact = self.graph.artifacts[a]
            if artifact.status in _GONE:
                blockers.append((a, f"copy is {artifact.status}"))
            elif a in open_actions:
                blockers.append((a, "a withdrawal still has an open action on this copy"))
        for r in self.graph.source_recordings(artifact_id):
            rec = self.graph.artifacts[r]
            consent = self.latest_consent(rec.participant_id or "", rec.project_id or "")
            if consent is None or not consent.allows(purpose):
                blockers.append((r, f"consent does not allow {purpose}"))
        return UseDecision(allowed=not blockers, blockers=sorted(set(blockers)))

    def filter_allowed(
        self, artifact_ids: Iterable[str], purpose: str, *, actor: Actor | str | None = None
    ) -> list[str]:
        """Keep only the artifacts that may be used for this purpose."""
        self._authorize(actor, "check_use", optional=True)
        return [a for a in artifact_ids if self._check_use(a, purpose).allowed]

    def check_training_run(
        self, artifact_ids: Sequence[str], *, actor: Actor | str, strict: bool = True
    ) -> TrainingCheck:
        """Pre-training check. Call it before every training run.

        With ``strict`` (the default) a run that includes any blocked item
        raises ``TrainingBlocked``, so a team cannot miss it.
        """
        actor_id = self._authorize(actor, "check_training_run")
        allowed: list[str] = []
        blocked: list[tuple[str, str]] = []
        with self._txn():
            for a in artifact_ids:
                decision = self._check_use(a, "model_training")
                if decision.allowed:
                    allowed.append(a)
                else:
                    blocked += decision.blockers
            result = TrainingCheck(
                run_id=new_id("run"), ok=not blocked, allowed=allowed, blocked=sorted(set(blocked))
            )
            self._log(
                actor_id,
                "training_check",
                result.run_id,
                {"artifacts": list(artifact_ids), "ok": result.ok, "blocked": [list(b) for b in result.blocked]},
            )
        if strict and not result.ok:  # raised after the transaction, so the check stays logged
            raise TrainingBlocked("this training run includes items that may not be used for training", result.blocked)
        return result

    # -------------------------------------------------------------- withdrawal

    def withdraw(
        self,
        project_id: str,
        *,
        participant_id: str | None = None,
        code: str | None = None,
        scope: str | Sequence[str] = "all",
        channel: str,
        actor: Actor | str,
    ) -> Withdrawal:
        """Withdraw all consent, or some uses, with no reason asked.

        Creates a new consent version, one action per affected copy, and
        an initial receipt. When a participant withdraws by code through a
        phone line or a health worker, the actor is the service or person
        relaying it.
        """
        actor_id = self._authorize(actor, "withdraw")
        if channel not in CHANNELS:
            raise ValueError(f"channel must be one of {CHANNELS}")
        if (participant_id is None) == (code is None):
            raise ValueError("give exactly one of participant_id or code")
        with self._txn():  # the whole withdrawal commits together or not at all
            pid = participant_id if participant_id is not None else self.participant_for_code(code or "")
            current = self.latest_consent(pid, project_id)
            if current is None:
                raise UnknownObject("no consent on file for this participant in this project")

            if scope == "all":
                revoked: set[str] | None = None
            else:
                uses = set([scope] if isinstance(scope, str) else scope)
                if not uses or uses - set(USES):
                    raise ValueError(f"scope must be 'all' or a list of uses from {USES}")
                # Refusing to be recorded takes everything with it.
                revoked = None if "record" in uses else uses

            if revoked is None:
                choices = {u: False for u in USES}
            else:
                choices = {u: (current.choices[u] and u not in revoked) for u in USES}

            new = self._append_consent(
                current,
                actor_id=actor_id,
                participant_id=pid,
                project_id=project_id,
                script_version=current.script_version,
                language=current.language,
                choices=choices,
                capture_method=f"withdrawal_{channel}",
                chw_id=actor_id if channel == "chw" else "n/a",
                device_id="n/a",
                teach_back_score=None,
                is_minor=current.is_minor,
                guardian_consent=current.guardian_consent,
                assent=current.assent,
                guardian_verification=current.guardian_verification,
                transfer_risk_explained=current.transfer_risk_explained,
            )
            withdrawal = Withdrawal(
                withdrawal_id=new_id("w"),
                participant_id=pid,
                project_id=project_id,
                scope=["all"] if revoked is None else sorted(revoked),
                channel=channel,
                received_at=self._now(),
                consent_id=new.consent_id,
            )
            recordings = self._recordings_of(pid, project_id)
            affected = self.graph.affected_by(recordings, revoked)
            withdrawal.already_gone = [a for a in affected if self.graph.artifacts[a].status in _GONE]
            self.withdrawals[withdrawal.withdrawal_id] = withdrawal
            self.store.upsert_withdrawal(withdrawal)
            self._log(actor_id, "withdrawal_received", withdrawal.withdrawal_id, withdrawal.to_dict())

            now = self.clock()
            for artifact_id in affected:
                if artifact_id in withdrawal.already_gone:
                    continue  # already gone, nothing left to do
                artifact = self.graph.artifacts[artifact_id]
                for kind, delta in plan_actions(artifact, self.policy):
                    action = Action(
                        action_id=new_id("act"),
                        withdrawal_id=withdrawal.withdrawal_id,
                        artifact_id=artifact_id,
                        kind=kind,
                        due_at=iso(now + delta),
                    )
                    self.actions[action.action_id] = action
                    self.store.upsert_action(action)
                    self._log(actor_id, "action_created", action.action_id, action.to_dict())
                if artifact.type == "model_version":
                    artifact.status = "tainted"
                    self.store.upsert_artifact(artifact)
            self._issue_receipt(withdrawal.withdrawal_id, actor_id)
            return withdrawal

    def actions_for(self, withdrawal_id: str, *, actor: Actor | str | None = None) -> list[Action]:
        self._authorize(actor, "view_actions", optional=True)
        return self._actions_for(withdrawal_id)

    def _actions_for(self, withdrawal_id: str) -> list[Action]:
        return [a for a in self.actions.values() if a.withdrawal_id == withdrawal_id]

    def _recordings_of(self, participant_id: str, project_id: str) -> list[str]:
        return [
            a.artifact_id
            for a in self.graph.artifacts.values()
            if a.type == "recording" and a.participant_id == participant_id and a.project_id == project_id
        ]

    def coverage(self, withdrawal_id: str, *, actor: Actor | str | None = None) -> float:
        """Share of affected copies, found by walking the graph, that received an action.

        The target is 100%. It is computed from the graph and not from the
        actions, so a copy the planner missed lowers it. Copies that were
        already gone when the withdrawal arrived are not owed an action.
        """
        self._authorize(actor, "view_actions", optional=True)
        w = self.withdrawals[withdrawal_id]
        revoked = None if w.scope == ["all"] else set(w.scope)
        affected = self.graph.affected_by(self._recordings_of(w.participant_id, w.project_id), revoked)
        owed = [a for a in affected if a not in w.already_gone]
        with_action = {a.artifact_id for a in self._actions_for(withdrawal_id)}
        return 1.0 if not owed else len([a for a in owed if a in with_action]) / len(owed)

    def complete_action(self, action_id: str, *, actor: Actor | str, evidence: str) -> Action:
        """Mark one action done, with who did it and proof."""
        done_by = self._authorize(actor, "complete_action")
        if not evidence.strip():
            raise ValueError("evidence is required, for example a storage deletion id or a new dataset version id")
        with self._txn():
            try:
                action = self.actions[action_id]
            except KeyError:
                raise UnknownObject(f"unknown action {action_id!r}") from None
            if action.done_at is not None:
                raise ValueError("action is already done")
            action.done_at = self._now()
            action.done_by = done_by
            action.evidence = evidence
            artifact = self.graph.artifacts[action.artifact_id]
            if action.kind == "delete":
                artifact.status = "deleted"
            elif action.kind in ("retire", "exclude"):
                # An excluded-from dataset is superseded by the new version the team publishes.
                artifact.status = "retired"
            elif action.kind == "retrain":
                artifact.status = "active"
            self.store.upsert_action(action)
            self.store.upsert_artifact(artifact)
            self._log(done_by, "action_completed", action_id, action.to_dict())
        return action

    def action_status(self, action: Action) -> str:
        if action.done_at is not None:
            return "done"
        return "overdue" if self.clock() > parse(action.due_at) else "pending"

    def overdue_actions(self, *, actor: Actor | str | None = None) -> list[Action]:
        self._authorize(actor, "view_actions", optional=True)
        return self._overdue_actions()

    def _overdue_actions(self) -> list[Action]:
        if self._depth == 0:
            self.refresh()
        return [a for a in self.actions.values() if self.action_status(a) == "overdue"]

    def escalate_overdue(self, *, actor: Actor | str) -> list[Action]:
        """Tell the board about overdue actions, once each."""
        actor_id = self._authorize(actor, "escalate_overdue")
        newly: list[Action] = []
        with self._txn():
            for a in self._overdue_actions():
                if not a.escalated:
                    a.escalated = True
                    newly.append(a)
                    self.store.upsert_action(a)
                    self._log(actor_id, "action_overdue", a.action_id, a.to_dict())
        return newly

    def issue_receipt(self, withdrawal_id: str, *, actor: Actor | str) -> Receipt:
        """Issue a signed receipt of what is done, what is pending, and what cannot be done."""
        return self._issue_receipt(withdrawal_id, self._authorize(actor, "issue_receipt"))

    def _issue_receipt(self, withdrawal_id: str, actor_id: str) -> Receipt:
        with self._txn():
            w = self.withdrawals[withdrawal_id]
            items = []
            for a in self._actions_for(withdrawal_id):
                artifact = self.graph.artifacts[a.artifact_id]
                items.append(
                    {
                        "artifact_id": a.artifact_id,
                        "artifact_type": artifact.type,
                        "kind": a.kind,
                        "status": self.action_status(a),
                        "due_at": a.due_at,
                        "done_at": a.done_at,
                    }
                )
            limits = []
            if any(i["artifact_type"] == "model_version" for i in items):
                limits.append(LIMIT_MODEL_WEIGHTS)
            limits.append(LIMIT_PUBLISHED_RESULTS)
            receipt = Receipt(
                receipt_id=new_id("r"),
                withdrawal_id=withdrawal_id,
                issued_at=self._now(),
                scope=w.scope,
                items=items,
                limits=limits,
            )
            receipt.signature = sign_body(self.signer, receipt.body())
            self.receipts[receipt.receipt_id] = receipt
            w.receipt_id = receipt.receipt_id
            self.store.add_receipt(receipt)
            self.store.upsert_withdrawal(w)
            self._log(actor_id, "receipt_issued", receipt.receipt_id, receipt.to_dict())
        return receipt

    def verify_receipt(self, receipt: Receipt) -> bool:
        return self.signer.verify(canonical(receipt.body()), receipt.signature)

    # ----------------------------------------------------------------- anchors

    def anchor(self, sink: AnchorSink, *, actor: Actor | str) -> Anchor | None:
        """Publish the log's current head outside the store.

        Run it on a schedule, for example daily from cron, with a sink the
        store's writers cannot edit. Returns None when nothing has happened
        since the last anchor, so a quiet system does not anchor itself in circles.
        """
        actor_id = self._authorize(actor, "anchor")
        with self._txn():
            if self.log.entries and self.log.entries[-1].event_type == "anchor_published":
                return None
            anchor = Anchor(seq=len(self.log.entries), head=self.log.head, time=self._now(), sink="")
            # Publish first: if it fails, nothing is recorded as anchored.
            anchor = Anchor(anchor.seq, anchor.head, anchor.time, sink.publish(anchor))
            self.anchors.append(anchor)
            self.store.add_anchor(anchor)
            self._log(actor_id, "anchor_published", f"anchor@{anchor.seq}", anchor.to_dict())
        return anchor

    def verify_integrity(self, anchors: Iterable[Anchor] = (), *, actor: Actor | str | None = None) -> list[str]:
        """Re-check the chains and anchors. ``anchors`` may include an external anchor file."""
        self._authorize(actor, "verify_integrity", optional=True)
        self.refresh()
        return verify_state(self.consents, self.log.entries, list(self.anchors) + list(anchors))

    # ---------------------------------------------------------------- identity

    def _need_vault(self) -> IdentityVault:
        if self.vault is None:
            raise ComotError("no identity vault is attached; pass vault=IdentityVault(...)")
        return self.vault

    def store_identity(self, participant_id: str, *, actor: Actor | str, **fields: str | None) -> None:
        """Keep a participant's name or phone in the vault. The audit log records that, never what."""
        actor_id = self._authorize(actor, "store_identity")
        vault = self._need_vault()
        with self._txn():
            if participant_id not in self._participants:
                raise UnknownObject(f"unknown participant {participant_id!r}")
            vault.put(participant_id, **fields)
            self._log(actor_id, "identity_stored", participant_id, {"participant_id": participant_id})

    def read_identity(self, participant_id: str, *, actor: Actor | str) -> dict[str, Any] | None:
        """Read a participant's identity. Every read is logged against the person who made it."""
        actor_id = self._authorize(actor, "read_identity")
        vault = self._need_vault()
        with self._txn():
            self._log(actor_id, "identity_read", participant_id, {"participant_id": participant_id})
            return vault.get(participant_id)

    def delete_identity(self, participant_id: str, *, actor: Actor | str) -> bool:
        """Erase a participant's identity alone. Consent records and the log are untouched."""
        actor_id = self._authorize(actor, "delete_identity")
        vault = self._need_vault()
        with self._txn():
            deleted = vault.delete(participant_id)
            self._log(actor_id, "identity_deleted", participant_id, {"participant_id": participant_id, "deleted": deleted})
            return deleted

    # ------------------------------------------------------------------ export

    def export_bundle(self, *, actor: Actor | str | None = None) -> dict[str, Any]:
        """A signed export for ethics committees and auditors.

        Holds pseudonymous ids, hashes and statuses only. Participant codes,
        storage locations and anything from the identity vault are left out on purpose.
        """
        self._authorize(actor, "export_bundle", optional=True)
        self.refresh()
        artifacts = []
        for a in self.graph.artifacts.values():
            d = a.to_dict()
            d.pop("storage_uri")
            artifacts.append(d)
        body = {
            "format": "comot-bundle/0",
            "exported_at": self._now(),
            "consents": [c.to_dict() for c in self.consents],
            "log": [e.to_dict() for e in self.log.entries],
            "log_head": self.log.head,
            "anchors": [a.to_dict() for a in self.anchors],
            "artifacts": artifacts,
            "edges": [e.to_dict() for e in self.graph.edges],
            "withdrawals": [w.to_dict() for w in self.withdrawals.values()],
            "actions": [a.to_dict() for a in self.actions.values()],
            "receipts": [r.to_dict() for r in self.receipts.values()],
            "refusals": self.refusals,
        }
        return {**body, "signature": sign_body(self.signer, body)}
