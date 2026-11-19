"""Withdrawal workflow types and planning.

Deadlines here are proposed defaults. A community data board should own the real
values, so they live in ``WithdrawalPolicy`` and nothing else hard-codes them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from .lineage import INTERNAL, Artifact

CHANNELS: tuple[str, ...] = ("participant_code", "chw", "status_line")
ACTION_KINDS: tuple[str, ...] = ("delete", "exclude", "retrain", "retire", "notify")

# Copies that are plain files and can simply be deleted.
FILE_TYPES: frozenset[str] = frozenset({"recording", "transcript", "clip", "features"})


@dataclass(frozen=True)
class WithdrawalPolicy:
    delete_days: int = 7
    dataset_days: int = 7
    model_days: int = 180  # next scheduled retrain, at most 6 months
    sharded_model_days: int = 30
    notify_days: int = 14  # outside holder must confirm within this time


@dataclass
class Withdrawal:
    withdrawal_id: str
    participant_id: str
    project_id: str
    scope: list[str]  # ["all"] or a list of uses
    channel: str
    received_at: str
    consent_id: str  # the consent record whose new version records the withdrawal
    already_gone: list[str] = field(default_factory=list)  # affected copies that no longer existed
    receipt_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Action:
    action_id: str
    withdrawal_id: str
    artifact_id: str
    kind: str
    due_at: str
    done_at: str | None = None
    done_by: str | None = None
    evidence: str | None = None
    escalated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def plan_actions(artifact: Artifact, policy: WithdrawalPolicy) -> list[tuple[str, timedelta]]:
    """What must happen to one affected copy, and by when.

    A copy held outside gets a notice, never a delete: we cannot delete what
    we do not hold, and the licence makes the holder confirm instead.
    """
    if artifact.holder != INTERNAL:
        return [("notify", timedelta(days=policy.notify_days))]
    if artifact.type in FILE_TYPES:
        return [("delete", timedelta(days=policy.delete_days))]
    if artifact.type == "dataset_version":
        # Remove the item and publish a new dataset version.
        return [("exclude", timedelta(days=policy.dataset_days))]
    if artifact.type == "model_version":
        if artifact.sharded:
            return [("retrain", timedelta(days=policy.sharded_model_days))]
        # Retire once the retrained version ships. Until then the item is kept
        # out of every new run by the pre-training check.
        return [("retire", timedelta(days=policy.model_days))]
    raise ValueError(f"no withdrawal plan for artifact type {artifact.type!r}")
