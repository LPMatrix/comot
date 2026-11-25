"""Consent-aware copies of local Hugging Face Dataset splits."""
from __future__ import annotations

from dataclasses import dataclass

from datasets import Dataset

from .access import Actor
from .core import Comot
from .errors import ConsentRefused
from .lineage import Artifact


@dataclass(frozen=True)
class RegisteredSplit:
    dataset: Dataset
    artifact: Artifact


def _row_ids(dataset: Dataset, id_column: str) -> list[str]:
    if id_column not in dataset.column_names:
        raise ValueError(f"missing lineage column: {id_column}")
    # Project first, including for datasets with a user-defined transform or
    # an Audio feature. Consent checks must never decode the payload.
    ids = list(dataset.select_columns([id_column]).with_format(None)[id_column])
    if not ids:
        raise ValueError("cannot register a split without any parents")
    if any(not isinstance(key, str) or not key for key in ids):
        raise ValueError("every row needs a nonempty artifact id")
    return ids


def register_split(
    comot: Comot, dataset: Dataset, purpose: str, *, actor: Actor | str,
    id_column: str = "artifact_id",
) -> RegisteredSplit:
    """Register the entire split or propagate Comot's refusal and blockers."""
    parents = list(dict.fromkeys(_row_ids(dataset, id_column)))
    artifact = comot.register("dataset_version", parents, purpose, actor=actor)
    return RegisteredSplit(dataset, artifact)


def filter_allowed(
    comot: Comot, dataset: Dataset, purpose: str, *, actor: Actor | str,
    id_column: str = "artifact_id",
) -> RegisteredSplit:
    """Return a registered subset in original row order, including repeated rows."""
    ids = _row_ids(dataset, id_column)
    parents = []
    blockers = set()
    for key in dict.fromkeys(ids):
        decision = comot.check_use(key, purpose, actor=actor)
        if decision.allowed:
            parents.append(key)
        else:
            blockers.update(decision.blockers)
    if not parents:
        raise ConsentRefused("no rows are allowed for this purpose", sorted(blockers))
    allowed = set(parents)
    subset = dataset.select([i for i, key in enumerate(ids) if key in allowed], keep_in_memory=True)
    # register() checks again inside its transaction, including withdrawals
    # that arrived after we selected these rows.
    artifact = comot.register("dataset_version", parents, purpose, actor=actor)
    return RegisteredSplit(subset, artifact)
