"""Consent records.

A ConsentRecord is immutable. Any change, including a withdrawal, is a new
version that points at the previous record's hash.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from .errors import ConsentError
from .hashing import hash_obj

# The six separate choices a participant answers one by one.
USES: tuple[str, ...] = (
    "record",
    "research",
    "model_training",
    "external_share",
    "retain_after_project",
    "recontact",
)

# Uses that an artifact can be created for. "record" and "recontact" are about
# the participant, not about derived copies.
PURPOSES: tuple[str, ...] = ("research", "model_training", "external_share", "retain_after_project")

CAPTURE_METHODS: tuple[str, ...] = (
    "spoken_yes_no",
    "button_press",
    "spoken_confirmed_by_chw",
    "chw_confirmed",
    # A withdrawal is also a new consent version; its capture method is its channel.
    "withdrawal_participant_code",
    "withdrawal_chw",
    "withdrawal_status_line",
)


def normalize_choices(answers: Mapping[str, bool | None]) -> dict[str, bool]:
    """Turn raw answers into the stored choices.

    Silence or a missing answer is "no". Anything that is not True,
    False or None is rejected so "yes" strings cannot slip in as truthy.
    Unknown keys are rejected so a typo cannot silently drop a choice.
    """
    unknown = set(answers) - set(USES)
    if unknown:
        raise ConsentError(f"unknown choices: {sorted(unknown)}")
    choices: dict[str, bool] = {}
    for use in USES:
        value = answers.get(use)
        if value is not None and not isinstance(value, bool):
            raise ConsentError(f"choice {use!r} must be True, False or None, got {value!r}")
        choices[use] = value is True
    if not choices["record"] and any(v for k, v in choices.items() if k != "record"):
        raise ConsentError("no other use can be accepted when recording is refused")
    return choices


@dataclass(frozen=True)
class ConsentRecord:
    consent_id: str
    participant_id: str
    project_id: str
    version: int
    script_version: str
    language: str
    choices: dict[str, bool]
    capture_method: str
    chw_id: str
    device_id: str
    teach_back_score: str | None
    is_minor: bool
    guardian_consent: bool | None
    assent: bool | None
    created_at: str
    prev_hash: str
    hash: str = field(default="")

    def body(self) -> dict[str, Any]:
        """Everything that is hashed: every field except the hash itself."""
        d = asdict(self)
        d.pop("hash")
        return d

    def compute_hash(self) -> str:
        return hash_obj(self.body())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def allows(self, use: str) -> bool:
        """May this use go ahead? Recording must be accepted for anything else."""
        if use == "record":
            return self.choices["record"]
        return self.choices["record"] and self.choices.get(use, False)

    @classmethod
    def build(cls, **fields: Any) -> "ConsentRecord":
        rec = cls(**fields, hash="")
        return cls(**{**rec.body(), "hash": rec.compute_hash()})

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ConsentRecord":
        return cls(**dict(d))
