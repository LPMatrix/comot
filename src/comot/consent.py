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

# How the person checking a minor's consent confirmed the child's age and that a
# guardian really agreed (Nigeria Data Protection Act s.31(2)). Never the
# document itself or its number.
GUARDIAN_VERIFICATION: tuple[str, ...] = (
    "government_id_seen",  # an ID was shown and looked at; nothing from it is stored
    "guardian_present",  # the guardian was there in person and agreed
    "facility_record",  # the age and guardian are on a health facility record
    "other_documented",  # another way, written up in the project's own procedure
)


def check_guardian_verification(guardian_consent: bool | None, verification: str | None) -> None:
    """A guardian's consent needs a stated way it was checked, and nothing else does."""
    if guardian_consent is True:
        if verification not in GUARDIAN_VERIFICATION:
            raise ConsentError(
                f"say how the child's age and the guardian's consent were checked: one of {list(GUARDIAN_VERIFICATION)}"
            )
    elif verification is not None:
        raise ConsentError("guardian_verification applies only when a guardian consented")


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
    guardian_verification: str | None
    transfer_risk_explained: bool  # the participant was told the risks of copies going abroad
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
