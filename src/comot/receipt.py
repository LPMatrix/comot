"""Withdrawal receipts.

A receipt is structured data first. Rendering it to words is the job of a
language pack's templates, so the same receipt can be read in Pidgin, Hausa or
Yoruba once those packs are signed off. English templates ship as the source.

Receipt text never names the study or the health topic, so a shared
phone reveals nothing.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .hashing import canonical

# What stays true whatever was deleted. Honest by default.
LIMIT_MODEL_WEIGHTS = "model_weights_not_erasable"
LIMIT_PUBLISHED_RESULTS = "published_results_unchanged"


class HmacSigner:
    """Signs receipts and exports with HMAC-SHA256.

    Current limitation: HMAC proves integrity only to someone who holds the key.
    Before an outside auditor can verify alone, swap in an asymmetric signer
    with the same two methods.
    """

    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(32)

    @classmethod
    def from_file(cls, path: str | Path, *, create: bool = False) -> "HmacSigner":
        """Load a hex key file. With ``create`` a missing file is made, readable only by its owner."""
        path = Path(path)
        if not path.exists():
            if not create:
                raise FileNotFoundError(f"no key file at {path}")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_bytes(32).hex() + "\n")
        key = bytes.fromhex(path.read_text().strip())
        if len(key) < 16:
            raise ValueError(f"{path}: key is too short")
        return cls(key)

    def sign(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(data), signature)


@dataclass
class Receipt:
    receipt_id: str
    withdrawal_id: str
    issued_at: str
    scope: list[str]
    items: list[dict[str, Any]]
    limits: list[str]
    signature: str = ""

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature")
        return d

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# English source templates. Keys are "<kind>.<status>"; {thing} and {due} are filled in.
EN_TEMPLATES: dict[str, str] = {
    "delete.done": "A {thing} has been deleted.",
    "delete.pending": "A {thing} will be deleted by {due}.",
    "exclude.done": "Your recording has been taken out of a dataset.",
    "exclude.pending": "Your recording will be taken out of a dataset by {due}.",
    "retire.done": "A model that learned from your recording has been retired.",
    "retire.pending": (
        "Your recording will not be used for any model trained from now on. "
        "A model that already learned from it will be replaced by {due}."
    ),
    "retrain.done": "The part of a model that learned from your recording has been retrained.",
    "retrain.pending": "The part of a model that learned from your recording will be retrained by {due}.",
    "notify.done": "Another team that held a copy has confirmed it removed the copy.",
    "notify.pending": "Another team that holds a copy has been told to remove it. They must confirm by {due}.",
    LIMIT_MODEL_WEIGHTS: "We cannot take your recording out of a model that was already trained.",
    LIMIT_PUBLISHED_RESULTS: "Results already published, such as statistics, cannot be changed. They do not identify you.",
    "overdue_suffix": " This is late. The board has been told.",
    "nothing": "No copies of your recording were affected.",
}

THINGS_EN: dict[str, str] = {
    "recording": "copy of your recording",
    "transcript": "written copy of your recording",
    "clip": "short clip of your recording",
    "features": "processed data file made from your recording",
}


def render_receipt(
    receipt: Receipt | Mapping[str, Any],
    templates: Mapping[str, str] = EN_TEMPLATES,
    things: Mapping[str, str] = THINGS_EN,
) -> str:
    """Render a receipt as plain sentences using one language's templates."""
    data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
    lines: list[str] = []
    for item in data["items"]:
        status = "done" if item["status"] == "done" else "pending"
        text = templates[f"{item['kind']}.{status}"].format(
            thing=things.get(item["artifact_type"], item["artifact_type"]),
            due=item["due_at"][:10],
        )
        if item["status"] == "overdue":
            text += templates["overdue_suffix"]
        lines.append(text)
    if not data["items"]:
        lines.append(templates["nothing"])
    lines.extend(templates[code] for code in data["limits"])
    return "\n".join(lines)


def sign_body(signer: HmacSigner, body: Mapping[str, Any]) -> str:
    return signer.sign(canonical(body))
