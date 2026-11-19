"""Language packs: scripts, audio and teach-back questions as data.

Adding a language means adding a pack, not changing code. A pack only counts
as releasable when the review group has signed it off and every item has the
approved text and the native-speaker audio.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .consent import USES


class PackError(ValueError):
    """A language pack is malformed."""


@dataclass
class LanguagePack:
    language: str
    pack_version: str
    status: str  # "draft_unreviewed" | "in_review" | "signed_off"
    signed_off_by: list[str]
    items: list[dict[str, Any]]

    def item_ids(self) -> list[str]:
        return [i["id"] for i in self.items]

    def missing_for_release(self) -> list[str]:
        """Reasons this pack cannot ship yet. Empty means it can."""
        reasons: list[str] = []
        if self.status != "signed_off":
            reasons.append(f"status is {self.status!r}, not 'signed_off'")
        if not self.signed_off_by:
            reasons.append("no reviewers recorded")
        for item in self.items:
            if not item.get("text"):
                reasons.append(f"{item['id']}: no approved text")
            if not item.get("audio"):
                reasons.append(f"{item['id']}: no native-speaker audio")
        return reasons

    @property
    def releasable(self) -> bool:
        return not self.missing_for_release()


def load_pack(path: str | Path) -> LanguagePack:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    try:
        pack = LanguagePack(
            language=raw["language"],
            pack_version=raw["pack_version"],
            status=raw["status"],
            signed_off_by=list(raw["review"]["signed_off_by"]),
            items=list(raw["items"]),
        )
    except KeyError as e:
        raise PackError(f"missing field {e}") from None
    _validate(pack)
    return pack


def _validate(pack: LanguagePack) -> None:
    ids = pack.item_ids()
    if len(ids) != len(set(ids)):
        raise PackError("item ids must be unique")
    for item in pack.items:
        if item.get("kind") not in ("explain", "choice", "teach_back"):
            raise PackError(f"{item.get('id')}: kind must be explain, choice or teach_back")
        if not item.get("source_en"):
            raise PackError(f"{item['id']}: source_en is required")
    choices = [i["use"] for i in pack.items if i["kind"] == "choice"]
    if choices != list(USES):
        raise PackError(f"choices must cover {list(USES)} in that order, got {choices}")
    if "explain.model_limit" not in ids:
        raise PackError("the pack must explain the model limit (explain.model_limit)")
    # The participant must hear the model limit before they choose on training.
    if ids.index("explain.model_limit") > ids.index("choice.model_training"):
        raise PackError("explain.model_limit must come before choice.model_training")
    if not 3 <= sum(1 for i in pack.items if i["kind"] == "teach_back") <= 5:
        raise PackError("a pack needs 3 to 5 teach-back questions")
