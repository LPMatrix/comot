"""Exceptions raised by Comot."""
from __future__ import annotations


class ComotError(Exception):
    """Base class for all Comot errors."""


class ConsentError(ComotError):
    """A consent record is invalid or cannot be created."""


class UnknownObject(ComotError):
    """An id does not refer to anything Comot knows about."""


class ConsentRefused(ComotError):
    """A requested use is not allowed by the consent behind the parents.

    ``blockers`` holds (artifact_id, reason) pairs. Ids are pseudonymous.
    """

    def __init__(self, message: str, blockers: list[tuple[str, str]]):
        super().__init__(message)
        self.blockers = blockers


class TrainingBlocked(ConsentRefused):
    """A training run includes items that may not be used for training."""


class StoreIntegrityError(ComotError):
    """A store failed its integrity checks when opened, so Comot refuses to use it."""

    def __init__(self, problems: list[str]):
        super().__init__("store failed integrity checks: " + "; ".join(problems[:5]) + (" ..." if len(problems) > 5 else ""))
        self.problems = problems
