"""Who may do what.

Comot does not authenticate anyone. It cannot know who is really calling, so
the caller (your service, your pipeline) passes in an ``Actor`` it has already
authenticated. Comot only enforces what that actor's roles allow, and logs every
refusal.

The role table is data, in the spirit of "rules the community can read": a
board can open the JSON, read it, and change it. ``DEFAULT_POLICY`` is a
starting point. Roles are just names, so a deployment can add its own, for
example a ``withdrawal_line`` role that may only ``withdraw``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import ComotError
from .hashing import hash_obj

# Every operation a policy can grant. Keeping the list closed means a typo in a
# policy file is an error and not a silently useless grant.
OPERATIONS: tuple[str, ...] = (
    "create_participant",
    "record_consent",
    "register_recording",
    "register",
    "check_use",
    "check_training_run",
    "withdraw",
    "view_actions",
    "complete_action",
    "escalate_overdue",
    "issue_receipt",
    "anchor",
    "verify_integrity",
    "export_bundle",
    "store_identity",
    "read_identity",
    "delete_identity",
)

DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "roles": {
        # In the field: records consent, takes withdrawals, keeps contact details.
        "health_worker": [
            "create_participant",
            "record_consent",
            "register_recording",
            "withdraw",
            "issue_receipt",
            "view_actions",
            "store_identity",
        ],
        # Builds datasets and models, and carries out withdrawal actions.
        "data_team": [
            "register_recording",
            "register",
            "check_use",
            "check_training_run",
            "view_actions",
            "complete_action",
        ],
        # Oversight: sees whether withdrawals are being carried out.
        "board": ["view_actions", "escalate_overdue", "export_bundle"],
        # Checks the system from outside. No access to who anyone is.
        "auditor": ["view_actions", "verify_integrity", "export_bundle"],
        # Owns identity and the integrity of the record.
        "dpo": [
            "withdraw",
            "issue_receipt",
            "view_actions",
            "escalate_overdue",
            "anchor",
            "verify_integrity",
            "export_bundle",
            "read_identity",
            "delete_identity",
        ],
    },
}


class AccessDenied(ComotError):
    def __init__(self, message: str, *, actor_id: str, operation: str):
        super().__init__(message)
        self.actor_id = actor_id
        self.operation = operation


@dataclass(frozen=True)
class Actor:
    """Someone your system has already authenticated, and the roles it gave them."""

    id: str
    roles: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("an actor needs a non-empty id")
        roles = frozenset([self.roles] if isinstance(self.roles, str) else self.roles)
        object.__setattr__(self, "roles", roles)


class AccessPolicy:
    """A table from role to the operations it may perform."""

    def __init__(self, roles: Mapping[str, Iterable[str]]):
        table: dict[str, frozenset[str]] = {}
        for role, ops in roles.items():
            granted = frozenset(ops)
            unknown = sorted(granted - set(OPERATIONS))
            if unknown:
                raise ValueError(f"role {role!r} grants unknown operations {unknown}; known: {list(OPERATIONS)}")
            table[role] = granted
        self.roles = table

    @classmethod
    def default(cls) -> "AccessPolicy":
        return cls.from_dict(DEFAULT_POLICY)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "AccessPolicy":
        if d.get("version") != 1:
            raise ValueError("unsupported access policy version")
        roles = d.get("roles")
        if not isinstance(roles, Mapping) or not roles:
            raise ValueError("an access policy needs a non-empty 'roles' table")
        for role, ops in roles.items():
            if isinstance(ops, str) or not isinstance(ops, (list, tuple)):
                raise ValueError(f"role {role!r} must list its operations")
        return cls(roles)

    @classmethod
    def load(cls, path: str | Path) -> "AccessPolicy":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, "roles": {r: sorted(ops) for r, ops in sorted(self.roles.items())}}

    def hash(self) -> str:
        """Identifies this exact table, so the audit log can show when it changed."""
        return hash_obj(self.to_dict())

    def allows(self, actor: Actor, operation: str) -> bool:
        if operation not in OPERATIONS:
            raise ValueError(f"unknown operation {operation!r}")
        return any(operation in self.roles.get(role, ()) for role in actor.roles)
