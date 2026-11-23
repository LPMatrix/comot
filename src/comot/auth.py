"""Authentication: turning a bearer token into an ``Actor``.

Comot's access policy decides what an actor may do. This module is how a network
caller becomes an actor in the first place. A token file lists, for each token,
the actor it stands for and that actor's roles. Only the SHA-256 of a token is
stored, so the file never holds a usable secret. Tokens are 256 bits of
randomness, so a plain hash is enough: there is nothing to guess.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

from .access import Actor
from .clock import Clock, iso, parse, system_clock

PREFIX = "cmt_"


class AuthError(Exception):
    """The token file is malformed or a request cannot be made."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return PREFIX + secrets.token_urlsafe(32)


class TokenAuthenticator:
    def __init__(self, entries: list[dict[str, Any]], clock: Clock = system_clock):
        for e in entries:
            if not isinstance(e.get("id"), str) or not e["id"].strip():
                raise AuthError("every token needs an actor id")
            if not isinstance(e.get("sha256"), str) or len(e["sha256"]) != 64:
                raise AuthError(f"token for {e['id']!r} needs a sha256")
            if not isinstance(e.get("roles"), list):
                raise AuthError(f"token for {e['id']!r} needs a list of roles")
        self._entries = entries
        self._clock = clock
        self._path: Path | None = None
        self._stamp: tuple[int, int] | None = None
        self.error: str | None = None  # why the file could not be re-read, if it could not

    @classmethod
    def load(cls, path: str | Path, clock: Clock = system_clock) -> "TokenAuthenticator":
        """Read a token file. It is read again whenever it changes, so a revoked token stops working at once."""
        auth = cls(cls._read_entries(Path(path)), clock)
        auth._path = Path(path)
        auth._stamp = auth._stat()
        return auth

    @staticmethod
    def _read_entries(path: Path) -> list[dict[str, Any]]:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        if raw.get("version") != 1 or not isinstance(raw.get("tokens"), list):
            raise AuthError(f"{path}: not a Comot token file")
        return raw["tokens"]

    def _stat(self) -> tuple[int, int] | None:
        try:
            st = os.stat(self._path)  # type: ignore[arg-type]
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _refresh(self) -> None:
        if self._path is None or self._stat() == self._stamp:
            return
        self._stamp = self._stat()
        try:
            self._entries = self._read_entries(self._path)
            TokenAuthenticator(self._entries)  # the same checks as at the start
            self.error = None
        except (OSError, ValueError, AuthError) as e:
            self._entries = []  # fail closed: a damaged file lets nobody in
            self.error = f"{self._path}: {e}"

    def authenticate(self, authorization: str | None) -> Actor | None:
        """The actor for an ``Authorization: Bearer <token>`` header, or None. Never raises on bad input."""
        self._refresh()
        if not authorization or not authorization.startswith("Bearer "):
            return None
        presented = hash_token(authorization[len("Bearer "):].strip())
        found: dict[str, Any] | None = None
        for e in self._entries:  # look at every entry, so timing does not show which one matched
            if hmac.compare_digest(e["sha256"], presented):
                found = e
        if found is None:
            return None
        if found.get("expires") and self._clock() >= parse(found["expires"]):
            return None
        return Actor(found["id"], set(found["roles"]))


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "tokens": []}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if raw.get("version") != 1:
        raise AuthError(f"{path}: not a Comot token file")
    return raw


def _write(path: Path, raw: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # readable only by its owner
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def issue_token(
    path: str | Path, actor_id: str, roles: list[str], *, days: int | None = None, clock: Clock = system_clock
) -> str:
    """Make a token for an actor and add its hash to the file. The token is returned once and never stored."""
    if not actor_id.strip() or not roles:
        raise AuthError("a token needs an actor id and at least one role")
    path = Path(path)
    raw = _read(path)
    token = new_token()
    now = clock()
    raw["tokens"].append(
        {
            "id": actor_id,
            "roles": sorted(set(roles)),
            "sha256": hash_token(token),
            "created": iso(now),
            "expires": iso(now + timedelta(days=days)) if days else None,
        }
    )
    _write(path, raw)
    return token


def revoke_tokens(path: str | Path, actor_id: str) -> int:
    """Remove every token for an actor. Returns how many were removed."""
    path = Path(path)
    raw = _read(path)
    kept = [t for t in raw["tokens"] if t["id"] != actor_id]
    removed = len(raw["tokens"]) - len(kept)
    raw["tokens"] = kept
    _write(path, raw)
    return removed
