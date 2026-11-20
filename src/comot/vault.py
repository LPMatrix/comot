"""Identity vault: the only place a name or phone number may live.

It is a separate SQLite file with its own key, so it can be backed up, locked
down and deleted on its own, and the consent database never holds identity.
Each record is encrypted with AES-256-GCM and bound to its participant id, so a
ciphertext copied onto another row fails to open.

Needs the optional ``cryptography`` package: ``pip install comot[vault]``.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from .clock import Clock, iso, system_clock

try:  # the core has no runtime dependencies; only the vault needs this
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None  # type: ignore[assignment,misc]
    InvalidTag = Exception  # type: ignore[assignment,misc]

KEY_BYTES = 32
FIELDS = ("name", "phone", "guardian_name", "guardian_phone")
_CHECK_ID = "__key_check__"


class VaultError(Exception):
    """The vault cannot be opened or a record cannot be read."""


def generate_key_file(path: str | Path) -> bytes:
    """Create a new random key file readable only by its owner. Refuses to overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    key = secrets.token_bytes(KEY_BYTES)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex() + "\n")
    return key


def load_key_file(path: str | Path) -> bytes:
    key = bytes.fromhex(Path(path).read_text().strip())
    if len(key) != KEY_BYTES:
        raise VaultError(f"{path}: key must be {KEY_BYTES} bytes")
    return key


class IdentityVault:
    """Encrypted storage of identity fields, keyed by pseudonymous participant id."""

    def __init__(self, path: str | Path, key: bytes, clock: Clock = system_clock):
        if AESGCM is None:
            raise VaultError("the identity vault needs the 'cryptography' package: pip install comot[vault]")
        if len(key) != KEY_BYTES:
            raise VaultError(f"key must be {KEY_BYTES} bytes")
        self._aead = AESGCM(key)
        self._clock = clock
        self.path = Path(path)
        new = not self.path.exists()
        self._db = sqlite3.connect(self.path, isolation_level=None)
        if new:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("PRAGMA secure_delete = ON")  # zero deleted rows instead of leaving them in free pages
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS identities ("
            " participant_id TEXT PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, updated_at TEXT NOT NULL)"
        )
        self._check_key()

    def _check_key(self) -> None:
        """A vault can only be opened with the key that created it."""
        row = self._db.execute("SELECT nonce, ciphertext FROM identities WHERE participant_id = ?", (_CHECK_ID,)).fetchone()
        if row is None:
            self._write(_CHECK_ID, {"ok": True})
            return
        try:
            self._open(_CHECK_ID, row[0], row[1])
        except VaultError:
            self._db.close()
            raise VaultError("wrong key for this vault") from None

    def _write(self, participant_id: str, data: dict[str, Any]) -> None:
        nonce = secrets.token_bytes(12)
        ciphertext = self._aead.encrypt(nonce, json.dumps(data, sort_keys=True).encode(), participant_id.encode())
        self._db.execute(
            "INSERT INTO identities (participant_id, nonce, ciphertext, updated_at) VALUES (?,?,?,?)"
            " ON CONFLICT(participant_id) DO UPDATE SET nonce = excluded.nonce,"
            " ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
            (participant_id, nonce, ciphertext, iso(self._clock())),
        )

    def _open(self, participant_id: str, nonce: bytes, ciphertext: bytes) -> dict[str, Any]:
        try:
            # The participant id is authenticated data: moving a ciphertext to another row fails.
            return json.loads(self._aead.decrypt(nonce, ciphertext, participant_id.encode()))
        except InvalidTag:
            raise VaultError(f"cannot decrypt the record for {participant_id}") from None

    # --------------------------------------------------------------------- API

    def put(self, participant_id: str, **fields: str | None) -> None:
        """Store or replace identity fields. Unknown field names are refused."""
        if participant_id == _CHECK_ID:
            raise VaultError("reserved id")
        unknown = set(fields) - set(FIELDS)
        if unknown:
            raise VaultError(f"unknown identity fields: {sorted(unknown)}; allowed: {list(FIELDS)}")
        self._write(participant_id, {k: v for k, v in fields.items() if v is not None})

    def get(self, participant_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT nonce, ciphertext FROM identities WHERE participant_id = ?", (participant_id,)
        ).fetchone()
        return None if row is None else self._open(participant_id, row[0], row[1])

    def delete(self, participant_id: str) -> bool:
        """Erase one person's identity. The consent records and audit log are untouched."""
        if participant_id == _CHECK_ID:
            return False
        cur = self._db.execute("DELETE FROM identities WHERE participant_id = ?", (participant_id,))
        return cur.rowcount > 0

    def ids(self) -> list[str]:
        rows = self._db.execute("SELECT participant_id FROM identities WHERE participant_id != ?", (_CHECK_ID,))
        return sorted(r[0] for r in rows)

    def close(self) -> None:
        self._db.close()
