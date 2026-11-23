"""Signing keys for receipts and exports.

Two kinds of signer, and a key ring so a key can be replaced without breaking
anything signed earlier:

* ``HmacSigner``: one shared secret. Only someone who holds it can verify, so it
  suits a single trusted party.
* ``Ed25519Signer``: a private key signs, and anyone with the public key verifies.
  This is the one to use when an outside auditor must check receipts and exports
  without being trusted with a secret. It needs the optional ``cryptography``
  package (``pip install comot[vault]``).
* ``KeyRing``: signs with the current key and verifies against the current and
  every retired key, which is what rotation needs.

A signature reads ``<algorithm>:<key id>:<hex>``. The key id says which key made
it, so a verifier picks the right one and a rotated key never makes an older
receipt fail.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Iterable, Protocol

from .hashing import sha256_hex

try:  # the core has no runtime dependencies; only Ed25519 needs this
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]

ALG_HMAC = "hmac-sha256"
ALG_ED25519 = "ed25519"
_PRIVATE = "ed25519-private:"  # a private key file reads ed25519-private:<hex>; a public key reads ed25519:<hex>


class SigningError(Exception):
    """A key cannot be loaded or used."""


class Verifier(Protocol):
    key_id: str

    @property
    def key_ids(self) -> list[str]: ...

    def verify(self, data: bytes, signature: str) -> bool: ...


def _key_id(algorithm: str, material: bytes) -> str:
    return sha256_hex(f"comot-key-id:{algorithm}:".encode() + material)[:16]


def split_signature(signature: str) -> tuple[str, str, str] | None:
    """(algorithm, key id, hex) or None when the string is not in the signed format."""
    parts = signature.split(":") if isinstance(signature, str) else []
    return (parts[0], parts[1], parts[2]) if len(parts) == 3 and all(parts) else None


def _need_ed25519() -> None:
    if Ed25519PrivateKey is None:
        raise SigningError("Ed25519 signatures need the 'cryptography' package: pip install comot[vault]")


def _write_new(path: str | Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # readable only by its owner
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")


class HmacSigner:
    """Signs with HMAC-SHA256. Only someone holding the key can verify."""

    algorithm = ALG_HMAC
    can_sign = True

    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(32)
        if len(self.key) < 16:
            raise SigningError("an HMAC key must be at least 16 bytes")

    @property
    def key_id(self) -> str:
        return _key_id(ALG_HMAC, self.key)

    @property
    def key_ids(self) -> list[str]:
        return [self.key_id]

    @classmethod
    def from_file(cls, path: str | Path, *, create: bool = False) -> "HmacSigner":
        """Load a hex key file. With ``create`` a missing file is made, readable only by its owner."""
        path = Path(path)
        if not path.exists():
            if not create:
                raise FileNotFoundError(f"no key file at {path}")
            _write_new(path, secrets.token_bytes(32).hex())
        text = path.read_text().strip()
        if text.startswith("ed25519"):
            raise SigningError(f"{path} holds an Ed25519 key; load it with load_signer()")
        key = bytes.fromhex(text)
        if len(key) < 16:
            raise SigningError(f"{path}: key is too short")
        return cls(key)

    def sign(self, data: bytes) -> str:
        return f"{ALG_HMAC}:{self.key_id}:{hmac.new(self.key, data, hashlib.sha256).hexdigest()}"

    def verify(self, data: bytes, signature: str) -> bool:
        parts = split_signature(signature)
        if parts is None or parts[0] != ALG_HMAC or parts[1] != self.key_id:
            return False
        return hmac.compare_digest(hmac.new(self.key, data, hashlib.sha256).hexdigest(), parts[2])


class Ed25519Verifier:
    """Checks Ed25519 signatures with a public key. It cannot sign."""

    algorithm = ALG_ED25519
    can_sign = False

    def __init__(self, public_key: bytes):
        _need_ed25519()
        if len(public_key) != 32:
            raise SigningError("an Ed25519 public key is 32 bytes")
        self.public_key = public_key
        self._key = Ed25519PublicKey.from_public_bytes(public_key)

    @classmethod
    def from_text(cls, text: str) -> "Ed25519Verifier":
        """Read ``ed25519:<hex>``, as printed by ``comot pubkey``."""
        text = text.strip()
        if not text.startswith(ALG_ED25519 + ":"):
            raise SigningError("a public key reads ed25519:<64 hex characters>")
        try:
            return cls(bytes.fromhex(text.split(":", 1)[1]))
        except ValueError:
            raise SigningError("a public key reads ed25519:<64 hex characters>") from None

    @property
    def key_id(self) -> str:
        return _key_id(ALG_ED25519, self.public_key)

    @property
    def key_ids(self) -> list[str]:
        return [self.key_id]

    @property
    def public_key_text(self) -> str:
        return f"{ALG_ED25519}:{self.public_key.hex()}"

    def verify(self, data: bytes, signature: str) -> bool:
        parts = split_signature(signature)
        if parts is None or parts[0] != ALG_ED25519 or parts[1] != self.key_id:
            return False
        try:
            self._key.verify(bytes.fromhex(parts[2]), data)
        except (InvalidSignature, ValueError):
            return False
        return True


class Ed25519Signer(Ed25519Verifier):
    """Signs with a private key. The public half, shared freely, lets anyone verify."""

    can_sign = True

    def __init__(self, seed: bytes | None = None):
        _need_ed25519()
        seed = seed or secrets.token_bytes(32)
        if len(seed) != 32:
            raise SigningError("an Ed25519 private key is 32 bytes")
        self._seed = seed
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        super().__init__(self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    @classmethod
    def from_file(cls, path: str | Path, *, create: bool = False) -> "Ed25519Signer":
        path = Path(path)
        if not path.exists():
            if not create:
                raise FileNotFoundError(f"no key file at {path}")
            _write_new(path, f"{_PRIVATE}{secrets.token_bytes(32).hex()}")
        text = path.read_text().strip()
        if not text.startswith(_PRIVATE):
            raise SigningError(f"{path} is not an Ed25519 private key file")
        try:
            return cls(bytes.fromhex(text.split(":", 1)[1]))
        except ValueError:
            raise SigningError(f"{path}: not a valid Ed25519 key") from None

    def verifier(self) -> Ed25519Verifier:
        """The public half, safe to hand to an auditor."""
        return Ed25519Verifier(self.public_key)

    def sign(self, data: bytes) -> str:
        return f"{ALG_ED25519}:{self.key_id}:{self._private.sign(data).hex()}"


class KeyRing:
    """Signs with the current key and verifies with the current and every retired one.

    To rotate, make a new key, open the store with ``KeyRing(new, retired=[old])``,
    and keep the old key (only its public half for Ed25519) from then on.
    """

    can_sign = True

    def __init__(self, current: HmacSigner | Ed25519Signer, retired: Iterable[Verifier] = ()):
        if not getattr(current, "can_sign", False):
            raise SigningError("the current key must be able to sign")
        self.current = current
        self._by_id: dict[str, Verifier] = {}
        for key in [*retired, current]:  # current last, so it wins a clash
            self._by_id[key.key_id] = key

    @property
    def key_id(self) -> str:
        return self.current.key_id

    @property
    def key_ids(self) -> list[str]:
        return [self.key_id, *[k for k in self._by_id if k != self.key_id]]

    @property
    def algorithm(self) -> str:
        return self.current.algorithm

    def sign(self, data: bytes) -> str:
        return self.current.sign(data)

    def verify(self, data: bytes, signature: str) -> bool:
        parts = split_signature(signature)
        key = self._by_id.get(parts[1]) if parts else None
        return key is not None and key.verify(data, signature)


def generate_signer_file(path: str | Path, algorithm: str = ALG_ED25519) -> HmacSigner | Ed25519Signer:
    """Create a new signing key file, readable only by its owner. Refuses to overwrite."""
    if Path(path).exists():
        raise FileExistsError(f"{path} already exists; not overwriting a key")
    if algorithm == ALG_ED25519:
        return Ed25519Signer.from_file(path, create=True)
    if algorithm in ("hmac", ALG_HMAC):
        return HmacSigner.from_file(path, create=True)
    raise SigningError(f"unknown algorithm {algorithm!r}; use ed25519 or hmac")


def load_signer(path: str | Path) -> HmacSigner | Ed25519Signer:
    """Load a key file of either kind. A plain hex file is HMAC, ``ed25519-private:<hex>`` is Ed25519."""
    text = Path(path).read_text().strip()
    return Ed25519Signer.from_file(path) if text.startswith(_PRIVATE) else HmacSigner.from_file(path)


def load_verifier(source: str | Path) -> Verifier:
    """A verifier from a public key written as ``ed25519:<hex>``, or a file holding one or a private key."""
    text = str(source).strip()
    if text.startswith(ALG_ED25519 + ":"):
        return Ed25519Verifier.from_text(text)
    path = Path(text)
    if not path.exists():
        raise SigningError(f"{text!r} is neither a public key (ed25519:<hex>) nor a key file")
    content = path.read_text().strip()
    if content.startswith(_PRIVATE):
        return Ed25519Signer.from_file(path).verifier()  # only the public half is used
    if content.startswith(ALG_ED25519 + ":"):
        return Ed25519Verifier.from_text(content)
    return HmacSigner.from_file(path)
