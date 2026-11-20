"""Comot: an open consent and withdrawal layer for Nigerian-language voice data."""
from .access import DEFAULT_POLICY, OPERATIONS, AccessDenied, AccessPolicy, Actor
from .anchor import Anchor, FileAnchorSink, read_anchor_file
from .bundle import verify_bundle
from .clock import ManualClock
from .consent import PURPOSES, USES, ConsentRecord
from .core import Comot, TrainingCheck, UseDecision
from .errors import ComotError, ConsentError, ConsentRefused, StoreIntegrityError, TrainingBlocked, UnknownObject
from .receipt import HmacSigner, render_receipt
from .store import SqliteStore, StoreError
from .vault import IdentityVault, VaultError, generate_key_file, load_key_file
from .withdrawal import WithdrawalPolicy

__version__ = "0.1.0"

__all__ = [
    "AccessDenied",
    "AccessPolicy",
    "Actor",
    "DEFAULT_POLICY",
    "OPERATIONS",
    "Anchor",
    "Comot",
    "FileAnchorSink",
    "IdentityVault",
    "SqliteStore",
    "StoreError",
    "StoreIntegrityError",
    "VaultError",
    "generate_key_file",
    "load_key_file",
    "read_anchor_file",
    "ConsentRecord",
    "ConsentError",
    "ConsentRefused",
    "ComotError",
    "HmacSigner",
    "ManualClock",
    "PURPOSES",
    "TrainingBlocked",
    "TrainingCheck",
    "UnknownObject",
    "USES",
    "UseDecision",
    "WithdrawalPolicy",
    "render_receipt",
    "verify_bundle",
]
