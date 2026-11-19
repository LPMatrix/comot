"""Comot: an open consent and withdrawal layer for Nigerian-language voice data."""
from .bundle import verify_bundle
from .clock import ManualClock
from .consent import PURPOSES, USES, ConsentRecord
from .core import Comot, TrainingCheck, UseDecision
from .errors import ComotError, ConsentError, ConsentRefused, TrainingBlocked, UnknownObject
from .receipt import HmacSigner, render_receipt
from .withdrawal import WithdrawalPolicy

__version__ = "0.0.1"

__all__ = [
    "Comot",
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
