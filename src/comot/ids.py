"""Random pseudonymous ids and short spoken participant codes."""
from __future__ import annotations

import secrets
from typing import Container


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def new_code(existing: Container[str], digits: int = 6) -> str:
    """A short numeric code a participant can say aloud or enter on USSD."""
    while True:
        code = "".join(secrets.choice("0123456789") for _ in range(digits))
        if code not in existing:
            return code
