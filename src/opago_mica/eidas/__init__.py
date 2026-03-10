"""
eIDAS wallet bridge package.

Re-exports :class:`EIDASWalletBridge` and associated Pydantic models.
"""

from __future__ import annotations

from opago_mica.eidas.eidas_wallet import (
    ConsentResult,
    EIDASWalletBridge,
    VerificationResult,
)

__all__ = [
    "ConsentResult",
    "EIDASWalletBridge",
    "VerificationResult",
]
