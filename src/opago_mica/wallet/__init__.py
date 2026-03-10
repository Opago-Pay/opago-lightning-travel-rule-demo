"""
opago_mica.wallet — Wallet integration package.

Re-exports SparkWalletManager, WalletFactory, error classes, and
configuration models for convenient top-level access.
"""

from __future__ import annotations

from opago_mica.wallet.spark_wallet import (
    InsufficientBalanceError,
    InvoiceResult,
    PaymentFailedError,
    PaymentResult,
    SparkWalletManager,
    TransactionRecord,
    WalletBalance,
    WalletConfig,
    WalletNotInitializedError,
    wallet_config_from_env,
)
from opago_mica.wallet.wallet_factory import WalletFactory

__all__ = [
    # Spark wallet manager
    "SparkWalletManager",
    # Configuration
    "WalletConfig",
    # Errors
    "WalletNotInitializedError",
    "PaymentFailedError",
    "InsufficientBalanceError",
    # Pydantic models
    "PaymentResult",
    "InvoiceResult",
    "WalletBalance",
    "TransactionRecord",
    "wallet_config_from_env",
    # Factory
    "WalletFactory",
]
