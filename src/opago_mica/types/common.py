"""
Common shared types used across the opago-MiCA-reference implementation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Compliance status
# ---------------------------------------------------------------------------

#: High-level compliance decision.
ComplianceStatus = Literal[
    "APPROVED",
    "PENDING_REVIEW",
    "REJECTED",
    "NOT_REQUIRED",
    "ERROR",
]

# ---------------------------------------------------------------------------
# Audit / compliance record
# ---------------------------------------------------------------------------


class AuditRecord(BaseModel):
    """A full audit record written after every payment attempt."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    timestamp: datetime
    payment_id: str
    sender_vasp: str
    receiver_vasp: str
    amount_sats: int
    currency: str
    travel_rule_transfer_id: str | None = None
    eidas_signed: bool
    compliance_status: ComplianceStatus
    protocols: list[str]
    #: SHA-256 of the IVMS101 payload (not the data itself)
    ivms101_hash: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

#: Risk category for a computed risk score.
RiskCategory = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class RiskFactor(BaseModel):
    """An individual contributing factor to the risk score."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    description: str
    weight: float


class RiskScore(BaseModel):
    """Risk score computed by the compliance engine."""

    model_config = ConfigDict(populate_by_name=True)

    #: 0 (lowest risk) – 100 (highest risk)
    score: float
    category: RiskCategory
    factors: list[RiskFactor]
    timestamp: datetime


# ---------------------------------------------------------------------------
# Sanctions
# ---------------------------------------------------------------------------

#: Match type for a sanctions hit.
MatchType = Literal["EXACT", "FUZZY", "PHONETIC"]


class SanctionsMatch(BaseModel):
    """A single sanctions match."""

    model_config = ConfigDict(populate_by_name=True)

    list_name: str
    entity_name: str
    #: Confidence score between 0 and 1.
    confidence: float
    match_type: MatchType


class SanctionsCheckResult(BaseModel):
    """Result of a sanctions-screening check."""

    model_config = ConfigDict(populate_by_name=True)

    screened: bool
    matches: list[SanctionsMatch]
    check_timestamp: datetime
    provider: str


# ---------------------------------------------------------------------------
# Wallet / transaction
# ---------------------------------------------------------------------------


class TokenBalance(BaseModel):
    """Balance for a single token (e.g. stablecoin)."""

    model_config = ConfigDict(populate_by_name=True)

    token_id: str
    token_symbol: str
    #: Big-decimal string representation.
    balance: str
    decimals: int


class WalletBalance(BaseModel):
    """Wallet balance snapshot."""

    model_config = ConfigDict(populate_by_name=True)

    satoshis: int
    token_balances: list[TokenBalance] | None = None
    last_updated: datetime


class PaymentResult(BaseModel):
    """Result of executing a Lightning payment."""

    model_config = ConfigDict(populate_by_name=True)

    success: bool
    payment_id: str
    preimage: str | None = None
    fee_sats: int | None = None
    error_code: str | None = None
    error_message: str | None = None


#: Transaction direction.
TransactionType = Literal["SEND", "RECEIVE"]

#: Transaction settlement status.
TransactionStatus = Literal["PENDING", "SETTLED", "FAILED"]


class TransactionRecord(BaseModel):
    """A historical transaction record."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: TransactionType
    amount_sats: int
    fee_sats: int | None = None
    counterparty_uma: str | None = None
    memo: str | None = None
    timestamp: datetime
    status: TransactionStatus
    payment_hash: str | None = None
    travel_rule_transfer_id: str | None = None


# ---------------------------------------------------------------------------
# Server config
# ---------------------------------------------------------------------------


class BaseServerConfig(BaseModel):
    """Common configuration shared between sender and receiver servers."""

    model_config = ConfigDict(populate_by_name=True)

    #: Hostname or IP to listen on.
    host: str
    #: TCP port.
    port: int
    #: Public domain (used in LNURL and UMA URLs).
    domain: str
    #: VASP display name.
    vasp_name: str


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

#: Possible health state values.
HealthState = Literal["ok", "degraded", "down"]


class HealthCheckResponse(BaseModel):
    """Health check response."""

    model_config = ConfigDict(populate_by_name=True)

    status: HealthState
    version: str
    timestamp: str
    services: dict[str, HealthState]
