"""
Travel Rule Provider — Abstract interface.

Defines the common contract that all Travel Rule protocol adapters must
satisfy (TRISA, TRP, TRUST, GTR, direct IVMS101).

All VASPs subject to MiCA Article 83 and the FATF Recommendation 16
("Travel Rule") must transmit originator and beneficiary information
alongside every crypto-asset transfer ≥ EUR 1,000.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from opago_mica.types.ivms101 import IVMS101Payload

# ---------------------------------------------------------------------------
# Protocol identifiers
# ---------------------------------------------------------------------------

TravelRuleProtocol = Literal["trisa", "trp", "trust", "gtr", "direct"]

# ---------------------------------------------------------------------------
# Transfer model
# ---------------------------------------------------------------------------

TransferStatus = Literal["pending", "accepted", "rejected", "expired"]
TransferDirection = Literal["outgoing", "incoming"]


class TravelRuleTransfer(BaseModel):
    """Represents a single travel-rule exchange across any protocol."""

    model_config = ConfigDict(populate_by_name=True)

    #: Unique identifier for this travel-rule exchange (UUID v4).
    transfer_id: str
    #: Protocol used for this transfer.
    protocol: TravelRuleProtocol
    #: IVMS101 payload attached to this transfer.
    ivms101: IVMS101Payload
    #: Current state of the transfer.
    status: TransferStatus
    created_at: datetime
    updated_at: datetime
    #: VASP identifier of the counterparty (domain or DID).
    counterparty_vasp: str
    #: On-chain transaction hash once known.
    tx_hash: str | None = None
    #: Asset identifier, e.g. "BTC", "ETH", "USDC".
    asset: str
    #: Amount as a decimal string, e.g. "0.012345".
    amount: str
    direction: TransferDirection
    #: Protocol-specific metadata (kept as opaque record).
    protocol_metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Counterparty discovery
# ---------------------------------------------------------------------------


class CounterpartyInfo(BaseModel):
    """Information about a counterparty VASP discovered via a protocol."""

    model_config = ConfigDict(populate_by_name=True)

    #: Internal VASP identifier used by the protocol.
    vasp_id: str
    #: Human-readable name of the VASP.
    name: str
    #: Internet domain of the VASP, e.g. "exchange.example.com".
    domain: str
    #: Protocols the counterparty advertises support for.
    supported_protocols: list[TravelRuleProtocol]
    #: PEM-encoded public key for encrypting IVMS101 data.
    public_key: str | None = None
    #: API endpoint URL for travel-rule messages.
    endpoint: str | None = None


# ---------------------------------------------------------------------------
# Provider input / output models
# ---------------------------------------------------------------------------


class SendTransferParams(BaseModel):
    """Parameters for initiating an outgoing travel-rule transfer."""

    model_config = ConfigDict(populate_by_name=True)

    ivms101: IVMS101Payload
    counterparty: CounterpartyInfo
    tx_hash: str
    asset: str
    amount: str


class TransferResponse(BaseModel):
    """Accept/reject response from the beneficiary side."""

    model_config = ConfigDict(populate_by_name=True)

    accepted: bool
    #: Beneficiary IVMS101 payload returned on acceptance (protocol-dependent).
    beneficiary_ivms101: IVMS101Payload | None = None
    #: Human-readable reason when rejecting.
    rejection_reason: str | None = None


class ValidationResult(BaseModel):
    """Result of validating an IVMS101 payload against a protocol's rules."""

    model_config = ConfigDict(populate_by_name=True)

    valid: bool
    errors: list[str]


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class TravelRuleProvider(ABC):
    """
    Every protocol adapter implements this abstract base class.

    Subclasses must define a class-level ``protocol`` attribute matching
    the :data:`TravelRuleProtocol` literal.
    """

    #: Identifies which protocol this adapter implements.
    protocol: TravelRuleProtocol

    @abstractmethod
    async def initialize(self) -> None:
        """
        Boot the provider: verify credentials, connect to directories / registries.
        Must be called once before any other method.
        """

    @abstractmethod
    async def discover_counterparty(self, vasp_domain: str) -> CounterpartyInfo:
        """
        Discover capabilities of a counterparty VASP.

        :param vasp_domain: Internet domain of the counterparty, e.g. "kraken.com".
        """

    @abstractmethod
    async def send_transfer(self, params: SendTransferParams) -> TravelRuleTransfer:
        """
        Originator side — send IVMS101 data to the beneficiary VASP.

        :param params: Transfer parameters including IVMS101 payload, counterparty
                       info, transaction hash, asset, and amount.
        """

    @abstractmethod
    async def handle_incoming_transfer(self, raw_data: Any) -> TravelRuleTransfer:
        """
        Beneficiary side — receive and parse raw incoming travel-rule data.

        :param raw_data: Protocol-specific raw message (HTTP body, gRPC message, …).
        """

    @abstractmethod
    async def respond_to_transfer(
        self,
        transfer_id: str,
        response: TransferResponse,
    ) -> TravelRuleTransfer:
        """
        Beneficiary side — accept or reject a pending incoming transfer.

        :param transfer_id: ID of the transfer to respond to.
        :param response:    Accept/reject decision with optional beneficiary IVMS101.
        """

    @abstractmethod
    async def get_transfer_status(self, transfer_id: str) -> TravelRuleTransfer:
        """
        Poll the current state of a transfer.

        :param transfer_id: ID of the transfer to retrieve.
        """

    @abstractmethod
    def validate_payload(self, payload: IVMS101Payload) -> ValidationResult:
        """
        Validate an IVMS101 payload against this protocol's requirements.
        Returns all validation errors so callers can surface them.

        :param payload: IVMS101 payload to validate.
        """
