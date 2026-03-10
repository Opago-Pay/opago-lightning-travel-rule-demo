"""
Extended UMA Types for MiCA Compliance.

Extends the Universal Money Address (UMA) protocol with MiCA-specific fields
for KYC data, Travel Rule (EU TFR / IVMS101), and eIDAS signatures.

Reference UMA spec: https://github.com/uma-universal-money-address/uma-spec
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

from opago_mica.types.ivms101 import IVMS101Payload

# ---------------------------------------------------------------------------
# KYC status
# ---------------------------------------------------------------------------


class KycStatus(StrEnum):
    """KYC verification status values."""

    UNKNOWN = "UNKNOWN"
    NOT_VERIFIED = "NOT_VERIFIED"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAIL = "FAIL"


# ---------------------------------------------------------------------------
# UMA Payer Data
# ---------------------------------------------------------------------------


class UMAComplianceData(BaseModel):
    """MiCA compliance data attached to UMA payer / payee data objects."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: KYC verification status at the sending VASP.
    kyc_status: KycStatus

    #: JWS (ES256) signature over the canonical pay request body.
    #: Provides non-repudiation for the sending VASP.
    signature: str | None = None

    #: Random nonce to prevent replay attacks.
    signature_nonce: str | None = None

    #: ISO 8601 timestamp when the signature was created.
    signature_timestamp: str | None = None

    #: Encrypted IVMS101 Travel Rule payload (JWE compact serialisation).
    #: Encrypted with the beneficiary VASP's public encryption key using
    #: ECDH-ES+A256KW / A256GCM.
    encrypted_travel_rule_info: str | None = None

    #: Human-readable indicator of the travel rule format used.
    #: Typically 'ivms101-2020' for standard IVMS101.
    travel_rule_info: str | None = Field(default=None, alias="travelRuleFormat")

    #: UTXOs / Lightning UTXOs used to fund this transaction (optional).
    utxos: list[str] | None = None

    #: Lightning node public key of the sending VASP (33 bytes, hex-encoded).
    node_public_key: str | None = Field(default=None, alias="nodePubKey")

    #: UTXO completion callback defined by UMA.
    utxo_callback: str | None = Field(default=None, alias="utxoCallback")

    #: eIDAS verifiable presentation (if sender opted-in).
    #: Base64url-encoded Verifiable Credential JSON.
    eidas_credential_presentation: str | None = None


class UMAPayerData(BaseModel):
    """Standard UMA payer data, extended with MiCA compliance fields."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: UMA address of the sender: $user@vasp.domain.
    identifier: str
    #: Full legal name (for KYC).
    name: str | None = None
    #: Email address.
    email: str | None = None
    #: MiCA-specific compliance data.
    compliance_data: UMAComplianceData | None = Field(default=None, alias="compliance")


class EIDASAttestation(BaseModel):
    """Transaction-bound eIDAS evidence attached to a pay request."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    payment_reference: str
    signature: str
    signing_certificate: str | None = None
    signed_at: str | None = None
    signature_level: str | None = None


# ---------------------------------------------------------------------------
# UMA Pay Request (sender → receiver VASP)
# ---------------------------------------------------------------------------

#: Supported travel rule data formats.
TravelRuleFormat = Literal["ivms101", "ivms101-2020", "custom"]


class UMAPayRequest(BaseModel):
    """
    UMA pay request with MiCA extensions, sent from the sending VASP to
    the receiving VASP after lnurlp lookup.
    """

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: UMA amount string on the wire.
    #: For Lightning in this demo, plain numeric values represent millisatoshis.
    amount: int | str

    #: Optional UMA receiving-currency hint from UMAD-05.
    convert: str | None = None

    #: Payer data including compliance fields.
    payer_data: UMAPayerData

    #: Travel rule data format used in encrypted_travel_rule_info.
    #: Defaults to 'ivms101'.
    travel_rule_format: TravelRuleFormat | None = None

    #: Fields requested from the beneficiary in the pay response.
    payee_data: dict[str, dict[str, bool]] | None = None

    #: Optional comment / memo attached to the payment.
    comment: str | None = None

    #: Identifier returned by the out-of-band travel rule exchange.
    travel_rule_transfer_id: str | None = None

    #: JSON-serialised Verifiable Presentation from the sender's eIDAS wallet.
    eidas_presentation: str | None = None

    #: Qualified signature metadata over the pre-invoice payment reference.
    eidas_attestation: EIDASAttestation | None = None

    #: UMA protocol version.
    uma_version: str | None = None

    @model_validator(mode="after")
    def _synchronise_eidas_presentation(self) -> UMAPayRequest:
        compliance = self.payer_data.compliance_data if self.payer_data else None
        inline_presentation = self.eidas_presentation
        compliance_presentation = (
            compliance.eidas_credential_presentation if compliance is not None else None
        )

        if (
            inline_presentation is not None
            and compliance_presentation is not None
            and inline_presentation != compliance_presentation
        ):
            raise ValueError(
                "eIDAS presentation must not differ between top-level and compliance data fields"
            )

        if compliance is not None and inline_presentation is not None:
            compliance.eidas_credential_presentation = inline_presentation
        elif compliance is not None and compliance_presentation is not None:
            self.eidas_presentation = compliance_presentation

        return self


# ---------------------------------------------------------------------------
# UMA Pay Response (receiver VASP → sender VASP)
# ---------------------------------------------------------------------------


class ResponseComplianceData(BaseModel):
    """Compliance data returned by the beneficiary VASP."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: KYC status of the beneficiary at the receiving VASP.
    kyc_status: KycStatus
    #: JWS signature by the receiving VASP.
    signature: str | None = None
    signature_nonce: str | None = None
    signature_timestamp: str | None = None
    #: Encrypted IVMS101 response payload (beneficiary data).
    encrypted_travel_rule_info: str | None = None
    #: Receiving VASP's Lightning node pubkey.
    node_public_key: str | None = Field(default=None, alias="nodePubKey")
    utxos: list[str] | None = None
    utxo_callback: str | None = Field(default=None, alias="utxoCallback")


class _PayeeData(BaseModel):
    """Optional payee data returned in a UMAPayResponse."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    identifier: str | None = None
    name: str | None = None
    email: str | None = None
    compliance: ResponseComplianceData | None = None


class UMAPayResponse(BaseModel):
    """UMA pay response returned by the receiving VASP."""

    model_config = ConfigDict(populate_by_name=True)

    #: UMA-standard payment request field.
    encoded_invoice: str = Field(alias="pr")

    #: Deprecated top-level compliance block kept for compatibility.
    compliance: ResponseComplianceData | None = None

    #: Optional payee data as requested.
    payee_data: _PayeeData | None = Field(default=None, alias="payeeData")

    #: Routing hint for Lightning payments.
    routes: list[str] | None = None

    #: UMA protocol version.
    uma_version: str | None = Field(default=None, alias="umaVersion")


# ---------------------------------------------------------------------------
# Compliance Requirement
# ---------------------------------------------------------------------------


class ComplianceRequirement(BaseModel):
    """
    Compliance requirements evaluated for a given transaction.
    Returned by UMAMiCAProtocol.evaluate_compliance_requirements().
    """

    model_config = ConfigDict(populate_by_name=True)

    #: Whether travel rule data exchange is required.
    #: True when amount exceeds travel_rule_threshold_eur per EU TFR.
    travel_rule_required: bool

    #: EUR threshold above which travel rule applies.
    #: Default: 1000 EUR per EU Transfer of Funds Regulation 2023/1113.
    travel_rule_threshold_eur: float

    #: Whether KYC verification of the sender is required.
    kyc_required: bool

    #: Whether eIDAS electronic signature is accepted / requested.
    eidas_signature_accepted: bool

    #: List of payer data field names that are required from the sender.
    required_fields: list[str]

    #: Reason code for why travel rule applies (informational).
    reason_code: str | None = None


# ---------------------------------------------------------------------------
# MiCA Transaction Metadata
# ---------------------------------------------------------------------------

#: Compliance status values specific to MiCA transaction reporting.
ComplianceStatus = Literal[
    "COMPLIANT",
    "NON_COMPLIANT",
    "PENDING_REVIEW",
    "SCREENED_CLEAR",
    "SCREENED_ALERT",
]


class MiCATransactionMetadata(BaseModel):
    """
    Immutable metadata record created for every MiCA-regulated transaction.
    Used for auditing, reporting, and sanctions compliance.
    """

    model_config = ConfigDict(populate_by_name=True)

    #: UUIDv4 transaction identifier.
    transaction_id: str

    #: ISO 8601 timestamp of transaction initiation.
    timestamp: str

    #: Transaction amount converted to EUR (for threshold evaluation).
    amount_eur: float

    #: Original transaction currency.
    currency: str

    #: Original transaction amount (in smallest unit of currency).
    amount: int

    #: Sending VASP domain / LEI.
    sender_vasp: str

    #: Receiving VASP domain / LEI.
    receiver_vasp: str

    #: Whether IVMS101 travel rule data was exchanged.
    travel_rule_exchanged: bool

    #: Whether an eIDAS signature was used.
    eidas_signed: bool

    #: Overall compliance status for reporting.
    compliance_status: ComplianceStatus

    #: Hash of the IVMS101 payload (SHA-256) for audit trail.
    ivms101_payload_hash: str | None = None

    #: Sender UMA address.
    sender_address: str | None = None

    #: Receiver UMA address.
    receiver_address: str | None = None

    #: Lightning payment hash (after payment).
    payment_hash: str | None = None


# ---------------------------------------------------------------------------
# Internal protocol types
# ---------------------------------------------------------------------------


class CurrencyPreference(BaseModel):
    """Currency preference entry returned by receiver capabilities."""

    model_config = ConfigDict(populate_by_name=True)

    code: str
    name: str
    symbol: str
    decimals: int
    min_sendable: int | None = None
    max_sendable: int | None = None
    #: EUR conversion rate (units of this currency per 1 EUR).
    eur_conversion_rate: float | None = None


class ReceiverCapabilities(BaseModel):
    """Receiver capabilities returned after UMA LNURLP discovery."""

    model_config = ConfigDict(populate_by_name=True)

    #: UMA address that was resolved.
    uma_address: str
    #: UMA protocol versions supported.
    uma_versions: list[str]
    #: Currencies supported by the receiver.
    currencies: list[CurrencyPreference]
    #: Receiving VASP's public key for encryption (ECDH).
    encryption_pub_key: str
    #: Receiving VASP's public key for signature verification.
    signing_pub_key: str
    #: Whether the receiving VASP requires travel rule data.
    requires_travel_rule: bool
    #: Min sendable amount in mSat.
    min_sendable: int
    #: Max sendable amount in mSat.
    max_sendable: int
    #: Receiving VASP domain.
    vasp_domain: str


class ParsedPayRequest(BaseModel):
    """
    A parsed, validated pay request after deserialization and
    signature verification by the receiving VASP.
    """

    model_config = ConfigDict(populate_by_name=True)

    request: UMAPayRequest
    #: Decrypted IVMS101 payload (if present).
    travel_rule_info: IVMS101Payload | None = None
    #: Whether the sending VASP's signature was verified.
    signature_verified: bool
    #: Sending VASP's domain inferred from payer identifier.
    sender_vasp_domain: str


class UMAMiCAConfig(BaseModel):
    """UMAMiCAProtocol constructor configuration."""

    model_config = ConfigDict(populate_by_name=True)

    #: Domain of this VASP (e.g. 'vasp.example.com').
    vasp_domain: str

    #: PEM-encoded or hex-encoded EC private key (P-256) used for
    #: signing UMA messages (JWS ES256).
    signing_key: str

    #: PEM-encoded or hex-encoded EC private key (P-256) used for
    #: ECDH-ES key wrapping (JWE encryption).
    encryption_key: str

    #: Travel rule threshold in EUR (default: 1000).
    travel_rule_threshold_eur: float | None = None

    #: Whether eIDAS is enabled for this VASP.
    eidas_enabled: bool | None = None

    #: UMA protocol version to use (default: '1.0').
    uma_version: str | None = None
