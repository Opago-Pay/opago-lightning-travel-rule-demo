"""
UMA (Universal Money Address) and LNURL type definitions.

Based on UMA specification v1.0 and LNURL-pay protocol.
Extended with MiCA compliance fields.

See:
  https://github.com/uma-universal-money-address/uma-spec
  https://github.com/lnurl/luds
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

# ---------------------------------------------------------------------------
# UMA Address
# ---------------------------------------------------------------------------


class ParsedUMAAddress(BaseModel):
    """Parsed UMA address components."""

    model_config = ConfigDict(populate_by_name=True)

    #: Username part, e.g. 'alice' from '$alice@receiver.vasp.com'.
    username: str
    #: Domain part, e.g. 'receiver.vasp.com'.
    domain: str
    #: Full UMA address string.
    full: str


# ---------------------------------------------------------------------------
# LNURL-pay / UMA discovery
# ---------------------------------------------------------------------------


class UMACurrency(BaseModel):
    """Currency supported by a VASP."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: ISO 4217 or crypto code, e.g. 'EUR', 'BTC', 'USDC'.
    code: str
    name: str
    symbol: str
    decimals: int
    max_sendable: int | None = None
    min_sendable: int | None = None
    #: Conversion factor to millisats.
    multiplier: float | None = None


class MandatoryField(BaseModel):
    """A single field option with a mandatory flag."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    mandatory: bool


class PayerDataOptions(BaseModel):
    """Options for what payer data can be included."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    name: MandatoryField | None = None
    identifier: MandatoryField | None = None
    email: MandatoryField | None = None
    compliance: MandatoryField | None = None

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_camel,
        extra="allow",
    )


#: Supported travel rule protocols.
TravelRuleProtocol = Literal["TRISA", "TRP", "TRUST", "GTR", "Sygna"]


class VASPComplianceInfo(BaseModel):
    """Compliance capabilities and requirements of a VASP."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_camel,
        extra="allow",
    )

    #: Standard UMA fields from UMAD-04.
    is_subject_to_travel_rule: bool | None = None
    kyc_status: Literal["VERIFIED", "PENDING", "NOT_REQUIRED"] | None = None
    signature: str | None = None
    signature_nonce: str | None = None
    signature_timestamp: int | None = None
    receiver_identifier: str | None = None

    #: Is this VASP regulated under MiCA?
    is_mica_regulated: bool
    #: Which travel rule protocols are supported.
    travel_rule_protocols: list[TravelRuleProtocol]
    #: PGP / ECDH public key for encrypting travel rule data.
    encryption_public_key: str | None = None
    #: Key ID for the encryption key.
    encryption_key_id: str | None = None
    #: Accepted eIDAS credential types.
    accepted_eidas_credential_types: list[str] | None = None
    #: MiCA license number.
    mica_license_number: str | None = None
    #: Jurisdiction, ISO 3166-1 alpha-2.
    jurisdiction: str | None = None


class LnurlpResponse(BaseModel):
    """LNURL-pay first response (metadata endpoint)."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    tag: Literal["payRequest"]
    callback: str
    #: Millisats.
    min_sendable: int
    #: Millisats.
    max_sendable: int
    metadata: str
    currencies: list[UMACurrency] | None = None
    payer_data: PayerDataOptions | None = None
    #: UMA-specific: VASP compliance requirements.
    compliance: VASPComplianceInfo | None = None
    #: UMA version supported.
    uma_version: str | None = None
    #: Whether travel rule data is required for this recipient.
    travel_rule_required: bool | None = None
    #: Whether eIDAS signatures are accepted / required.
    eidas_signature_accepted: bool | None = None
    #: Minimum amount (sats) above which travel rule applies.
    travel_rule_threshold: int | None = None
    allows_nostr: bool | None = None


# ---------------------------------------------------------------------------
# UMA Pay Request / Response
# ---------------------------------------------------------------------------


class PayerComplianceData(BaseModel):
    """Compliance-specific payer data."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    utxos: list[str] | None = None
    node_pub_key: str | None = None
    kyc_status: Literal["VERIFIED", "PENDING", "NOT_REQUIRED"] | None = None
    encrypted_travel_rule_info: str | None = None
    travel_rule_format: str | None = None


class PayerData(BaseModel):
    """Payer data included in the pay request."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_camel,
        extra="allow",
    )

    name: str | None = None
    identifier: str | None = None
    email: str | None = None
    compliance: PayerComplianceData | None = None


class UMAPayRequest(BaseModel):
    """UMA pay request sent by the originating VASP."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: In currency.decimals units OR millisats.
    amount: int | str
    payer_data: PayerData | None = None
    convert: str | None = None
    comment: str | None = None
    #: Encrypted IVMS101 payload (base64).
    travel_rule_data: str | None = None
    #: Travel rule protocol used to encrypt / send the data.
    travel_rule_protocol: str | None = None
    #: eIDAS Verifiable Presentation (JSON string).
    eidas_presentation: str | None = None
    #: UMA version of the paying VASP.
    uma_version: str | None = None


class ResponseComplianceData(BaseModel):
    """Compliance data in the pay response."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    node_pub_key: str | None = None
    utxos: list[str] | None = None
    utxo_callback: str | None = None
    #: Beneficiary VASP's travel rule transfer ID.
    travel_rule_transfer_id: str | None = None
    #: Whether the beneficiary verified the originator's eIDAS presentation.
    eidas_verified: bool | None = None
    #: Result of compliance check.
    compliance_status: Literal["APPROVED", "PENDING", "REJECTED"] | None = None


class PaymentInfo(BaseModel):
    """Payment info in the response."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    amount: int
    currency_code: str
    decimals: int
    multiplier: float
    exchange_fees: float | None = None


class SuccessAction(BaseModel):
    """Success action after payment."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    tag: Literal["message", "url", "aes"]
    message: str | None = None
    url: str | None = None
    description: str | None = None
    ciphertext: str | None = None
    iv: str | None = None


class UMAPayResponse(BaseModel):
    """UMA pay response returned by the beneficiary VASP."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    #: BOLT11 invoice.
    pr: str
    routes: list[Any] | None = None
    compliance: ResponseComplianceData | None = None
    payment_info: PaymentInfo | None = None
    disposable: bool | None = None
    success_action: SuccessAction | None = None


# ---------------------------------------------------------------------------
# UMA / VASP configuration
# ---------------------------------------------------------------------------


class _ComplianceFeatures(BaseModel):
    """Nested compliance features block in UMAConfiguration."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    travel_rule_protocols: list[str]
    eidas_supported: bool
    mica_regulated: bool


class _VASPInfo(BaseModel):
    """Nested VASP info block in UMAConfiguration."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    name: str
    domain: str
    license_number: str | None = None
    jurisdiction: str


class UMAConfiguration(BaseModel):
    """UMA VASP configuration (served at /.well-known/uma-configuration)."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    uma_version: str
    encryption_pubkey: str = Field(alias="encryptionPubKey")
    encryption_algo: str
    signing_cert_chain: list[str] | None = Field(default=None, alias="signingCertChain")
    signing_pub_key: str | None = Field(default=None, alias="signingPubKey")
    compliance_features: _ComplianceFeatures
    vasp_info: _VASPInfo


# ---------------------------------------------------------------------------
# Internal protocol types used between sender and receiver
# ---------------------------------------------------------------------------


class ReceiverCapabilities(BaseModel):
    """Capabilities returned after resolving a receiver UMA address."""

    model_config = ConfigDict(populate_by_name=True)

    lnurlp_response: LnurlpResponse
    uma_configuration: UMAConfiguration | None = None
    #: Resolved callback URL for pay request.
    pay_request_callback_url: str
    #: Resolved receiver domain.
    receiver_domain: str


#: Preferred travel rule / compliance protocol.
PreferredProtocol = Literal["TRISA", "TRP", "TRUST", "GTR", "Sygna", "inline"]


class ComplianceRequirement(BaseModel):
    """Compliance requirement profile for a specific payment."""

    model_config = ConfigDict(populate_by_name=True)

    travel_rule_required: bool
    eidas_signature_required: bool
    eidas_signature_accepted: bool
    preferred_protocol: PreferredProtocol
    required_originator_fields: list[str]
    encryption_public_key: str | None = None
