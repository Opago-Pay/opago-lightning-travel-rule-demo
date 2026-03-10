"""
Types barrel export.

Re-exports all type definitions. The uma_extended module provides richer
MiCA-compliant versions of some UMA types; where names conflict the
extended versions take precedence and the originals are re-exported with
a "Base" prefix for backward-compatibility.
"""

from __future__ import annotations

# Common shared types (AuditRecord, RiskScore, SanctionsCheckResult, etc.)
# Note: ComplianceStatus is intentionally NOT re-exported from here because
# uma_extended exports a richer version. Consumers should import ComplianceStatus
# from opago_mica.types.uma_extended directly.
from opago_mica.types.common import (
    AuditRecord,
    BaseServerConfig,
    HealthCheckResponse,
    HealthState,
    MatchType,
    PaymentResult,
    RiskCategory,
    RiskFactor,
    RiskScore,
    SanctionsCheckResult,
    SanctionsMatch,
    TokenBalance,
    TransactionRecord,
    TransactionStatus,
    TransactionType,
    WalletBalance,
)

# Re-export ComplianceStatus from common with an alias so both are accessible.
from opago_mica.types.common import ComplianceStatus as LegacyComplianceStatus

# eIDAS wallet types.
from opago_mica.types.eidas import (
    AgeVerificationCredentialSubject,
    CredentialSubject,
    CredentialType,
    EIDASAddress,
    EIDASCredential,
    EIDASCredentialSubject,
    EIDASProof,
    EIDASSignatureRequest,
    EIDASSignatureResponse,
    EIDASVerificationResult,
    EIDASWalletConfig,
    IdentityCredentialSubject,
    InputDescriptor,
    LinkedDataProof,
    OpenID4VPAuthorizationRequest,
    PresentationDefinition,
    SignatureLevel,
    VerifiablePresentation,
)

# IVMS101 data model types (Travel Rule).
from opago_mica.types.ivms101 import (
    Address,
    AddressTypeCode,
    Beneficiary,
    BeneficiaryPerson,
    BeneficiaryVASP,
    DateAndPlaceOfBirth,
    GeographicAddress,
    IVMS101Payload,
    LegalPerson,
    LegalPersonName,
    LegalPersonNameIdentifier,
    LegalPersonNameTypeCode,
    LegalPersonNationalIdentification,
    NationalIdentification,
    NationalIdentifierTypeCode,
    NaturalPerson,
    NaturalPersonName,
    NaturalPersonNameIdentifier,
    NaturalPersonNameTypeCode,
    OriginatingVASP,
    Originator,
    OriginatorPerson,
    PayloadMetadata,
    PersonType,
    TransferPath,
    TransferPathEntry,
    TransferPathPerson,
    TransliterationMethod,
)
from opago_mica.types.uma import (
    ComplianceRequirement as BaseComplianceRequirement,
)

# Base UMA types (LNURL-pay, VASP config, etc.) – types NOT superseded by uma_extended.
from opago_mica.types.uma import (
    LnurlpResponse,
    MandatoryField,
    ParsedUMAAddress,
    PayerComplianceData,
    PayerData,
    PayerDataOptions,
    PaymentInfo,
    PreferredProtocol,
    SuccessAction,
    TravelRuleProtocol,
    UMAConfiguration,
    UMACurrency,
    VASPComplianceInfo,
)
from opago_mica.types.uma import (
    ReceiverCapabilities as BaseReceiverCapabilities,
)
from opago_mica.types.uma import (
    ResponseComplianceData as BaseResponseComplianceData,
)
from opago_mica.types.uma import (
    # These are superseded – re-exported with Base prefix for reference.
    UMAPayRequest as BaseUMAPayRequest,
)
from opago_mica.types.uma import (
    UMAPayResponse as BaseUMAPayResponse,
)

# MiCA-extended UMA types – primary types used by core modules.
# They supersede the corresponding types in uma.py.
from opago_mica.types.uma_extended import (
    ComplianceRequirement,
    ComplianceStatus,
    CurrencyPreference,
    KycStatus,
    MiCATransactionMetadata,
    ParsedPayRequest,
    ReceiverCapabilities,
    ResponseComplianceData,
    TravelRuleFormat,
    UMAComplianceData,
    UMAMiCAConfig,
    UMAPayerData,
    UMAPayRequest,
    UMAPayResponse,
)

__all__ = [
    # common
    "AuditRecord",
    "BaseServerConfig",
    "HealthCheckResponse",
    "HealthState",
    "LegacyComplianceStatus",
    "MatchType",
    "PaymentResult",
    "RiskCategory",
    "RiskFactor",
    "RiskScore",
    "SanctionsCheckResult",
    "SanctionsMatch",
    "TokenBalance",
    "TransactionRecord",
    "TransactionStatus",
    "TransactionType",
    "WalletBalance",
    # uma (base)
    "BaseComplianceRequirement",
    "BaseReceiverCapabilities",
    "BaseResponseComplianceData",
    "BaseUMAPayRequest",
    "BaseUMAPayResponse",
    "LnurlpResponse",
    "MandatoryField",
    "ParsedUMAAddress",
    "PayerComplianceData",
    "PayerData",
    "PayerDataOptions",
    "PaymentInfo",
    "PreferredProtocol",
    "SuccessAction",
    "TravelRuleProtocol",
    "UMAConfiguration",
    "UMACurrency",
    "VASPComplianceInfo",
    # ivms101
    "Address",
    "AddressTypeCode",
    "Beneficiary",
    "BeneficiaryPerson",
    "BeneficiaryVASP",
    "DateAndPlaceOfBirth",
    "GeographicAddress",
    "IVMS101Payload",
    "LegalPerson",
    "LegalPersonName",
    "LegalPersonNameIdentifier",
    "LegalPersonNameTypeCode",
    "LegalPersonNationalIdentification",
    "NationalIdentification",
    "NationalIdentifierTypeCode",
    "NaturalPerson",
    "NaturalPersonName",
    "NaturalPersonNameIdentifier",
    "NaturalPersonNameTypeCode",
    "Originator",
    "OriginatingVASP",
    "OriginatorPerson",
    "PayloadMetadata",
    "PersonType",
    "TransferPath",
    "TransferPathEntry",
    "TransferPathPerson",
    "TransliterationMethod",
    # eidas
    "AgeVerificationCredentialSubject",
    "CredentialSubject",
    "CredentialType",
    "EIDASAddress",
    "EIDASCredential",
    "EIDASCredentialSubject",
    "EIDASProof",
    "EIDASSignatureRequest",
    "EIDASSignatureResponse",
    "EIDASVerificationResult",
    "EIDASWalletConfig",
    "IdentityCredentialSubject",
    "InputDescriptor",
    "LinkedDataProof",
    "OpenID4VPAuthorizationRequest",
    "PresentationDefinition",
    "SignatureLevel",
    "VerifiablePresentation",
    # uma_extended (primary)
    "ComplianceRequirement",
    "ComplianceStatus",
    "CurrencyPreference",
    "KycStatus",
    "MiCATransactionMetadata",
    "ParsedPayRequest",
    "ReceiverCapabilities",
    "ResponseComplianceData",
    "TravelRuleFormat",
    "UMAComplianceData",
    "UMAMiCAConfig",
    "UMAPayerData",
    "UMAPayRequest",
    "UMAPayResponse",
]
