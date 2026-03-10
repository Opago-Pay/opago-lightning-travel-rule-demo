"""
opago_mica — Python port of the opago-MiCA-reference TypeScript implementation.

Exports key classes and functions from the types, config, and utils sub-packages.

Typical usage::

    from opago_mica.types import (
        IVMS101Payload,
        KycStatus,
        UMAPayRequest,
        UMAPayResponse,
    )
    from opago_mica.config import load_config, get_config
    from opago_mica.utils import (
        logger,
        sha256_hex,
        generate_nonce,
        encrypt_payload_with_jwk,
        sign_payload_with_jwk,
    )
"""

from __future__ import annotations

# Config
from opago_mica.config import (
    AppConfig,
    DatabaseConfig,
    EIDASConfig,
    ObservabilityConfig,
    ServerConfig,
    SparkConfig,
    VASPConfig,
    get_config,
    load_config,
    reset_config,
)

# Types
from opago_mica.types import (
    # common
    AuditRecord,
    BaseServerConfig,
    Beneficiary,
    # uma_extended (primary)
    ComplianceRequirement,
    ComplianceStatus,
    # eidas
    CredentialType,
    CurrencyPreference,
    EIDASCredential,
    EIDASSignatureRequest,
    EIDASSignatureResponse,
    EIDASVerificationResult,
    EIDASWalletConfig,
    GeographicAddress,
    HealthCheckResponse,
    # ivms101
    IVMS101Payload,
    KycStatus,
    LegacyComplianceStatus,
    LegalPerson,
    # uma (base)
    LnurlpResponse,
    MiCATransactionMetadata,
    NaturalPerson,
    Originator,
    ParsedPayRequest,
    ParsedUMAAddress,
    PaymentResult,
    PersonType,
    ReceiverCapabilities,
    ResponseComplianceData,
    RiskCategory,
    RiskFactor,
    RiskScore,
    SanctionsCheckResult,
    SanctionsMatch,
    SignatureLevel,
    TokenBalance,
    TransactionRecord,
    TravelRuleFormat,
    UMAComplianceData,
    UMAConfiguration,
    UMACurrency,
    UMAMiCAConfig,
    UMAPayerData,
    UMAPayRequest,
    UMAPayResponse,
    VASPComplianceInfo,
    VerifiablePresentation,
    WalletBalance,
)

# Utils
from opago_mica.utils import (
    audit_logger,
    create_component_logger,
    create_logger,
    decrypt_payload,
    decrypt_payload_with_jwk,
    decrypt_payload_with_pem,
    encrypt_payload,
    encrypt_payload_with_jwk,
    encrypt_payload_with_pem,
    from_base64url,
    generate_base64url_nonce,
    generate_ecdh_key_pair,
    generate_ed25519_key_pair,
    generate_key_pair,
    generate_nonce,
    generate_uuid_nonce,
    hash_data,
    hash_object,
    log_audit_event,
    logger,
    sha256_base64url,
    sha256_hex,
    sign_payload_with_jwk,
    sign_payload_with_pem,
    to_base64url,
    verify_payload_with_jwk,
    verify_payload_with_pem,
)

__version__ = "0.1.0"

__all__ = [
    # version
    "__version__",
    # types/common
    "AuditRecord",
    "BaseServerConfig",
    "HealthCheckResponse",
    "LegacyComplianceStatus",
    "PaymentResult",
    "RiskCategory",
    "RiskFactor",
    "RiskScore",
    "SanctionsCheckResult",
    "SanctionsMatch",
    "TokenBalance",
    "TransactionRecord",
    "WalletBalance",
    # types/ivms101
    "IVMS101Payload",
    "Beneficiary",
    "GeographicAddress",
    "LegalPerson",
    "NaturalPerson",
    "Originator",
    "PersonType",
    # types/uma (base)
    "LnurlpResponse",
    "ParsedUMAAddress",
    "UMAConfiguration",
    "UMACurrency",
    "VASPComplianceInfo",
    # types/uma_extended
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
    # types/eidas
    "CredentialType",
    "EIDASCredential",
    "EIDASSignatureRequest",
    "EIDASSignatureResponse",
    "EIDASVerificationResult",
    "EIDASWalletConfig",
    "SignatureLevel",
    "VerifiablePresentation",
    # config
    "AppConfig",
    "DatabaseConfig",
    "EIDASConfig",
    "ObservabilityConfig",
    "ServerConfig",
    "SparkConfig",
    "VASPConfig",
    "get_config",
    "load_config",
    "reset_config",
    # utils/logger
    "audit_logger",
    "create_component_logger",
    "create_logger",
    "log_audit_event",
    "logger",
    # utils/crypto
    "decrypt_payload",
    "decrypt_payload_with_jwk",
    "decrypt_payload_with_pem",
    "encrypt_payload",
    "encrypt_payload_with_jwk",
    "encrypt_payload_with_pem",
    "from_base64url",
    "generate_base64url_nonce",
    "generate_ecdh_key_pair",
    "generate_ed25519_key_pair",
    "generate_key_pair",
    "generate_nonce",
    "generate_uuid_nonce",
    "hash_data",
    "hash_object",
    "sha256_base64url",
    "sha256_hex",
    "sign_payload_with_jwk",
    "sign_payload_with_pem",
    "to_base64url",
    "verify_payload_with_jwk",
    "verify_payload_with_pem",
]
