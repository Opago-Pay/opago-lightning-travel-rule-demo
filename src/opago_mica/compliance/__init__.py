"""
opago_mica.compliance — Travel Rule compliance package.

Re-exports all protocol adapters, the TravelRuleManager, and the shared
abstract base types for convenient top-level access.
"""

from __future__ import annotations

from opago_mica.compliance.gtr_adapter import (
    GTRAdapter,
    GTRConfig,
    GTROneStepRequest,
    GTROneStepResponse,
    GTRPiiFieldType,
    GTRPiiSecuredInfo,
    GTRVASPRecord,
    GTRVerifyField,
    GTRVerifyStatus,
)
from opago_mica.compliance.travel_rule_manager import (
    PROTOCOL_PREFERENCE,
    InitiateTransferParams,
    NegotiationResult,
    TravelRuleManager,
)
from opago_mica.compliance.travel_rule_provider import (
    CounterpartyInfo,
    SendTransferParams,
    TransferDirection,
    TransferResponse,
    TransferStatus,
    TravelRuleProtocol,
    TravelRuleProvider,
    TravelRuleTransfer,
    ValidationResult,
)
from opago_mica.compliance.trisa_adapter import (
    SecureEnvelope,
    TRISAAdapter,
    TRISAConfig,
    TRISAError,
    TRISAErrorCode,
    TRISAVASPRecord,
)
from opago_mica.compliance.trp_adapter import (
    TRPAdapter,
    TRPConfig,
    TRPEndpoint,
    TRPMessage,
    TRPMessageType,
    TRPRejectionCode,
    TRPResponse,
    TxInfo,
)
from opago_mica.compliance.trust_adapter import (
    AddressOwnershipProof,
    TRUSTAdapter,
    TRUSTComplianceStatus,
    TRUSTConfig,
    TRUSTMember,
    TRUSTRejectionCode,
    TRUSTTransferPayload,
    TRUSTTransferResponse,
)

__all__ = [
    # Abstract base / shared types
    "TravelRuleProvider",
    "TravelRuleTransfer",
    "TravelRuleProtocol",
    "TransferStatus",
    "TransferDirection",
    "CounterpartyInfo",
    "SendTransferParams",
    "TransferResponse",
    "ValidationResult",
    # Manager
    "TravelRuleManager",
    "InitiateTransferParams",
    "NegotiationResult",
    "PROTOCOL_PREFERENCE",
    # TRISA
    "TRISAAdapter",
    "TRISAConfig",
    "TRISAVASPRecord",
    "SecureEnvelope",
    "TRISAError",
    "TRISAErrorCode",
    # TRP
    "TRPAdapter",
    "TRPConfig",
    "TRPEndpoint",
    "TRPMessage",
    "TRPMessageType",
    "TRPResponse",
    "TRPRejectionCode",
    "TxInfo",
    # TRUST
    "TRUSTAdapter",
    "TRUSTConfig",
    "TRUSTMember",
    "TRUSTComplianceStatus",
    "AddressOwnershipProof",
    "TRUSTTransferPayload",
    "TRUSTTransferResponse",
    "TRUSTRejectionCode",
    # GTR
    "GTRAdapter",
    "GTRConfig",
    "GTRVASPRecord",
    "GTROneStepRequest",
    "GTROneStepResponse",
    "GTRPiiSecuredInfo",
    "GTRVerifyField",
    "GTRVerifyStatus",
    "GTRPiiFieldType",
]
