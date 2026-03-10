"""GTR adapter implementation compatible with TravelRuleProvider."""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from opago_mica.compliance.travel_rule_provider import (
    CounterpartyInfo,
    SendTransferParams,
    TransferResponse,
    TravelRuleProvider,
    TravelRuleTransfer,
    ValidationResult,
)
from opago_mica.types.ivms101 import IVMS101Payload

GTRPiiFieldType = Literal["FULL_JSON_OBJECT_ENCRYPT"]
GTRVerifyField = Literal["ADDRESS", "PII", "TXID"]


class GTRVerifyStatus(IntEnum):
    SUCCESS = 100000
    ADDRESS_NOT_FOUND = 200001
    PII_VERIFICATION_FAILED = 200003
    TXID_NOT_FOUND = 200007


class GTRConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    endpoint: str
    api_token: str
    vasp_code: str
    vasp_domain: str
    public_key: str
    private_key: str
    request_id_prefix: str = "GTR"
    allow_insecure_mock_mode: bool = False


class GTRVASPRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    vasp_code: str
    domain: str
    name: str
    availability: int = 0


class GTRPiiSecuredInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    initiator_key_info: dict[str, str]
    receiver_key_info: dict[str, str]
    secret_algorithm: str
    pii_secret_format_type: GTRPiiFieldType
    pii_spec_version: str
    secured_payload: str
    encryption_params: dict[str, Any]


class GTROneStepRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    request_id: str
    originator_vasp: str
    beneficiary_vasp: str
    tx_hash: str
    asset: str
    amount: str
    pii_secured_info: GTRPiiSecuredInfo


class GTROneStepResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    data: dict[str, Any]
    verify_status: GTRVerifyStatus
    verify_message: str


class GTRAdapter(TravelRuleProvider):
    """In-memory mock GTR adapter used only for local testing and demo flows."""

    protocol = "gtr"

    def __init__(self, config: GTRConfig) -> None:
        self._config = config
        self._initialized = False
        self._transfers: dict[str, TravelRuleTransfer] = {}

    async def initialize(self) -> None:
        if not self._config.allow_insecure_mock_mode:
            raise RuntimeError(
                "GTRAdapter is mock-only. Set allow_insecure_mock_mode=True "
                "for local or demo use."
            )
        if not self._config.api_token:
            raise ValueError("GTR config validation failed: api_token is required")
        if not self._config.public_key:
            raise ValueError("GTR config validation failed: public_key is required")
        if not self._config.private_key:
            raise ValueError("GTR config validation failed: private_key is required")
        self._initialized = True

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError("GTR adapter not initialized")

    async def discover_counterparty(self, vasp_domain: str) -> CounterpartyInfo:
        self._require_initialized()
        return CounterpartyInfo(
            vasp_id=f"gtr-{vasp_domain}",
            name=f"GTR Member {vasp_domain}",
            domain=vasp_domain,
            supported_protocols=["gtr"],
            public_key=f"pubkey-{vasp_domain}",
            endpoint=f"{self._config.endpoint.rstrip('/')}/api/verify/v2/one_step",
        )

    async def send_transfer(self, params: SendTransferParams) -> TravelRuleTransfer:
        self._require_initialized()
        validation = self.validate_payload(params.ivms101)
        if not validation.valid:
            message = "; ".join(validation.errors).lower()
            if "originator" in message:
                raise ValueError(f"Invalid originator payload: {message}")
            if "beneficiary" in message:
                raise ValueError(f"Invalid beneficiary payload: {message}")
            raise ValueError(f"Invalid IVMS101 payload: {message}")

        request_id = f"{self._config.request_id_prefix}-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(UTC)
        transfer = TravelRuleTransfer(
            transfer_id=str(uuid.uuid4()),
            protocol="gtr",
            ivms101=params.ivms101,
            status="accepted",
            created_at=now,
            updated_at=now,
            counterparty_vasp=params.counterparty.vasp_id,
            tx_hash=params.tx_hash or None,
            asset=params.asset,
            amount=params.amount,
            direction="outgoing",
            protocol_metadata={
                "request_id": request_id,
                "gtr_vasp_code": self._config.vasp_code,
                "needs_tx_id_notification": not bool(params.tx_hash),
            },
        )
        self._transfers[transfer.transfer_id] = transfer
        return transfer

    async def handle_incoming_transfer(self, raw_data: Any) -> TravelRuleTransfer:
        self._require_initialized()

        if isinstance(raw_data, GTROneStepResponse):
            data = raw_data.data
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            raise TypeError("Incoming GTR payload must be GTROneStepResponse or dict")

        secured = data.get("piiSecuredInfo") or data.get("pii_secured_info")
        encrypted_payload = data.get("encryptedPayload") or data.get("encrypted_payload")
        if secured and isinstance(secured, dict):
            encrypted_payload = secured.get("securedPayload") or secured.get("secured_payload")
        if not encrypted_payload or not isinstance(encrypted_payload, str):
            raise ValueError("Incoming GTR payload has no PII payload")

        ivms101 = self.decrypt_pii(encrypted_payload)
        transfer_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="gtr",
            ivms101=ivms101,
            status="pending",
            created_at=now,
            updated_at=now,
            counterparty_vasp=str(data.get("originatorVasp") or data.get("originator_vasp") or ""),
            tx_hash=None,
            asset=str(data.get("asset") or "BTC"),
            amount=str(data.get("amount") or "0"),
            direction="incoming",
            protocol_metadata={
                "request_id": data.get("requestId") or data.get("request_id"),
                "verify_status": int(data.get("verifyStatus", GTRVerifyStatus.SUCCESS)),
            },
        )
        self._transfers[transfer_id] = transfer
        return transfer

    async def respond_to_transfer(
        self,
        transfer_id: str,
        response: TransferResponse,
    ) -> TravelRuleTransfer:
        self._require_initialized()
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise KeyError("Transfer not found")
        if transfer.direction != "incoming":
            raise ValueError("Transfer is not an incoming transfer")

        updated = transfer.model_copy(
            update={
                "status": "accepted" if response.accepted else "rejected",
                "updated_at": datetime.now(UTC),
            }
        )
        self._transfers[transfer_id] = updated
        return updated

    async def get_transfer_status(self, transfer_id: str) -> TravelRuleTransfer:
        self._require_initialized()
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise KeyError("Transfer not found")
        return transfer

    def validate_payload(self, payload: IVMS101Payload) -> ValidationResult:
        errors: list[str] = []
        if not payload.originator.originator_persons:
            errors.append("originator_persons is required")
        if not payload.originator.account_number:
            errors.append("originator account_number is required")
        if not payload.beneficiary.beneficiary_persons:
            errors.append("beneficiary_persons is required")
        if not payload.beneficiary.account_number:
            errors.append("beneficiary account_number is required")

        if payload.originator.originator_persons:
            first = payload.originator.originator_persons[0].natural_person
            identifiers = first.name_identifier if first else None
            if not identifiers or not any(i.name_identifier_type == "LEGL" for i in identifiers):
                errors.append("originator must include LEGL name identifier")

        return ValidationResult(valid=not errors, errors=errors)

    def asset_to_network(self, asset: str) -> str:
        mapping = {"BTC": "BTC", "ETH": "ETH", "USDC": "ETH"}
        return mapping.get(asset.upper(), asset.upper())

    def encrypt_pii(
        self,
        ivms101: IVMS101Payload,
        counterparty_public_key: str,
    ) -> dict[str, Any]:
        payload_json = ivms101.model_dump_json()
        encrypted_payload = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
        pii_secured_info = GTRPiiSecuredInfo(
            initiator_key_info={"publicKey": self._config.public_key},
            receiver_key_info={"publicKey": counterparty_public_key},
            secret_algorithm="curve25519",
            pii_secret_format_type="FULL_JSON_OBJECT_ENCRYPT",
            pii_spec_version="ivms101-2020",
            secured_payload=encrypted_payload,
            encryption_params={"ecies": {"ephemeralPublicKey": secrets.token_hex(16)}},
        )
        return {
            "encrypted_payload": encrypted_payload,
            "pii_secured_info": pii_secured_info,
        }

    def decrypt_pii(self, encrypted_payload: str) -> IVMS101Payload:
        try:
            decoded = base64.b64decode(encrypted_payload.encode("utf-8"))
            return IVMS101Payload.model_validate_json(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValidationError) as exc:
            raise ValueError("Could not decrypt/parse GTR PII payload") from exc

    def find_vasp_by_domain(self, domain: str) -> GTRVASPRecord:
        return GTRVASPRecord(
            vasp_code=f"gtr-{domain}",
            domain=domain,
            name=f"GTR Member {domain}",
            availability=0,
        )

    async def notify_tx_id(self, request_id: str, tx_id: str) -> None:
        self._require_initialized()
        digest = hashlib.sha256(f"{request_id}:{tx_id}".encode()).hexdigest()
        _ = digest
