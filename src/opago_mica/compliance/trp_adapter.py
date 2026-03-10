"""
TRP Adapter — Travel Rule Protocol (by the OpenVASP Association).

Implements the TravelRuleProvider interface for the TRP protocol.

Key characteristics of TRP:
 - Fully decentralised — no central directory required
 - HTTPS POST with JSON messages; no persistent connections
 - Counterparty discovery via "Travel Addresses" (ta-prefix), which are
   resolved through LNURL-style HTTP redirects at the counterparty's domain
 - End-to-end signed & encrypted payloads using JWE (JSON Web Encryption)
   and JWS (JSON Web Signature)
 - Message lifecycle: INQUIRY → INQUIRY_RESOLUTION → TRANSFER

Travel Address format: "ta<base32(vasp_domain + "#" + customer_id)>"

References:
 - https://openvasp.org
 - https://gitlab.com/openvasp/travel-rule-protocol
 - TRP Specification v2.x

NOTE: Network calls that require live endpoints are clearly marked with TODO.
"""

from __future__ import annotations

import hmac as hmac_module
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from opago_mica.compliance.travel_rule_provider import (
    CounterpartyInfo,
    SendTransferParams,
    TransferResponse,
    TravelRuleProvider,
    TravelRuleTransfer,
    ValidationResult,
)
from opago_mica.types.ivms101 import IVMS101Payload
from opago_mica.utils.logger import create_logger

log = create_logger("TRPAdapter")

# ---------------------------------------------------------------------------
# TRP-specific types
# ---------------------------------------------------------------------------


class TRPConfig(BaseModel):
    """Configuration for the TRP protocol adapter."""

    model_config = ConfigDict(populate_by_name=True)

    #: Internet domain this VASP operates on, e.g. "myvasp.example.com".
    vasp_domain: str
    #: Public HTTPS URL that counterparties will POST messages to.
    #: Must be publicly reachable and match the /.well-known/travel-rule endpoint.
    callback_url: str
    #: PEM-encoded ECDSA P-256 private key used to sign outgoing JWS messages.
    #: Counterparties discover the corresponding public key via LNURL / .well-known.
    signing_key: str
    #: PEM-encoded ECDH P-256 private key used for JWE (ECDH-ES+A256KW)
    #: key agreement when encrypting the IVMS101 payload.
    encryption_key: str


class TRPEndpoint(BaseModel):
    """A resolved Travel Address, ready to receive TRP messages."""

    model_config = ConfigDict(populate_by_name=True)

    travel_address: str
    #: Counterparty's callback URL.
    callback_url: str
    #: JWK-format public signing key.
    signing_key: dict[str, Any]
    #: JWK-format public encryption key.
    encryption_key: dict[str, Any]
    #: Supported TRP version, e.g. "2.0".
    version: str = "2.0"


class TxInfo(BaseModel):
    """Transaction information attached to a TRP INQUIRY message."""

    model_config = ConfigDict(populate_by_name=True)

    tx_hash: str
    asset: str
    amount: str
    #: ISO 8601 timestamp.
    transaction_time: str | None = None
    network_id: str | None = None


# TRP message type discriminators
TRPMessageType = Literal[
    "INQUIRY",
    "INQUIRY_RESOLUTION",
    "TRANSFER",
    "TRANSFER_CONFIRMATION",
    "CANCELLATION",
]


class TRPMessage(BaseModel):
    """Base TRP message envelope."""

    model_config = ConfigDict(populate_by_name=True)

    type: TRPMessageType
    version: str = "2.0"
    #: Unique message identifier (UUID v4).
    msg_id: str
    #: Identifier of the message this responds to (if any).
    in_reply_to: str | None = None
    #: ISO 8601 timestamp.
    sent_at: str
    #: Sender VASP domain.
    sender: str
    #: Recipient VASP domain.
    recipient: str
    #: IVMS101 payload (present in INQUIRY and TRANSFER).
    ivms101: IVMS101Payload | None = None
    #: Transaction information.
    tx_info: TxInfo | None = None
    #: True = accepted, False = rejected (INQUIRY_RESOLUTION).
    approved: bool | None = None
    rejection_code: str | None = None
    rejection_reason: str | None = None
    #: Beneficiary IVMS101 returned in INQUIRY_RESOLUTION when approved.
    beneficiary_ivms101: IVMS101Payload | None = None
    #: JWS compact serialisation when message is signed.
    signature: str | None = None


class TRPResponse(BaseModel):
    """HTTP response from a counterparty's TRP endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    msg_id: str
    accepted: bool
    message: TRPMessage | None = None
    http_status: int
    error: str | None = None


class TRPRejectionCode(StrEnum):
    """TRP rejection codes (subset of spec-defined codes)."""

    NO_CRYPTO_TRAVEL_RULE_REQUIRED = "NCTR"
    UNVERIFIED_BENEFICIARY = "UNBF"
    HIGH_RISK = "HISK"
    SYSTEM_ERROR = "SERR"
    TRANSACTION_CANCELLED = "TCAN"


# ---------------------------------------------------------------------------
# TRP Adapter
# ---------------------------------------------------------------------------


class TRPAdapter(TravelRuleProvider):
    """
    TravelRuleProvider implementation for the TRP protocol.

    Manages the INQUIRY → INQUIRY_RESOLUTION → TRANSFER message lifecycle.
    All HTTP network calls are stubbed with TODO markers.

    :param config: TRP configuration (domain, callback URL, signing/encryption keys).
    """

    protocol = "trp"

    def __init__(self, config: TRPConfig) -> None:
        self._config = config
        self._transfers: dict[str, TravelRuleTransfer] = {}
        self._initialized = False

    # -------------------------------------------------------------------------
    # TravelRuleProvider — lifecycle
    # -------------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Boot the TRP adapter.

        Validates signing/encryption keys and (in production) registers the
        callback URL with the internal HTTP server.

        TODO: Register callback URL handler for incoming TRP messages.
        """
        log.info(
            "Initializing TRP adapter",
            vasp_domain=self._config.vasp_domain,
            callback_url=self._config.callback_url,
        )

        if not self._config.signing_key or not self._config.encryption_key:
            raise ValueError("TRP adapter requires signing_key and encryption_key")

        # TODO: Register callback URL with internal HTTP server so incoming
        #   TRP messages are routed to handle_incoming_transfer().
        #
        #   The following endpoints should be served at vasp_domain:
        #     GET  /.well-known/travel-rule         → LNURL descriptor (JSON)
        #     POST {callback_url}                   → TRP message handler
        #     GET  /.well-known/travel-rule/jwks    → JWK Set with public keys
        #
        #   Example LNURL descriptor:
        #   {
        #     "tag": "travelRule",
        #     "version": "2.0",
        #     "callback": "https://myvasp.example.com/travel-rule",
        #     "k1": "<nonce>",
        #     "enc": { "kty":"EC", "crv":"P-256", ... },
        #     "sig": { "kty":"EC", "crv":"P-256", ... }
        #   }

        self._initialized = True
        log.info("TRP adapter initialized", vasp_domain=self._config.vasp_domain)

    # -------------------------------------------------------------------------
    # TravelRuleProvider — counterparty discovery
    # -------------------------------------------------------------------------

    async def discover_counterparty(self, vasp_domain: str) -> CounterpartyInfo:
        """
        Discover capabilities of a counterparty VASP via its LNURL descriptor.

        :param vasp_domain: Internet domain of the counterparty VASP.
        :returns: CounterpartyInfo with endpoint derived from the descriptor.

        TODO: Fetch /.well-known/travel-rule from the counterparty domain.
        """
        self._assert_initialized()
        log.debug("TRP: resolving counterparty LNURL descriptor", vasp_domain=vasp_domain)

        # TODO: Fetch /.well-known/travel-rule from the counterparty domain
        #
        #   import httpx
        #   url = f"https://{vasp_domain}/.well-known/travel-rule"
        #   async with httpx.AsyncClient() as client:
        #       resp = await client.get(url, headers={"Accept": "application/json"})
        #       resp.raise_for_status()
        #   descriptor = resp.json()
        #
        #   return CounterpartyInfo(
        #       vasp_id=vasp_domain,
        #       name=descriptor.get("vaspName", vasp_domain),
        #       domain=vasp_domain,
        #       supported_protocols=["trp"],
        #       public_key=json.dumps(descriptor["enc"]),
        #       endpoint=descriptor["callback"],
        #   )

        # Placeholder
        return CounterpartyInfo(
            vasp_id=vasp_domain,
            name=f"VASP: {vasp_domain}",
            domain=vasp_domain,
            supported_protocols=["trp"],
            # public_key: TODO — populated from LNURL descriptor
            endpoint=f"https://{vasp_domain}/travel-rule",
        )

    # -------------------------------------------------------------------------
    # TravelRuleProvider — send (originator side)
    # -------------------------------------------------------------------------

    async def send_transfer(self, params: SendTransferParams) -> TravelRuleTransfer:
        """
        Originator side — execute the TRP INQUIRY → TRANSFER message flow.

        Phase 1: Send INQUIRY, await INQUIRY_RESOLUTION.
        Phase 2: If accepted, send TRANSFER, await TRANSFER_CONFIRMATION.

        :param params: Transfer parameters.
        :returns: Completed TravelRuleTransfer record.
        """
        self._assert_initialized()

        validation = self.validate_payload(params.ivms101)
        if not validation.valid:
            raise ValueError(
                f"IVMS101 validation failed: {'; '.join(validation.errors)}"
            )

        transfer_id = str(uuid.uuid4())
        now = datetime.now(tz=UTC)

        log.info(
            "TRP: initiating outgoing transfer",
            transfer_id=transfer_id,
            counterparty=params.counterparty.domain,
            asset=params.asset,
            amount=params.amount,
        )

        # Phase 1: INQUIRY
        tx_info = TxInfo(
            tx_hash=params.tx_hash,
            asset=params.asset,
            amount=params.amount,
            transaction_time=now.isoformat(),
        )

        inquiry_msg = self.build_trp_message(
            ivms101=params.ivms101,
            tx_info=tx_info,
            msg_type="INQUIRY",
            recipient_domain=params.counterparty.domain,
        )

        inquiry_response = await self.post_to_counterparty(
            endpoint=(
                params.counterparty.endpoint
                or f"https://{params.counterparty.domain}/travel-rule"
            ),
            message=inquiry_msg,
        )

        log.debug(
            "TRP: received INQUIRY_RESOLUTION",
            transfer_id=transfer_id,
            accepted=inquiry_response.accepted,
        )

        if not inquiry_response.accepted:
            rejected = TravelRuleTransfer(
                transfer_id=transfer_id,
                protocol="trp",
                ivms101=params.ivms101,
                status="rejected",
                created_at=now,
                updated_at=datetime.now(tz=UTC),
                counterparty_vasp=params.counterparty.domain,
                tx_hash=params.tx_hash,
                asset=params.asset,
                amount=params.amount,
                direction="outgoing",
                protocol_metadata={
                    "inquiry_msg_id": inquiry_msg.msg_id,
                    "rejection_code": (
                        inquiry_response.message.rejection_code
                        if inquiry_response.message
                        else None
                    ),
                    "rejection_reason": (
                        inquiry_response.message.rejection_reason
                        if inquiry_response.message
                        else None
                    ),
                },
            )
            self._transfers[transfer_id] = rejected
            return rejected

        # Phase 2: TRANSFER (send IVMS101 again with confirmed tx hash)
        transfer_msg = self.build_trp_message(
            ivms101=params.ivms101,
            tx_info=tx_info,
            msg_type="TRANSFER",
            recipient_domain=params.counterparty.domain,
            in_reply_to=inquiry_msg.msg_id,
        )

        transfer_response = await self.post_to_counterparty(
            endpoint=(
                params.counterparty.endpoint
                or f"https://{params.counterparty.domain}/travel-rule"
            ),
            message=transfer_msg,
        )

        final_status = "accepted" if transfer_response.accepted else "rejected"

        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="trp",
            ivms101=params.ivms101,
            status=final_status,
            created_at=now,
            updated_at=datetime.now(tz=UTC),
            counterparty_vasp=params.counterparty.domain,
            tx_hash=params.tx_hash,
            asset=params.asset,
            amount=params.amount,
            direction="outgoing",
            protocol_metadata={
                "inquiry_msg_id": inquiry_msg.msg_id,
                "transfer_msg_id": transfer_msg.msg_id,
            },
        )

        self._transfers[transfer_id] = transfer
        log.info(
            "TRP: outgoing transfer complete",
            transfer_id=transfer_id,
            final_status=final_status,
        )
        return transfer

    # -------------------------------------------------------------------------
    # TravelRuleProvider — receive (beneficiary side)
    # -------------------------------------------------------------------------

    async def handle_incoming_transfer(self, raw_data: Any) -> TravelRuleTransfer:
        """
        Beneficiary side — receive and parse an incoming TRP message.

        :param raw_data: A :class:`TRPMessage` instance (or dict).
        :returns: Parsed TravelRuleTransfer with status 'pending' (INQUIRY) or
                  'accepted' (TRANSFER).
        :raises ValueError: If the message type is unexpected or IVMS101 is missing.
        """
        self._assert_initialized()

        msg = (
            TRPMessage.model_validate(raw_data)
            if isinstance(raw_data, dict)
            else raw_data
        )

        log.info(
            "TRP: received incoming message",
            msg_type=msg.type,
            msg_id=msg.msg_id,
            sender=msg.sender,
        )

        # TODO: Fetch the sender's public signing key from their /.well-known/travel-rule/jwks
        #   then verify with jose/python-jose:
        #   from jose import jwt
        #   claims = jwt.decode(msg.signature, sender_public_key, algorithms=["ES256"])

        if msg.type not in ("INQUIRY", "TRANSFER"):
            raise ValueError(
                f'TRP: unexpected incoming message type "{msg.type}" '
                "— expected INQUIRY or TRANSFER"
            )

        if not msg.ivms101:
            raise ValueError(
                f"TRP: incoming {msg.type} message from {msg.sender} has no IVMS101 payload"
            )

        transfer_id = str(uuid.uuid4())
        now = datetime.now(tz=UTC)

        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="trp",
            ivms101=msg.ivms101,
            status="pending" if msg.type == "INQUIRY" else "accepted",
            created_at=now,
            updated_at=now,
            counterparty_vasp=msg.sender,
            tx_hash=msg.tx_info.tx_hash if msg.tx_info else None,
            asset=msg.tx_info.asset if msg.tx_info else "UNKNOWN",
            amount=msg.tx_info.amount if msg.tx_info else "0",
            direction="incoming",
            protocol_metadata={
                "inbound_msg_id": msg.msg_id,
                "msg_type": msg.type,
            },
        )

        self._transfers[transfer_id] = transfer
        log.info(
            "TRP: incoming transfer stored",
            transfer_id=transfer_id,
            msg_type=msg.type,
        )
        return transfer

    # -------------------------------------------------------------------------
    # TravelRuleProvider — respond (beneficiary side)
    # -------------------------------------------------------------------------

    async def respond_to_transfer(
        self,
        transfer_id: str,
        response: TransferResponse,
    ) -> TravelRuleTransfer:
        """
        Beneficiary side — build and POST an INQUIRY_RESOLUTION back to the
        originator VASP.

        :param transfer_id: Transfer to respond to.
        :param response:    Accept/reject decision.
        :returns: Updated TravelRuleTransfer record.
        :raises ValueError: If the transfer is not an incoming transfer.
        """
        self._assert_initialized()

        transfer = self._require_transfer(transfer_id)
        if transfer.direction != "incoming":
            raise ValueError(f"Transfer {transfer_id} is not an incoming transfer")

        meta = transfer.protocol_metadata or {}
        inbound_msg_id: str | None = meta.get("inbound_msg_id")  # type: ignore[assignment]
        now = datetime.now(tz=UTC)

        log.info(
            "TRP: responding to incoming transfer",
            transfer_id=transfer_id,
            accepted=response.accepted,
        )

        # Build INQUIRY_RESOLUTION
        resolution_msg = TRPMessage(
            type="INQUIRY_RESOLUTION",
            version="2.0",
            msg_id=str(uuid.uuid4()),
            in_reply_to=inbound_msg_id,
            sent_at=now.isoformat(),
            sender=self._config.vasp_domain,
            recipient=transfer.counterparty_vasp,
            approved=response.accepted,
            rejection_code=(
                TRPRejectionCode.HIGH_RISK.value if response.rejection_reason else None
            ),
            rejection_reason=response.rejection_reason if not response.accepted else None,
            beneficiary_ivms101=(
                response.beneficiary_ivms101
                if response.accepted and response.beneficiary_ivms101
                else None
            ),
        )

        # TODO: Sign resolution_msg with this VASP's signing key
        #   from jose import jwt
        #   token = jwt.encode(
        #       resolution_msg.model_dump(),
        #       self._config.signing_key,
        #       algorithm="ES256",
        #   )
        #   resolution_msg.signature = token

        # POST INQUIRY_RESOLUTION back to the originator
        counterparty_endpoint = await self.discover_counterparty(transfer.counterparty_vasp)
        await self.post_to_counterparty(
            endpoint=(
                counterparty_endpoint.endpoint
                or f"https://{transfer.counterparty_vasp}/travel-rule"
            ),
            message=resolution_msg,
        )

        new_status = "accepted" if response.accepted else "rejected"
        updated = transfer.model_copy(
            update={
                "status": new_status,
                "updated_at": now,
                "protocol_metadata": {
                    **meta,
                    "resolution_msg_id": resolution_msg.msg_id,
                },
            }
        )

        self._transfers[transfer_id] = updated
        return updated

    # -------------------------------------------------------------------------
    # TravelRuleProvider — status
    # -------------------------------------------------------------------------

    async def get_transfer_status(self, transfer_id: str) -> TravelRuleTransfer:
        """
        Return the current state of a transfer.

        :param transfer_id: ID of the transfer to retrieve.
        """
        return self._require_transfer(transfer_id)

    # -------------------------------------------------------------------------
    # TravelRuleProvider — validation
    # -------------------------------------------------------------------------

    def validate_payload(self, payload: IVMS101Payload) -> ValidationResult:
        """
        Validate an IVMS101 payload against TRP requirements.

        TRP requires at least one geographic address for originator natural persons.

        :param payload: IVMS101 payload to validate.
        :returns: ValidationResult with any errors found.
        """
        errors: list[str] = []

        if not payload.originator:
            errors.append("originator is required")
        else:
            if not payload.originator.originator_persons:
                errors.append("originator.originator_persons is required")
            if not payload.originator.account_number:
                errors.append("originator.account_number is required")

        if not payload.beneficiary:
            errors.append("beneficiary is required")
        else:
            if not payload.beneficiary.beneficiary_persons:
                errors.append("beneficiary.beneficiary_persons is required")
            if not payload.beneficiary.account_number:
                errors.append("beneficiary.account_number is required")

        # TRP requires at least one address field for the originator natural person
        for person in (payload.originator.originator_persons if payload.originator else []):
            if person.natural_person and not person.natural_person.geographic_address:
                errors.append(
                    "TRP: originator natural person must have at least one geographic_address"
                )

        return ValidationResult(valid=len(errors) == 0, errors=errors)

    # -------------------------------------------------------------------------
    # TRP-specific public helpers
    # -------------------------------------------------------------------------

    async def resolve_travel_address(self, address: str) -> TRPEndpoint:
        """
        Resolve a Travel Address to a TRP endpoint descriptor.

        Travel Address format: "ta" + base32(domain + "#" + customer_id)
        The LNURL mechanism resolves to /.well-known/travel-rule at the VASP domain.

        :param address: Travel Address string starting with "ta".
        :returns: Resolved TRPEndpoint with callback URL and JWK public keys.

        TODO: Replace base32 decode placeholder with a real library (e.g. base64/struct).
        """
        log.debug("TRP: resolving Travel Address", address=address)

        if not address.startswith("ta"):
            raise ValueError(
                f'Invalid Travel Address format: "{address}" (must start with "ta")'
            )

        # Decode base32 → "domain#customerId"
        # TODO: Use a proper base32 decode library
        #   import base64
        #   decoded = base64.b32decode(address[2:].upper())
        #   domain, _, _ = decoded.decode().partition("#")
        #   lnurl_base = f"https://{domain}/.well-known/travel-rule"
        #
        #   import httpx
        #   async with httpx.AsyncClient() as client:
        #       resp = await client.get(lnurl_base)
        #   descriptor = resp.json()
        #
        #   return TRPEndpoint(
        #       travel_address=address,
        #       callback_url=descriptor["callback"],
        #       signing_key=descriptor["sig"],
        #       encryption_key=descriptor["enc"],
        #       version=descriptor.get("version", "2.0"),
        #   )

        # Placeholder: derive domain from a trivial mock decode
        mock_domain = "unknown-vasp.example.com"
        return TRPEndpoint(
            travel_address=address,
            callback_url=f"https://{mock_domain}/travel-rule",
            signing_key={},
            encryption_key={},
            version="2.0",
        )

    def build_trp_message(
        self,
        ivms101: IVMS101Payload,
        tx_info: TxInfo,
        msg_type: TRPMessageType = "INQUIRY",
        recipient_domain: str = "",
        in_reply_to: str | None = None,
    ) -> TRPMessage:
        """
        Construct a TRP protocol message for the given IVMS101 payload and
        transaction metadata.

        :param ivms101:           IVMS101 payload to include.
        :param tx_info:           Transaction metadata.
        :param msg_type:          TRP message type (default: INQUIRY).
        :param recipient_domain:  Domain of the recipient VASP.
        :param in_reply_to:       Optional msg_id of the message being replied to.
        :returns: Constructed TRPMessage.
        """
        include_payload = msg_type in ("INQUIRY", "TRANSFER")
        return TRPMessage(
            type=msg_type,
            version="2.0",
            msg_id=str(uuid.uuid4()),
            in_reply_to=in_reply_to,
            sent_at=datetime.now(tz=UTC).isoformat(),
            sender=self._config.vasp_domain,
            recipient=recipient_domain,
            ivms101=ivms101 if include_payload else None,
            tx_info=tx_info if include_payload else None,
        )

    async def post_to_counterparty(
        self,
        endpoint: str,
        message: TRPMessage,
    ) -> TRPResponse:
        """
        POST a TRP message to a counterparty endpoint and return the parsed response.

        In production:
          - The message body should be signed (JWS compact serialisation) with this
            VASP's signing key (ES256 / ECDSA P-256).
          - The IVMS101 sub-object may optionally be JWE-encrypted with the
            recipient's public encryption key (ECDH-ES+A256KW / A256GCM).

        TODO: Replace stub with real HTTP POST via httpx.

        :param endpoint: Counterparty's TRP callback URL.
        :param message:  TRP message to POST.
        :returns: Parsed TRPResponse.
        """
        log.debug(
            "TRP: posting message to counterparty",
            endpoint=endpoint,
            msg_type=message.type,
            msg_id=message.msg_id,
        )

        # TODO: Sign the message with self._config.signing_key:
        #   from jose import jwt
        #   token = jwt.encode(
        #       message.model_dump(exclude_none=True),
        #       self._config.signing_key,
        #       algorithm="ES256",
        #   )

        # TODO: Optionally JWE-encrypt the IVMS101 field with the recipient's
        #   public encryption key using ECDH-ES+A256KW / A256GCM.

        # TODO: Make actual HTTP POST:
        #   import httpx
        #   async with httpx.AsyncClient() as client:
        #       response = await client.post(
        #           endpoint,
        #           json={"token": token},
        #           headers={
        #               "Content-Type": "application/json",
        #               "X-TRP-Version": "2.0",
        #           },
        #       )
        #   if response.status_code not in (200, 202):
        #       raise RuntimeError(f"TRP: HTTP {response.status_code} from {endpoint}")
        #   return TRPResponse.model_validate(response.json())

        # Simulate a successful INQUIRY_RESOLUTION response for dev/testing
        is_inquiry = message.type == "INQUIRY"
        simulated_response = TRPResponse(
            msg_id=str(uuid.uuid4()),
            accepted=True,
            http_status=200 if is_inquiry else 202,
            message=(
                TRPMessage(
                    type="INQUIRY_RESOLUTION",
                    version="2.0",
                    msg_id=str(uuid.uuid4()),
                    in_reply_to=message.msg_id,
                    sent_at=datetime.now(tz=UTC).isoformat(),
                    sender=message.recipient,
                    recipient=message.sender,
                    approved=True,
                )
                if is_inquiry
                else None
            ),
        )

        log.debug(
            "TRP: received response",
            msg_id=simulated_response.msg_id,
            accepted=simulated_response.accepted,
            http_status=simulated_response.http_status,
        )
        return simulated_response

    def compute_message_hmac(self, message: TRPMessage, secret: str) -> str:
        """
        Compute a HMAC-SHA256 signature over a TRP message body.
        Used for webhook-style verification when JWS is not available.

        :param message: TRP message to sign.
        :param secret:  Shared HMAC secret.
        :returns: Hex-encoded HMAC-SHA256 digest.
        """
        body = json.dumps(message.model_dump(exclude_none=True), sort_keys=True)
        return hmac_module.new(
            secret.encode("utf-8"), body.encode("utf-8"), "sha256"
        ).hexdigest()

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _assert_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError(
                "TRPAdapter is not initialized — call initialize() first"
            )

    def _require_transfer(self, transfer_id: str) -> TravelRuleTransfer:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise KeyError(f"Transfer not found: {transfer_id}")
        return transfer
