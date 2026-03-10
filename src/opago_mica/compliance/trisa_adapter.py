"""
TRISA Adapter — Travel Rule Information Sharing Alliance.

Implements the TravelRuleProvider interface for the TRISA protocol.

Key characteristics of TRISA:
 - Peer-to-peer gRPC communication over mTLS
 - Certificates issued by the TRISA Global Directory Service (GDS)
 - "Secure Envelopes" (TRISA Envelope v2): IVMS101 payload is sealed
   inside an RSA-OAEP-encrypted AES-256-GCM symmetric envelope
 - Counterparty lookup via the TRISA GDS WHOIS endpoint
 - Each VASP registers with a unique vasp_id (e.g. "example.vasp.us")

References:
 - https://trisa.io
 - https://vaspdirectory.net
 - https://github.com/trisacrypto/trisa (protobuf specs)

Uses grpcio with compiled TRISA protobuf stubs from trisacrypto/trisa.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import Any

import httpx
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

log = create_logger("TRISAAdapter")

# ---------------------------------------------------------------------------
# TRISA-specific types
# ---------------------------------------------------------------------------


class TRISAConfig(BaseModel):
    """Configuration for the TRISA protocol adapter."""

    model_config = ConfigDict(populate_by_name=True)

    #: Path to the PEM-encoded mTLS certificate issued by the TRISA GDS.
    certificate_path: str
    #: Path to the matching private key.
    private_key_path: str
    #: TRISA GDS endpoint, e.g. "api.vaspdirectory.net:443".
    directory_endpoint: str
    #: This VASP's registered TRISA identifier, e.g. "myvasp.example.com".
    vasp_id: str


class TRISAVASPRecord(BaseModel):
    """A VASP record as returned by the TRISA Global Directory Service."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    website: str
    common_name: str
    trp_endpoint: str
    #: PEM-encoded public signing certificate from the GDS.
    signing_certificate: str
    verified_on: str
    first_listed: str
    country: str


class SecureEnvelope(BaseModel):
    """
    TRISA Secure Envelope v2.

    The IVMS101 payload is sealed inside an RSA-OAEP-encrypted AES-256-GCM
    symmetric envelope.
    """

    model_config = ConfigDict(populate_by_name=True)

    #: UUID v4 envelope identifier.
    id: str
    #: AES-256-GCM encrypted IVMS101 payload (base64).
    encrypted_payload: str
    #: RSA-OAEP encrypted AES key (base64).
    encrypted_key: str
    #: AES-GCM initialisation vector (base64).
    iv: str
    #: AES-GCM authentication tag (base64).
    hmac: str
    encryption_algorithm: str = "AES256-GCM"
    key_encryption_algorithm: str = "RSA-OAEP-SHA512"
    #: Sender VASP identifier.
    sender_vasp_id: str
    #: Recipient VASP identifier.
    receiver_vasp_id: str
    #: ISO 8601 timestamp.
    sent_at: str
    #: True when this is a rejection response.
    is_error: bool
    error: TRISAError | None = None


class TRISAError(BaseModel):
    """A TRISA protocol-level error."""

    model_config = ConfigDict(populate_by_name=True)

    code: int
    message: str
    retry: bool


class TRISAErrorCode(IntEnum):
    """Numeric error codes aligned with TRISA Error codes v1."""

    UNHANDLED = 49
    MISSING_FIELDS = 40
    INCOMPLETE_IDENTITY = 41
    COMPLIANCE_CHECK_FAIL = 42
    NO_COMPLIANCE = 43
    HIGH_RISK = 44
    OUT_OF_NETWORK = 45
    FORBIDDEN = 46
    REJECTED = 47
    UNVERIFIED = 48


# ---------------------------------------------------------------------------
# TRISA Adapter
# ---------------------------------------------------------------------------


class TRISAAdapter(TravelRuleProvider):
    """
    TravelRuleProvider implementation for the TRISA protocol.

    Manages Secure Envelope creation/opening and GDS-based counterparty
    discovery. All gRPC network calls are stubbed with TODO markers.

    :param config: TRISA configuration (credentials, GDS endpoint, VASP ID).
    """

    protocol = "trisa"

    def __init__(self, config: TRISAConfig) -> None:
        self._config = config
        self._transfers: dict[str, TravelRuleTransfer] = {}
        self._initialized = False

    # -------------------------------------------------------------------------
    # TravelRuleProvider — lifecycle
    # -------------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Boot the TRISA adapter.

        Loads mTLS credentials from disk and verifies they are valid.
        In production, this would also establish the gRPC channel to the
        TRISA Global Directory Service (GDS).
        """
        log.info(
            "Initializing TRISA adapter",
            vasp_id=self._config.vasp_id,
            directory=self._config.directory_endpoint,
        )

        cert_path = Path(self._config.certificate_path)
        key_path = Path(self._config.private_key_path)
        if not cert_path.exists():
            raise FileNotFoundError(
                f"TRISA certificate not found: {cert_path}"
            )
        if not key_path.exists():
            raise FileNotFoundError(
                f"TRISA private key not found: {key_path}"
            )

        with open(cert_path, "rb") as f:
            self._cert_pem = f.read()
        with open(key_path, "rb") as f:
            self._key_pem = f.read()

        # Verify credentials load correctly
        from cryptography.hazmat.primitives import serialization

        self._private_key = serialization.load_pem_private_key(
            self._key_pem, password=None
        )

        import grpc

        channel_credentials = grpc.ssl_channel_credentials(
            root_certificates=None,
            private_key=self._key_pem,
            certificate_chain=self._cert_pem,
        )
        self._gds_channel = grpc.aio.secure_channel(
            self._config.directory_endpoint,
            channel_credentials,
        )

        self._initialized = True
        log.info("TRISA adapter initialized", vasp_id=self._config.vasp_id)

    # -------------------------------------------------------------------------
    # TravelRuleProvider — counterparty discovery
    # -------------------------------------------------------------------------

    async def discover_counterparty(self, vasp_domain: str) -> CounterpartyInfo:
        """
        Discover capabilities of a counterparty VASP via the TRISA GDS.

        :param vasp_domain: Internet domain of the counterparty VASP.
        :returns: CounterpartyInfo with public key and endpoint from GDS.
        """
        self._assert_initialized()
        log.debug("TRISA: looking up counterparty", vasp_domain=vasp_domain)

        vasp_record = await self.lookup_vasp(vasp_domain)

        return CounterpartyInfo(
            vasp_id=vasp_record.id,
            name=vasp_record.name,
            domain=vasp_domain,
            supported_protocols=["trisa"],
            public_key=vasp_record.signing_certificate,
            endpoint=vasp_record.trp_endpoint,
        )

    # -------------------------------------------------------------------------
    # TravelRuleProvider — send (originator side)
    # -------------------------------------------------------------------------

    async def send_transfer(self, params: SendTransferParams) -> TravelRuleTransfer:
        """
        Originator side — seal the IVMS101 payload in a Secure Envelope and
        send it to the beneficiary VASP via gRPC.

        :param params: Transfer parameters.
        :returns: Completed TravelRuleTransfer record.
        :raises ValueError: If counterparty has no public key, or validation fails.
        """
        self._assert_initialized()

        validation = self.validate_payload(params.ivms101)
        if not validation.valid:
            raise ValueError(
                f"IVMS101 validation failed: {'; '.join(validation.errors)}"
            )

        log.info(
            "TRISA: initiating outgoing transfer",
            counterparty_vasp=params.counterparty.vasp_id,
            asset=params.asset,
            amount=params.amount,
        )

        if not params.counterparty.public_key:
            raise ValueError(
                f"No public key available for counterparty {params.counterparty.vasp_id}"
            )

        envelope = await self.create_secure_envelope(
            params.ivms101,
            params.counterparty.public_key,
            params.counterparty.vasp_id,
        )

        transfer_id = envelope.id
        now = datetime.now(tz=UTC)
        status: str = "accepted"
        response_envelope: SecureEnvelope | None = None

        http_bridge_endpoint = self._http_bridge_endpoint(params.counterparty.endpoint)
        if http_bridge_endpoint is not None:
            response = await self._post_http_bridge(
                http_bridge_endpoint,
                envelope,
            )
            transfer_id = str(response.get("transferId") or transfer_id)
            status = self._map_transfer_state(response.get("transferState"))
        elif params.counterparty.endpoint and envelope.encrypted_key:
            import grpc
            from trisa.api.v1beta1 import api_pb2_grpc

            from opago_mica.compliance.trisa_grpc import trisa  # noqa: F401

            channel_creds = grpc.ssl_channel_credentials(
                root_certificates=None,
                private_key=self._key_pem,
                certificate_chain=self._cert_pem,
            )
            channel = grpc.aio.secure_channel(
                params.counterparty.endpoint,
                channel_creds,
            )
            stub = api_pb2_grpc.TRISANetworkStub(channel)
            proto_env = self._to_proto_envelope(envelope, transfer_state=1)  # STARTED
            try:
                proto_response = await stub.Transfer(proto_env)
                response_envelope = self._from_proto_envelope(
                    proto_response,
                    sender_vasp_id=params.counterparty.vasp_id,
                    receiver_vasp_id=self._config.vasp_id,
                )
            finally:
                await channel.close()
            status = "rejected" if response_envelope.is_error else "accepted"
        else:
            response_envelope = SecureEnvelope(
                id=str(uuid.uuid4()),
                encrypted_payload=base64.b64encode(b"{}").decode(),
                encrypted_key="",
                iv="",
                hmac="",
                encryption_algorithm="AES256-GCM",
                key_encryption_algorithm="RSA-OAEP-SHA512",
                sender_vasp_id=params.counterparty.vasp_id,
                receiver_vasp_id=self._config.vasp_id,
                sent_at=datetime.now(tz=UTC).isoformat(),
                is_error=False,
            )

        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="trisa",
            ivms101=params.ivms101,
            status=status,
            created_at=now,
            updated_at=datetime.now(tz=UTC),
            counterparty_vasp=params.counterparty.vasp_id,
            tx_hash=params.tx_hash,
            asset=params.asset,
            amount=params.amount,
            direction="outgoing",
            protocol_metadata={
                "envelope_id": envelope.id,
                **(
                    {"response_envelope_id": response_envelope.id}
                    if response_envelope is not None
                    else {}
                ),
            },
        )

        self._transfers[transfer_id] = transfer

        log.info("TRISA: outgoing transfer complete", transfer_id=transfer_id, status=status)
        return transfer

    # -------------------------------------------------------------------------
    # TravelRuleProvider — receive (beneficiary side)
    # -------------------------------------------------------------------------

    async def handle_incoming_transfer(self, raw_data: Any) -> TravelRuleTransfer:
        """
        Beneficiary side — receive and decrypt an incoming TRISA Secure Envelope.

        :param raw_data: A :class:`SecureEnvelope` instance (or dict) from the
                         gRPC transport layer.
        :returns: Parsed TravelRuleTransfer with status 'pending'.
        :raises ValueError: If the envelope contains an error flag.
        """
        self._assert_initialized()

        # raw_data is expected to be a SecureEnvelope or compatible dict
        if isinstance(raw_data, dict):
            envelope = SecureEnvelope.model_validate(raw_data)
        else:
            envelope = raw_data  # type: SecureEnvelope

        log.info(
            "TRISA: received incoming secure envelope",
            envelope_id=envelope.id,
            sender_vasp_id=envelope.sender_vasp_id,
        )

        if envelope.is_error:
            error_msg = envelope.error.message if envelope.error else "unknown error"
            raise ValueError(
                f"Received error envelope from {envelope.sender_vasp_id}: {error_msg}"
            )

        ivms101 = await self.open_secure_envelope(envelope)

        transfer_id = str(uuid.uuid4())
        now = datetime.now(tz=UTC)

        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="trisa",
            ivms101=ivms101,
            status="pending",
            created_at=now,
            updated_at=now,
            counterparty_vasp=envelope.sender_vasp_id,
            # asset/amount populated by caller after blockchain correlation
            asset="UNKNOWN",
            amount="0",
            direction="incoming",
            protocol_metadata={"envelope_id": envelope.id},
        )

        self._transfers[transfer_id] = transfer

        log.info(
            "TRISA: incoming transfer stored, awaiting compliance review",
            transfer_id=transfer_id,
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
        Beneficiary side — accept or reject a pending incoming TRISA transfer.

        Builds a response Secure Envelope and (in production) sends it back
        via gRPC.

        :param transfer_id: Transfer to respond to.
        :param response:    Accept/reject decision with optional beneficiary IVMS101.
        :returns: Updated TravelRuleTransfer record.
        :raises ValueError: If the transfer is not an incoming transfer.
        """
        self._assert_initialized()

        transfer = self._require_transfer(transfer_id)
        if transfer.direction != "incoming":
            raise ValueError(f"Transfer {transfer_id} is not an incoming transfer")

        new_status = "accepted" if response.accepted else "rejected"
        now = datetime.now(tz=UTC)

        log.info(
            "TRISA: responding to incoming transfer",
            transfer_id=transfer_id,
            accepted=response.accepted,
            rejection_reason=response.rejection_reason,
        )

        counterparty_info = await self.discover_counterparty(transfer.counterparty_vasp)

        response_payload = (
            response.beneficiary_ivms101
            if response.accepted and response.beneficiary_ivms101
            else transfer.ivms101
        )

        if counterparty_info.public_key and counterparty_info.endpoint:
            resp_envelope = await self.create_secure_envelope(
                response_payload,
                counterparty_info.public_key,
                transfer.counterparty_vasp,
            )
            original_id = (transfer.protocol_metadata or {}).get("envelope_id", resp_envelope.id)
            envelope_dump = {**resp_envelope.model_dump(), "id": original_id}
            if not response.accepted:
                envelope_dump["is_error"] = True
                envelope_dump["error"] = TRISAError(
                    code=TRISAErrorCode.REJECTED,
                    message=response.rejection_reason or "Transfer rejected",
                    retry=False,
                )
            resp_envelope = SecureEnvelope(**envelope_dump)

            import grpc
            from trisa.api.v1beta1 import api_pb2_grpc

            from opago_mica.compliance.trisa_grpc import trisa  # noqa: F401

            channel_creds = grpc.ssl_channel_credentials(
                root_certificates=None,
                private_key=self._key_pem,
                certificate_chain=self._cert_pem,
            )
            channel = grpc.aio.secure_channel(
                counterparty_info.endpoint,
                channel_creds,
            )
            stub = api_pb2_grpc.TRISANetworkStub(channel)
            transfer_state = 5 if response.accepted else 7  # ACCEPTED or REJECTED
            proto_env = self._to_proto_envelope(resp_envelope, transfer_state=transfer_state)
            try:
                await stub.Transfer(proto_env)
            finally:
                await channel.close()

        updated = transfer.model_copy(
            update={"status": new_status, "updated_at": now}
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
        Validate an IVMS101 payload against TRISA requirements.

        TRISA requires originator natural persons to have a LEGL name identifier.

        :param payload: IVMS101 payload to validate.
        :returns: ValidationResult with any errors found.
        """
        errors: list[str] = []

        if not payload.originator:
            errors.append("originator is required")
        else:
            if not payload.originator.originator_persons:
                errors.append("originator.originator_persons must have at least one entry")
            if not payload.originator.account_number:
                errors.append(
                    "originator.account_number must have at least one entry (blockchain address)"
                )

        if not payload.beneficiary:
            errors.append("beneficiary is required")
        else:
            if not payload.beneficiary.beneficiary_persons:
                errors.append(
                    "beneficiary.beneficiary_persons must have at least one entry"
                )
            if not payload.beneficiary.account_number:
                errors.append(
                    "beneficiary.account_number must have at least one entry (blockchain address)"
                )

        # TRISA requires natural persons to have a legal name
        for person in (payload.originator.originator_persons if payload.originator else []):
            if person.natural_person:
                from_name = any(
                    any(n.name_identifier_type == "LEGL" for n in nr.name_identifiers)
                    for nr in (person.natural_person.name or [])
                )
                from_identifier = any(
                    n.name_identifier_type == "LEGL"
                    for n in (person.natural_person.name_identifier or [])
                )
                if not (from_name or from_identifier):
                    errors.append(
                        "originator natural person must have a LEGL nameIdentifierType"
                    )

        return ValidationResult(valid=len(errors) == 0, errors=errors)

    # -------------------------------------------------------------------------
    # TRISA-specific public helpers
    # -------------------------------------------------------------------------

    async def lookup_vasp(self, vasp_id: str) -> TRISAVASPRecord:
        """
        Look up a VASP record from the TRISA Global Directory Service.

        :param vasp_id: VASP domain or registered TRISA ID.
        :returns: TRISAVASPRecord from the GDS.
        """
        log.debug("TRISA GDS: looking up VASP", vasp_id=vasp_id)

        from trisa.gds.api.v1beta1 import api_pb2, api_pb2_grpc

        from opago_mica.compliance.trisa_grpc import trisa  # noqa: F401

        stub = api_pb2_grpc.TRISADirectoryStub(self._gds_channel)
        request = api_pb2.LookupRequest(common_name=vasp_id)
        reply = await stub.Lookup(request)

        if reply.error and reply.error.code != 0:
            raise ValueError(
                f"TRISA GDS Lookup failed for {vasp_id}: {reply.error.message}"
            )

        signing_pem = ""
        if reply.signing_certificate and reply.signing_certificate.data:
            from cryptography.hazmat.primitives import serialization
            from cryptography.x509 import load_der_x509_certificate

            cert = load_der_x509_certificate(reply.signing_certificate.data)
            signing_pem = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

        return TRISAVASPRecord(
            id=reply.id or vasp_id,
            name=reply.name or f"VASP: {vasp_id}",
            website=f"https://{reply.common_name or vasp_id}",
            common_name=reply.common_name or vasp_id,
            trp_endpoint=reply.endpoint or f"{vasp_id}:443",
            signing_certificate=signing_pem or (
                "-----BEGIN CERTIFICATE-----\n(no cert from GDS)\n-----END CERTIFICATE-----"
            ),
            verified_on=reply.verified_on or datetime.now(tz=UTC).isoformat(),
            first_listed=reply.verified_on or datetime.now(tz=UTC).isoformat(),
            country=reply.country or "XX",
        )

    async def create_secure_envelope(
        self,
        payload: IVMS101Payload,
        recipient_public_key_pem: str,
        receiver_vasp_id: str,
    ) -> SecureEnvelope:
        """
        Seal an IVMS101 payload into a TRISA Secure Envelope.

        Algorithm:
          1. Serialise IVMS101 to JSON → plaintext
          2. Generate a random 256-bit AES session key
          3. Encrypt plaintext with AES-256-GCM → ciphertext + IV + tag
          4. Encrypt session key with recipient RSA public key (OAEP-SHA512)
          5. Return SecureEnvelope

        :param payload:                   IVMS101 payload to seal.
        :param recipient_public_key_pem:  PEM-encoded recipient public key.
        :param receiver_vasp_id:          Recipient VASP identifier.
        :returns: Sealed SecureEnvelope.
        """
        log.debug("TRISA: creating secure envelope", receiver_vasp_id=receiver_vasp_id)

        plaintext = json.dumps(payload.model_dump()).encode("utf-8")

        # 1. Generate ephemeral AES-256 key + IV
        aes_key = os.urandom(32)   # 256-bit
        iv = os.urandom(12)         # 96-bit IV for GCM

        # 2. AES-256-GCM encrypt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(aes_key)
        # AESGCM.encrypt returns ciphertext + 16-byte tag appended
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # 3. RSA-OAEP encrypt the AES key with the recipient's public key
        encrypted_key_b64: str
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            public_key = serialization.load_pem_public_key(
                recipient_public_key_pem.encode("utf-8")
            )
            encrypted_key = public_key.encrypt(  # type: ignore[union-attr]
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            )
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
        except Exception:
            # Placeholder cert is not a real key — use empty string in dev
            log.warning(
                "TRISA: RSA encryption skipped (placeholder cert), using empty encrypted_key"
            )
            encrypted_key_b64 = ""

        envelope = SecureEnvelope(
            id=str(uuid.uuid4()),
            encrypted_payload=base64.b64encode(ciphertext + tag).decode(),
            encrypted_key=encrypted_key_b64,
            iv=base64.b64encode(iv).decode(),
            hmac=base64.b64encode(tag).decode(),
            encryption_algorithm="AES256-GCM",
            key_encryption_algorithm="RSA-OAEP-SHA512",
            sender_vasp_id=self._config.vasp_id,
            receiver_vasp_id=receiver_vasp_id,
            sent_at=datetime.now(tz=UTC).isoformat(),
            is_error=False,
        )

        log.debug("TRISA: secure envelope created", envelope_id=envelope.id)
        return envelope

    def _http_bridge_endpoint(self, endpoint: str | None) -> str | None:
        """Return a usable HTTP bridge URL when the endpoint is HTTP-based."""
        if endpoint is None:
            return None
        if not endpoint.startswith(("http://", "https://")):
            return None
        if endpoint.rstrip("/").endswith("/api/travel-rule/trisa"):
            return endpoint
        return endpoint.rstrip("/") + "/api/travel-rule/trisa"

    async def _post_http_bridge(
        self,
        endpoint: str,
        envelope: SecureEnvelope,
    ) -> dict[str, Any]:
        """Send a secure envelope through the HTTP bridge used in local/demo setups."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                endpoint,
                headers={"X-TRISA-Sender": self._config.vasp_id},
                json=envelope.model_dump(mode="json"),
            )

        try:
            payload: dict[str, Any] = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"TRISA HTTP bridge returned non-JSON response ({response.status_code})"
            ) from exc

        if response.is_error:
            error_message = payload.get("detail") or payload.get("error") or response.text
            raise RuntimeError(
                f"TRISA HTTP bridge request failed with status {response.status_code}: "
                f"{error_message}"
            )

        return payload

    def _map_transfer_state(self, state: Any) -> str:
        """Normalize bridge response states to TravelRuleTransfer statuses."""
        normalized = str(state or "").strip().lower()
        if normalized in {"pending", "accepted", "rejected", "expired"}:
            return normalized
        return "accepted"

    async def open_secure_envelope(self, envelope: SecureEnvelope) -> IVMS101Payload:
        """
        Open (decrypt) an incoming TRISA Secure Envelope using this VASP's private key.

        Algorithm (reverse of create_secure_envelope):
          1. RSA-OAEP decrypt encrypted_key → AES session key
          2. AES-256-GCM decrypt encrypted_payload with session key + IV
          3. Parse JSON → IVMS101Payload

        :param envelope: Sealed SecureEnvelope to open.
        :returns: Decrypted IVMS101Payload.
        """
        log.debug(
            "TRISA: opening secure envelope",
            envelope_id=envelope.id,
            sender_vasp_id=envelope.sender_vasp_id,
        )

        if not envelope.encrypted_key:
            # Dev placeholder: payload may be base64-encoded plain JSON
            try:
                raw = base64.b64decode(envelope.encrypted_payload).decode("utf-8")
                return IVMS101Payload.model_validate_json(raw)
            except Exception as exc:
                raise ValueError(
                    f"Failed to open TRISA secure envelope {envelope.id}: "
                    "encrypted_key is empty and payload is not plain JSON"
                ) from exc

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        private_key = getattr(self, "_private_key", None)
        if private_key is None:
            from cryptography.hazmat.primitives import serialization

            with open(self._config.private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

        aes_key = private_key.decrypt(
            base64.b64decode(envelope.encrypted_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )

        combined = base64.b64decode(envelope.encrypted_payload)
        ciphertext = combined[:-16]
        auth_tag = combined[-16:]
        iv = base64.b64decode(envelope.iv)

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
        return IVMS101Payload.model_validate_json(plaintext.decode("utf-8"))

    # -------------------------------------------------------------------------
    # Proto envelope mapping
    # -------------------------------------------------------------------------

    def _to_proto_envelope(
        self,
        envelope: SecureEnvelope,
        *,
        transfer_state: int = 1,
    ) -> Any:
        """Convert our SecureEnvelope to TRISA proto SecureEnvelope."""
        from trisa.api.v1beta1 import api_pb2

        payload_bytes = base64.b64decode(envelope.encrypted_payload)
        enc_key_bytes = base64.b64decode(envelope.encrypted_key) if envelope.encrypted_key else b""
        hmac_bytes = base64.b64decode(envelope.hmac) if envelope.hmac else b""

        return api_pb2.SecureEnvelope(
            id=envelope.id,
            payload=payload_bytes,
            encryption_key=enc_key_bytes,
            encryption_algorithm=envelope.encryption_algorithm,
            hmac=hmac_bytes,
            hmac_secret=enc_key_bytes,
            hmac_algorithm="HMAC-SHA256",
            sealed=bool(envelope.encrypted_key),
            timestamp=envelope.sent_at,
            transfer_state=transfer_state,
        )

    def _from_proto_envelope(
        self,
        proto: Any,
        *,
        sender_vasp_id: str = "",
        receiver_vasp_id: str = "",
    ) -> SecureEnvelope:
        """Convert TRISA proto SecureEnvelope to our SecureEnvelope model."""
        error_obj = None
        if getattr(proto, "error", None) and proto.error.code != 0:
            error_obj = TRISAError(
                code=proto.error.code,
                message=proto.error.message or "Unknown error",
                retry=False,
            )
        is_error = error_obj is not None

        return SecureEnvelope(
            id=proto.id,
            encrypted_payload=base64.b64encode(proto.payload).decode() if proto.payload else "",
            encrypted_key=(
                base64.b64encode(proto.encryption_key).decode()
                if proto.encryption_key
                else ""
            ),
            iv="",
            hmac=base64.b64encode(proto.hmac).decode() if proto.hmac else "",
            encryption_algorithm=proto.encryption_algorithm or "AES256-GCM",
            key_encryption_algorithm="RSA-OAEP-SHA512",
            sender_vasp_id=sender_vasp_id,
            receiver_vasp_id=receiver_vasp_id,
            sent_at=proto.timestamp or datetime.now(tz=UTC).isoformat(),
            is_error=is_error,
            error=error_obj,
        )

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _assert_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError(
                "TRISAAdapter is not initialized — call initialize() first"
            )

    def _require_transfer(self, transfer_id: str) -> TravelRuleTransfer:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise KeyError(f"Transfer not found: {transfer_id}")
        return transfer
