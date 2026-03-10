"""
TRUST Adapter — Travel Rule Universal Solution Technology (Coinbase).

Implements the TravelRuleProvider interface for the Coinbase TRUST protocol.

Key characteristics of TRUST:
 - Decentralised peer-to-peer data sharing — no central data store
 - End-to-end encrypted transmission of IVMS101 PII data
 - Proof of address ownership before personal data is exchanged
 - Blockchain-agnostic — supports all digital assets
 - Members include Coinbase, Kraken, Gemini, Binance.US, Crypto.com,
   PayPal, Revolut, Robinhood, and others
 - Membership requires core AML, security, and privacy compliance

Protocol flow:
 1. Originator VASP looks up beneficiary address in TRUST network
 2. Beneficiary VASP proves ownership of the receiving address
 3. IVMS101 data is encrypted end-to-end and transmitted directly
 4. Beneficiary confirms receipt and compliance check result

References:
 - https://www.coinbase.com/blog/introducing-the-travel-rule-universal-solution-technology-trust
 - Coinbase Exchange API — POST /travel-rules

NOTE: This adapter provides a complete structural and logical
implementation. Actual TRUST network API calls require a TRUST membership
and API credentials. These sections are clearly marked with TODO comments.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
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

log = create_logger("TRUSTAdapter")

# ---------------------------------------------------------------------------
# TRUST-specific types
# ---------------------------------------------------------------------------


class TRUSTConfig(BaseModel):
    """Configuration for the TRUST protocol adapter."""

    model_config = ConfigDict(populate_by_name=True)

    #: TRUST member identifier (assigned upon membership approval).
    member_id: str
    #: API key for TRUST network authentication.
    api_key: str
    #: API secret for signing TRUST requests.
    api_secret: str
    #: TRUST network endpoint, e.g. "https://trust-api.coinbase.com".
    endpoint: str
    #: This VASP's registered domain.
    vasp_domain: str


class TRUSTMember(BaseModel):
    """TRUST member record returned by the directory lookup."""

    model_config = ConfigDict(populate_by_name=True)

    #: TRUST member identifier.
    member_id: str
    #: Human-readable name of the VASP.
    name: str
    #: Member's registered domain.
    domain: str
    #: PEM-encoded public key for encrypting PII.
    public_key: str
    #: TRUST compliance status.
    compliance_status: TRUSTComplianceStatus
    #: Supported asset types.
    supported_assets: list[str]
    #: TRUST network endpoint for this member.
    endpoint: str


TRUSTComplianceStatus = Literal["active", "pending", "suspended", "revoked"]


class AddressOwnershipProof(BaseModel):
    """Address ownership proof request / response."""

    model_config = ConfigDict(populate_by_name=True)

    #: The blockchain address to prove ownership of.
    address: str
    #: The asset/chain identifier, e.g. "BTC", "ETH".
    asset: str
    #: Nonce for the proof challenge.
    nonce: str
    #: Cryptographic signature proving ownership.
    signature: str
    #: ISO 8601 timestamp of proof generation.
    timestamp: str


class TRUSTTransferPayload(BaseModel):
    """TRUST transfer request payload."""

    model_config = ConfigDict(populate_by_name=True)

    #: Unique request identifier.
    request_id: str
    #: Originator TRUST member ID.
    originator_member_id: str
    #: Beneficiary TRUST member ID.
    beneficiary_member_id: str
    #: Encrypted IVMS101 payload (base64).
    encrypted_payload: str
    #: RSA-OAEP encrypted AES key (base64).
    encrypted_key: str
    #: AES-GCM IV (base64).
    iv: str
    #: AES-GCM auth tag (base64).
    auth_tag: str
    #: Blockchain transaction hash.
    tx_hash: str
    #: Asset identifier.
    asset: str
    #: Transfer amount.
    amount: str
    #: Address ownership proof from the beneficiary VASP.
    address_proof: AddressOwnershipProof | None = None
    #: ISO 8601 timestamp.
    created_at: str


class TRUSTTransferResponse(BaseModel):
    """TRUST transfer response from the beneficiary."""

    model_config = ConfigDict(populate_by_name=True)

    #: Request identifier echoed back.
    request_id: str
    status: Literal["accepted", "rejected", "pending"]
    rejection_reason: str | None = None
    #: Beneficiary IVMS101 data (encrypted, base64).
    encrypted_beneficiary_payload: str | None = None
    #: ISO 8601 timestamp.
    responded_at: str


class TRUSTRejectionCode(StrEnum):
    """TRUST rejection codes."""

    ADDRESS_MISMATCH = "ADDRESS_MISMATCH"
    COMPLIANCE_FAILURE = "COMPLIANCE_FAILURE"
    MEMBER_NOT_ACTIVE = "MEMBER_NOT_ACTIVE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    UNSUPPORTED_ASSET = "UNSUPPORTED_ASSET"
    PROOF_FAILED = "PROOF_FAILED"


# ---------------------------------------------------------------------------
# TRUST Adapter
# ---------------------------------------------------------------------------


class TRUSTAdapter(TravelRuleProvider):
    """
    TravelRuleProvider implementation for the Coinbase TRUST protocol.

    Manages address-ownership-proof verification and end-to-end encrypted
    IVMS101 transmission. All HTTP API calls are stubbed with TODO markers.

    :param config: TRUST configuration (member ID, API credentials, endpoint).
    """

    protocol = "trust"

    def __init__(self, config: TRUSTConfig) -> None:
        self._config = config
        self._transfers: dict[str, TravelRuleTransfer] = {}
        self._initialized = False

    # -------------------------------------------------------------------------
    # TravelRuleProvider — lifecycle
    # -------------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Boot the TRUST adapter.

        Validates API credentials and (in production) verifies TRUST membership
        status and registers this VASP's public key.

        TODO: Call TRUST membership verification and public key registration APIs.
        """
        log.info(
            "Initializing TRUST adapter",
            member_id=self._config.member_id,
            endpoint=self._config.endpoint,
        )

        if not self._config.api_key or not self._config.api_secret:
            raise ValueError("TRUST adapter requires api_key and api_secret")

        # TODO: Verify TRUST membership status via API
        #   member_status = await self._verify_membership()
        #   if member_status.compliance_status != "active":
        #       raise RuntimeError(
        #           f"TRUST membership not active: {member_status.compliance_status}"
        #       )

        # TODO: Register this VASP's public key with the TRUST network
        #   await self._register_public_key()

        self._initialized = True
        log.info("TRUST adapter initialized", member_id=self._config.member_id)

    # -------------------------------------------------------------------------
    # TravelRuleProvider — counterparty discovery
    # -------------------------------------------------------------------------

    async def discover_counterparty(self, vasp_domain: str) -> CounterpartyInfo:
        """
        Discover capabilities of a counterparty VASP via the TRUST member directory.

        :param vasp_domain: Internet domain of the counterparty VASP.
        :returns: CounterpartyInfo with TRUST member ID and public key.
        :raises ValueError: If the counterparty is not an active TRUST member.
        """
        self._assert_initialized()
        log.debug("TRUST: looking up counterparty member", vasp_domain=vasp_domain)

        member = await self.lookup_member(vasp_domain)

        if member.compliance_status != "active":
            raise ValueError(
                f"TRUST: counterparty {vasp_domain} is not an active member "
                f"(status: {member.compliance_status})"
            )

        return CounterpartyInfo(
            vasp_id=member.member_id,
            name=member.name,
            domain=member.domain,
            supported_protocols=["trust"],
            public_key=member.public_key,
            endpoint=member.endpoint,
        )

    # -------------------------------------------------------------------------
    # TravelRuleProvider — send (originator side)
    # -------------------------------------------------------------------------

    async def send_transfer(self, params: SendTransferParams) -> TravelRuleTransfer:
        """
        Originator side — verify address ownership, encrypt IVMS101, and submit
        the transfer to the TRUST network.

        :param params: Transfer parameters.
        :returns: Completed TravelRuleTransfer record.
        :raises ValueError: If validation fails or counterparty has no public key.
        """
        self._assert_initialized()

        validation = self.validate_payload(params.ivms101)
        if not validation.valid:
            raise ValueError(
                f"IVMS101 validation failed: {'; '.join(validation.errors)}"
            )

        transfer_id = str(uuid.uuid4())
        request_id = f"{self._config.member_id}-{transfer_id}"
        now = datetime.now(tz=UTC)

        log.info(
            "TRUST: initiating outgoing transfer",
            transfer_id=transfer_id,
            counterparty_vasp=params.counterparty.vasp_id,
            asset=params.asset,
            amount=params.amount,
        )

        # Step 1: Request address ownership proof from beneficiary VASP
        proof = await self.request_address_proof(
            params.counterparty,
            params.tx_hash,
            params.asset,
        )

        # Step 2: Verify the proof
        if not self.verify_address_proof(proof):
            raise ValueError(
                f"TRUST: address ownership proof verification failed "
                f"for {params.counterparty.vasp_id}"
            )

        # Step 3: Encrypt and send IVMS101 payload
        if not params.counterparty.public_key:
            raise ValueError(
                f"No public key available for counterparty {params.counterparty.vasp_id}"
            )

        encrypted_data = self.encrypt_payload(params.ivms101, params.counterparty.public_key)

        trust_payload = TRUSTTransferPayload(
            request_id=request_id,
            originator_member_id=self._config.member_id,
            beneficiary_member_id=params.counterparty.vasp_id,
            encrypted_payload=encrypted_data["ciphertext"],
            encrypted_key=encrypted_data["encrypted_key"],
            iv=encrypted_data["iv"],
            auth_tag=encrypted_data["auth_tag"],
            tx_hash=params.tx_hash,
            asset=params.asset,
            amount=params.amount,
            address_proof=proof,
            created_at=now.isoformat(),
        )
        _ = trust_payload  # Used in production API call (see TODO below)

        # TODO: Send to TRUST network via API
        #   import httpx
        #   auth_token = await self._generate_auth_token()
        #   async with httpx.AsyncClient() as client:
        #       response = await client.post(
        #           f"{self._config.endpoint}/v1/travel-rules",
        #           json=trust_payload.model_dump(),
        #           headers={
        #               "Content-Type": "application/json",
        #               "Authorization": f"Bearer {auth_token}",
        #               "X-TRUST-Member-Id": self._config.member_id,
        #           },
        #       )
        #   response.raise_for_status()
        #   trust_response = TRUSTTransferResponse.model_validate(response.json())

        # Placeholder: simulate accepted response
        trust_response = TRUSTTransferResponse(
            request_id=request_id,
            status="accepted",
            responded_at=datetime.now(tz=UTC).isoformat(),
        )

        status: Any = (
            "accepted" if trust_response.status == "accepted"
            else "rejected" if trust_response.status == "rejected"
            else "pending"
        )

        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="trust",
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
                "request_id": request_id,
                "trust_member_id": params.counterparty.vasp_id,
                "address_proof_verified": True,
            },
        )

        self._transfers[transfer_id] = transfer
        log.info("TRUST: outgoing transfer complete", transfer_id=transfer_id, status=status)
        return transfer

    # -------------------------------------------------------------------------
    # TravelRuleProvider — receive (beneficiary side)
    # -------------------------------------------------------------------------

    async def handle_incoming_transfer(self, raw_data: Any) -> TravelRuleTransfer:
        """
        Beneficiary side — receive and decrypt an incoming TRUST transfer payload.

        :param raw_data: A :class:`TRUSTTransferPayload` instance (or dict).
        :returns: Parsed TravelRuleTransfer with status 'pending'.
        """
        self._assert_initialized()

        if isinstance(raw_data, dict):
            payload = TRUSTTransferPayload.model_validate(raw_data)
        else:
            payload = raw_data  # type: TRUSTTransferPayload

        log.info(
            "TRUST: received incoming transfer",
            request_id=payload.request_id,
            originator_member_id=payload.originator_member_id,
        )

        ivms101 = self.decrypt_payload(payload)

        transfer_id = str(uuid.uuid4())
        now = datetime.now(tz=UTC)

        transfer = TravelRuleTransfer(
            transfer_id=transfer_id,
            protocol="trust",
            ivms101=ivms101,
            status="pending",
            created_at=now,
            updated_at=now,
            counterparty_vasp=payload.originator_member_id,
            tx_hash=payload.tx_hash,
            asset=payload.asset,
            amount=payload.amount,
            direction="incoming",
            protocol_metadata={
                "request_id": payload.request_id,
                "trust_member_id": payload.originator_member_id,
            },
        )

        self._transfers[transfer_id] = transfer
        log.info(
            "TRUST: incoming transfer stored, awaiting compliance review",
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
        Beneficiary side — accept or reject a pending TRUST transfer.

        :param transfer_id: Transfer to respond to.
        :param response:    Accept/reject decision.
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
            "TRUST: responding to incoming transfer",
            transfer_id=transfer_id,
            accepted=response.accepted,
            rejection_reason=response.rejection_reason,
        )

        # TODO: Send response back to TRUST network
        #   trust_response = TRUSTTransferResponse(
        #       request_id=str(transfer.protocol_metadata.get("request_id", "")),
        #       status="accepted" if response.accepted else "rejected",
        #       rejection_reason=response.rejection_reason,
        #       responded_at=now.isoformat(),
        #   )
        #   request_id = trust_response.request_id
        #   import httpx
        #   auth_token = await self._generate_auth_token()
        #   async with httpx.AsyncClient() as client:
        #       await client.post(
        #           f"{self._config.endpoint}/v1/travel-rules/{request_id}/respond",
        #           json=trust_response.model_dump(),
        #           headers={
        #               "Content-Type": "application/json",
        #               "Authorization": f"Bearer {auth_token}",
        #               "X-TRUST-Member-Id": self._config.member_id,
        #           },
        #       )

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
        Validate an IVMS101 payload against TRUST requirements.

        TRUST requires the originator to have a LEGL name identifier.

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

        # TRUST requires the originator to have a legal name
        for person in (payload.originator.originator_persons if payload.originator else []):
            if person.natural_person:
                # Check structured name records (NaturalPersonName list)
                has_legal_name_in_names = any(
                    any(n.name_identifier_type == "LEGL" for n in name_record.name_identifiers)
                    for name_record in (person.natural_person.name or [])
                )
                # Check flat name identifiers (NaturalPersonNameIdentifier list)
                has_legal_name_in_identifiers = any(
                    n.name_identifier_type == "LEGL"
                    for n in (person.natural_person.name_identifier or [])
                )
                if not has_legal_name_in_names and not has_legal_name_in_identifiers:
                    errors.append(
                        "originator natural person must have a LEGL nameIdentifierType"
                    )

        return ValidationResult(valid=len(errors) == 0, errors=errors)

    # -------------------------------------------------------------------------
    # TRUST-specific public helpers
    # -------------------------------------------------------------------------

    async def lookup_member(self, vasp_domain: str) -> TRUSTMember:
        """
        Look up a TRUST member by domain.

        :param vasp_domain: Domain of the VASP to look up.
        :returns: TRUSTMember record.

        TODO: Replace placeholder with a real TRUST directory API call.
        """
        log.debug("TRUST: looking up member", vasp_domain=vasp_domain)

        # TODO: Call TRUST directory API
        #   import httpx
        #   auth_token = await self._generate_auth_token()
        #   async with httpx.AsyncClient() as client:
        #       response = await client.get(
        #           f"{self._config.endpoint}/v1/members?domain={vasp_domain}",
        #           headers={
        #               "Authorization": f"Bearer {auth_token}",
        #               "X-TRUST-Member-Id": self._config.member_id,
        #           },
        #       )
        #   response.raise_for_status()
        #   return TRUSTMember.model_validate(response.json()["member"])

        # Placeholder
        return TRUSTMember(
            member_id=f"trust-{vasp_domain}",
            name=f"VASP: {vasp_domain}",
            domain=vasp_domain,
            public_key="-----BEGIN PUBLIC KEY-----\n(placeholder)\n-----END PUBLIC KEY-----",
            compliance_status="active",
            supported_assets=["BTC", "ETH", "USDC", "USDT"],
            endpoint=f"https://{vasp_domain}/trust",
        )

    async def request_address_proof(
        self,
        counterparty: CounterpartyInfo,
        tx_hash: str,
        asset: str,
    ) -> AddressOwnershipProof:
        """
        Request address ownership proof from the beneficiary VASP.

        TRUST's key differentiator: the beneficiary must cryptographically prove
        they own the receiving address before any PII is exchanged.

        :param counterparty: Counterparty VASP info.
        :param tx_hash:      Transaction hash (used as address proxy in dev).
        :param asset:        Asset identifier.
        :returns: AddressOwnershipProof from the beneficiary VASP.

        TODO: Replace placeholder with a real TRUST proof-request API call.
        """
        log.debug(
            "TRUST: requesting address ownership proof",
            counterparty=counterparty.vasp_id,
            asset=asset,
        )

        nonce = os.urandom(32).hex()

        # TODO: Send proof request to beneficiary VASP via TRUST network
        #   import httpx
        #   auth_token = await self._generate_auth_token()
        #   async with httpx.AsyncClient() as client:
        #       response = await client.post(
        #           f"{self._config.endpoint}/v1/address-proof/request",
        #           json={
        #               "beneficiaryMemberId": counterparty.vasp_id,
        #               "address": tx_hash,
        #               "asset": asset,
        #               "nonce": nonce,
        #           },
        #           headers={
        #               "Content-Type": "application/json",
        #               "Authorization": f"Bearer {auth_token}",
        #           },
        #       )
        #   return AddressOwnershipProof.model_validate(response.json())

        # Placeholder: return a simulated valid proof
        signature = hashlib.sha256(f"{tx_hash}:{nonce}".encode()).hexdigest()
        return AddressOwnershipProof(
            address=tx_hash,
            asset=asset,
            nonce=nonce,
            signature=signature,
            timestamp=datetime.now(tz=UTC).isoformat(),
        )

    def verify_address_proof(self, proof: AddressOwnershipProof) -> bool:
        """
        Verify an address ownership proof.

        In production, verifies the cryptographic signature against the
        beneficiary VASP's known public key, ensuring they control the address.

        :param proof: AddressOwnershipProof to verify.
        :returns: True if the proof is valid.

        TODO: Replace hash comparison with real cryptographic signature verification.
        """
        log.debug(
            "TRUST: verifying address ownership proof",
            address=proof.address,
            asset=proof.asset,
        )

        # TODO: Verify the cryptographic signature
        #   from cryptography.hazmat.primitives.asymmetric import padding, ec
        #   expected_message = f"{proof.address}:{proof.nonce}".encode()
        #   public_key = ...  # fetch from TRUST directory
        #   public_key.verify(
        #       bytes.fromhex(proof.signature),
        #       expected_message,
        #       ec.ECDSA(hashes.SHA256()),
        #   )
        #   return True  # raises on failure

        # Placeholder: verify using simple hash comparison
        expected_sig = hashlib.sha256(
            f"{proof.address}:{proof.nonce}".encode()
        ).hexdigest()
        return proof.signature == expected_sig

    def encrypt_payload(
        self,
        payload: IVMS101Payload,
        recipient_public_key_pem: str,
    ) -> dict[str, str]:
        """
        Encrypt an IVMS101 payload for transmission via TRUST.

        Algorithm:
          1. Serialise IVMS101 to JSON
          2. Generate random AES-256-GCM key and IV
          3. Encrypt payload with AES-256-GCM
          4. Encrypt AES key with recipient RSA public key (OAEP-SHA256)

        :param payload:                  IVMS101 payload to encrypt.
        :param recipient_public_key_pem: PEM-encoded recipient public key.
        :returns: Dict with keys: ciphertext, encrypted_key, iv, auth_tag (all base64).
        """
        plaintext = json.dumps(payload.model_dump()).encode("utf-8")

        aes_key = os.urandom(32)
        iv = os.urandom(12)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        ciphertext = ciphertext_with_tag[:-16]
        auth_tag = ciphertext_with_tag[-16:]

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
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
        except Exception:
            log.warning(
                "TRUST: RSA encryption skipped (placeholder cert), using empty encrypted_key"
            )
            encrypted_key_b64 = ""

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "encrypted_key": encrypted_key_b64,
            "iv": base64.b64encode(iv).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
        }

    def decrypt_payload(self, payload: TRUSTTransferPayload) -> IVMS101Payload:
        """
        Decrypt an incoming TRUST transfer payload.

        TODO: Replace placeholder with real AES-256-GCM + RSA-OAEP decryption.

        :param payload: Encrypted transfer payload.
        :returns: Decrypted IVMS101Payload.
        """
        log.debug("TRUST: decrypting incoming payload", request_id=payload.request_id)

        # TODO: Decrypt using this VASP's private key
        #   with open(self._config.private_key_path, "rb") as f:
        #       private_key = serialization.load_pem_private_key(f.read(), password=None)
        #   aes_key = private_key.decrypt(
        #       base64.b64decode(payload.encrypted_key),
        #       padding.OAEP(
        #           mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #           algorithm=hashes.SHA256(),
        #           label=None,
        #       ),
        #   )
        #   iv       = base64.b64decode(payload.iv)
        #   auth_tag = base64.b64decode(payload.auth_tag)
        #   cipher   = base64.b64decode(payload.encrypted_payload)
        #
        #   aesgcm    = AESGCM(aes_key)
        #   plaintext = aesgcm.decrypt(iv, cipher + auth_tag, None)
        #   return IVMS101Payload.model_validate_json(plaintext)

        # Placeholder: try to decode base64 payload directly
        try:
            raw = base64.b64decode(payload.encrypted_payload).decode("utf-8")
            return IVMS101Payload.model_validate_json(raw)
        except Exception as exc:
            raise ValueError(
                f"Failed to decrypt TRUST payload {payload.request_id}: "
                "private key decryption not yet implemented (see TODO)"
            ) from exc

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _assert_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError(
                "TRUSTAdapter is not initialized — call initialize() first"
            )

    def _require_transfer(self, transfer_id: str) -> TravelRuleTransfer:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise KeyError(f"Transfer not found: {transfer_id}")
        return transfer
