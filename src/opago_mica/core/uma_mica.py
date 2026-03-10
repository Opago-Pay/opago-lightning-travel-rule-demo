"""
UMA MiCA Protocol Handler

Central implementation of the Universal Money Address (UMA) protocol,
customised for MiCA / EU Transfer of Funds Regulation (TFR 2023/1113).

Port of src/core/uma-mica.ts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from opago_mica.types.ivms101 import IVMS101Payload
from opago_mica.types.uma import UMAConfiguration
from opago_mica.types.uma_extended import (
    ComplianceRequirement,
    CurrencyPreference,
    KycStatus,
    MiCATransactionMetadata,
    ParsedPayRequest,
    ReceiverCapabilities,
    ResponseComplianceData,
    UMAComplianceData,
    UMAMiCAConfig,
    UMAPayerData,
    UMAPayRequest,
    UMAPayResponse,
    _PayeeData,
)
from opago_mica.utils.crypto import (
    decrypt_payload_with_pem,
    derive_public_key_pem,
    encrypt_payload_with_pem,
    generate_nonce,
    hash_data,
    sign_payload_with_pem,
    verify_payload_with_pem,
)
from opago_mica.utils.logger import create_logger, log_audit_event
from opago_mica.utils.url import build_service_url

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TRAVEL_RULE_THRESHOLD_EUR: float = 1000.0
_UMA_VERSION: str = "1.0"
_SIGNATURE_TTL_SECONDS: int = 300


# ---------------------------------------------------------------------------
# UMAMiCAProtocol
# ---------------------------------------------------------------------------


class UMAMiCAProtocol:
    """
    UMAMiCAProtocol — handles the full UMA + MiCA compliance flow.

    Example::

        protocol = UMAMiCAProtocol(UMAMiCAConfig(
            vasp_domain='vasp.example.com',
            signing_key=os.environ['UMA_SIGNING_KEY'],
            encryption_key=os.environ['UMA_ENCRYPTION_KEY'],
            travel_rule_threshold_eur=1000,
        ))
    """

    def __init__(self, config: UMAMiCAConfig) -> None:
        self._vasp_domain: str = config.vasp_domain
        self._signing_key: str = config.signing_key
        self._encryption_key: str = config.encryption_key
        self._travel_rule_threshold_eur: float = (
            config.travel_rule_threshold_eur
            if config.travel_rule_threshold_eur is not None
            else _DEFAULT_TRAVEL_RULE_THRESHOLD_EUR
        )
        self._eidas_enabled: bool = config.eidas_enabled or False
        self._uma_version: str = config.uma_version or _UMA_VERSION
        self._log = create_logger("UMAMiCAProtocol", vasp_domain=self._vasp_domain)

        self._log.info(
            "UMAMiCAProtocol initialised",
            travel_rule_threshold_eur=self._travel_rule_threshold_eur,
            eidas_enabled=self._eidas_enabled,
            uma_version=self._uma_version,
        )

    # -------------------------------------------------------------------------
    # 1. Discovery
    # -------------------------------------------------------------------------

    async def resolve_receiver(self, uma_address: str) -> ReceiverCapabilities:
        """
        Resolve a UMA address ($user@vasp.domain) to the receiver VASP's
        capabilities by performing an LNURLP lookup over HTTPS.

        Args:
            uma_address: UMA address in the format $user@vasp.domain
        """
        self._log.debug("Resolving UMA receiver", uma_address=uma_address)

        parsed = self._parse_uma_address(uma_address)
        user = parsed["user"]
        domain = parsed["domain"]
        safe_user = quote(user, safe="")
        lnurlp_url = build_service_url(domain, f"/.well-known/lnurlp/{safe_user}")

        self._log.debug("Fetching LNURLP endpoint", url=lnurlp_url)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    lnurlp_url,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": f"opago-mica/{_UMA_VERSION}",
                    },
                )
            response.raise_for_status()
            lnurlp_data: dict[str, Any] = response.json()
        except Exception as exc:
            self._log.error(
                "LNURLP lookup error",
                uma_address=uma_address,
                error=str(exc),
            )
            raise ValueError(
                f"Failed to resolve UMA address {uma_address}: {exc}"
            ) from exc

        if lnurlp_data.get("tag") != "payRequest":
            raise ValueError(
                f"Invalid LNURLP tag: expected 'payRequest', got '{lnurlp_data.get('tag')}'"
            )

        compliance = lnurlp_data.get("compliance")
        if compliance:
            sig_valid = await self._verify_lnurlp_signature(lnurlp_data, domain)
            if not sig_valid:
                self._log.warning(
                    "LNURLP compliance signature invalid",
                    domain=domain,
                    uma_address=uma_address,
                )

        raw_currencies = lnurlp_data.get("currencies") or []
        currencies: list[CurrencyPreference] = []
        for c in raw_currencies:
            pref = CurrencyPreference(
                code=c["code"],
                name=c["name"],
                symbol=c["symbol"],
                decimals=c["decimals"],
            )
            min_sendable = c.get("minSendable", c.get("min_sendable"))
            max_sendable = c.get("maxSendable", c.get("max_sendable"))
            if min_sendable is not None:
                pref.min_sendable = min_sendable
            if max_sendable is not None:
                pref.max_sendable = max_sendable
            currencies.append(pref)

        uma_configuration = await self._fetch_uma_configuration(domain)
        uma_version_raw = (
            lnurlp_data.get("umaVersion")
            or lnurlp_data.get("uma_version")
            or uma_configuration.uma_version
        )
        encryption_pub_key = (
            uma_configuration.encryption_pubkey
            or (compliance.get("encryptionPubKey") if compliance else None)
            or (compliance.get("encryptionPublicKey") if compliance else None)
            or (compliance.get("encryption_public_key") if compliance else None)
            or ""
        )
        signing_pub_key = self._extract_signing_key_from_uma_configuration(
            uma_configuration
        ) or ""
        capabilities = ReceiverCapabilities(
            uma_address=uma_address,
            uma_versions=[uma_version_raw] if uma_version_raw else [_UMA_VERSION],
            currencies=currencies,
            encryption_pub_key=encryption_pub_key,
            signing_pub_key=signing_pub_key,
            requires_travel_rule=(
                compliance.get("isSubjectToTravelRule")
                or lnurlp_data.get("travelRuleRequired")
                or lnurlp_data.get("travel_rule_required")
                or False
            )
            if compliance
            else bool(
                lnurlp_data.get("travelRuleRequired")
                or lnurlp_data.get("travel_rule_required")
            ),
            min_sendable=lnurlp_data.get("minSendable", lnurlp_data.get("min_sendable", 0)),
            max_sendable=lnurlp_data.get("maxSendable", lnurlp_data.get("max_sendable", 0)),
            vasp_domain=domain,
        )

        self._log.info(
            "UMA receiver resolved",
            uma_address=uma_address,
            vasp_domain=domain,
            requires_travel_rule=capabilities.requires_travel_rule,
            currencies=[c.code for c in capabilities.currencies],
        )

        return capabilities

    def get_signing_public_key_pem(self) -> str:
        """Return the VASP signing public key in PEM format."""
        return derive_public_key_pem(self._signing_key)

    def get_encryption_public_key_pem(self) -> str:
        """Return the VASP encryption public key in PEM format."""
        return derive_public_key_pem(self._encryption_key)

    def build_lnurlp_compliance(
        self,
        *,
        receiver_identifier: str,
        is_subject_to_travel_rule: bool,
        kyc_status: KycStatus,
    ) -> dict[str, Any]:
        """Build a UMA-style LNURLP compliance block."""
        signature_nonce = generate_nonce(16)
        signature_timestamp = int(datetime.now(tz=UTC).timestamp())
        signature_payload = {
            "receiverIdentifier": receiver_identifier,
            "signatureNonce": signature_nonce,
            "signatureTimestamp": signature_timestamp,
        }
        signature = sign_payload_with_pem(
            signature_payload,
            self._signing_key,
            self._vasp_domain,
            _SIGNATURE_TTL_SECONDS,
        ).token

        return {
            "isSubjectToTravelRule": is_subject_to_travel_rule,
            "kycStatus": kyc_status.value,
            "signature": signature,
            "signatureNonce": signature_nonce,
            "signatureTimestamp": signature_timestamp,
            "receiverIdentifier": receiver_identifier,
        }

    def get_travel_rule_threshold_eur(self) -> float:
        """Return the configured travel rule threshold in EUR."""
        return self._travel_rule_threshold_eur

    # -------------------------------------------------------------------------
    # 2. Build Compliance Payer Data
    # -------------------------------------------------------------------------

    async def build_compliance_payer_data(
        self,
        *,
        payer_identifier: str,
        payer_name: str,
        payer_email: str | None = None,
        receiver_encryption_pub_key: str,
        travel_rule_info: IVMS101Payload,
        kyc_status: KycStatus,
    ) -> UMAComplianceData:
        """
        Build a MiCA-compliant UMAComplianceData object for the payer.

        Args:
            payer_identifier:         UMA address of the payer
            payer_name:               Legal full name of the payer
            payer_email:              Optional email address
            receiver_encryption_pub_key: PEM-encoded receiver VASP public key
            travel_rule_info:         IVMS101 payload to encrypt and attach
            kyc_status:               KYC verification status at this VASP
        """
        self._log.debug(
            "Building compliance payer data",
            payer_identifier=payer_identifier,
            kyc_status=kyc_status,
        )

        encrypted_travel_rule_info = await self._encrypt_travel_rule_info(
            travel_rule_info, receiver_encryption_pub_key
        )

        signature_nonce = generate_nonce(16)
        signature_timestamp = datetime.now(tz=UTC).isoformat()

        canonical_payload = {
            "payerIdentifier": payer_identifier,
            "kycStatus": kyc_status.value if isinstance(kyc_status, KycStatus) else kyc_status,
            "travelRuleInfoHash": hash_data(travel_rule_info.model_dump_json()),
            "nonce": signature_nonce,
            "timestamp": signature_timestamp,
            "issuer": self._vasp_domain,
        }

        sig_result = sign_payload_with_pem(
            canonical_payload,
            self._signing_key,
            self._vasp_domain,
            _SIGNATURE_TTL_SECONDS,
        )
        signature = sig_result.token

        compliance_data = UMAComplianceData(
            kyc_status=kyc_status,
            signature=signature,
            signature_nonce=signature_nonce,
            signature_timestamp=signature_timestamp,
            encrypted_travel_rule_info=encrypted_travel_rule_info,
            travel_rule_info="ivms101-2020",
        )

        self._log.debug("Compliance payer data built", kyc_status=kyc_status)
        return compliance_data

    # -------------------------------------------------------------------------
    # 3. Create MiCA Pay Request
    # -------------------------------------------------------------------------

    async def create_mica_pay_request(
        self,
        *,
        receiver_address: str,
        amount: int,
        currency: str,
        sender_ivms101: IVMS101Payload,
        receiver_encryption_key: str,
        payer_identifier: str,
        payer_name: str | None = None,
        payer_email: str | None = None,
        kyc_status: KycStatus | None = None,
    ) -> UMAPayRequest:
        """
        Construct a full UMA pay request with MiCA-compliant travel rule data.

        Args:
            receiver_address:     UMA address of the recipient
            amount:               Amount in smallest currency unit
            currency:             ISO 4217 currency code
            sender_ivms101:       IVMS101 payload for the sender
            receiver_encryption_key: PEM-encoded receiver VASP public key
            payer_identifier:     UMA address of the payer
            payer_name:           Legal full name (optional)
            payer_email:          Email address (optional)
            kyc_status:           KYC status (default VERIFIED)
        """
        self._log.info(
            "Creating MiCA pay request",
            receiver_address=receiver_address,
            amount=amount,
            currency=currency,
        )

        resolved_kyc = kyc_status if kyc_status is not None else KycStatus.VERIFIED

        compliance_data = await self.build_compliance_payer_data(
            payer_identifier=payer_identifier,
            payer_name=payer_name or "",
            payer_email=payer_email,
            receiver_encryption_pub_key=receiver_encryption_key,
            travel_rule_info=sender_ivms101,
            kyc_status=resolved_kyc,
        )

        payer_data = UMAPayerData(
            identifier=payer_identifier,
            compliance_data=compliance_data,
        )
        if payer_name is not None:
            payer_data.name = payer_name
        if payer_email is not None:
            payer_data.email = payer_email

        pay_request = UMAPayRequest(
            amount=str(amount * 1000) if currency == "SAT" else str(amount),
            convert=currency if currency != "SAT" else None,
            payer_data=payer_data,
            travel_rule_format="ivms101",
            payee_data={
                "identifier": {"mandatory": False},
                "name": {"mandatory": False},
                "compliance": {"mandatory": False},
            },
            uma_version=self._uma_version,
        )

        self._log.info(
            "MiCA pay request created",
            receiver_address=receiver_address,
            amount=amount,
        )

        return pay_request

    # -------------------------------------------------------------------------
    # 4. Parse Incoming Pay Request
    # -------------------------------------------------------------------------

    async def parse_pay_request(self, raw_request: Any) -> ParsedPayRequest:
        """
        Parse and validate an incoming pay request from a sending VASP.

        Args:
            raw_request: Raw request object (dict or UMAPayRequest)
        """
        self._log.debug("Parsing incoming pay request")

        if isinstance(raw_request, dict):
            if (
                not all(k in raw_request for k in ("payerData", "amount"))
                and not all(k in raw_request for k in ("payer_data", "amount"))
            ):
                raise ValueError("Invalid pay request: missing required fields")
            try:
                request = UMAPayRequest.model_validate(raw_request)
            except Exception as exc:
                exc_str = str(exc)
                # Pydantic ValidationError about missing identifier → cleaner message
                if "identifier" in exc_str and "missing" in exc_str:
                    raise ValueError("Invalid pay request: missing payer identifier") from exc
                raise ValueError(f"Invalid pay request: missing required fields ({exc})") from exc
        elif isinstance(raw_request, UMAPayRequest):
            request = raw_request
        else:
            raise ValueError("Invalid pay request: missing required fields")

        if not request.payer_data or not request.payer_data.identifier:
            raise ValueError("Invalid pay request: missing payer identifier")

        sender_vasp_domain = self._parse_uma_address(request.payer_data.identifier)["domain"]

        signature_verified = False
        travel_rule_info: IVMS101Payload | None = None

        if request.payer_data.compliance_data:
            compliance = request.payer_data.compliance_data

            sender_pub_key_pem: str | None = None
            try:
                sender_pub_key_pem = await self._fetch_vasp_signing_public_key(sender_vasp_domain)
            except Exception as exc:
                self._log.warning(
                    "Could not fetch sender VASP signing key",
                    sender_vasp_domain=sender_vasp_domain,
                    error=str(exc),
                )

            if sender_pub_key_pem is not None and compliance.signature:
                ver_result = verify_payload_with_pem(
                    compliance.signature,
                    sender_pub_key_pem,
                    sender_vasp_domain,
                )
                signature_verified = ver_result.valid
                if not signature_verified:
                    self._log.warning(
                        "Pay request signature verification failed",
                        sender_vasp_domain=sender_vasp_domain,
                        error=ver_result.error,
                    )

            if compliance.encrypted_travel_rule_info:
                try:
                    decrypted = decrypt_payload_with_pem(
                        compliance.encrypted_travel_rule_info,
                        self._encryption_key,
                    )
                    travel_rule_info = IVMS101Payload.model_validate(decrypted)
                except Exception as exc:
                    self._log.error(
                        "Failed to decrypt travel rule info",
                        error=str(exc),
                    )
                    raise ValueError(f"Travel rule decryption failed: {exc}") from exc

        self._log.info(
            "Pay request parsed",
            sender_vasp_domain=sender_vasp_domain,
            amount=request.amount,
            signature_verified=signature_verified,
            has_travel_rule=travel_rule_info is not None,
        )

        return ParsedPayRequest(
            request=request,
            signature_verified=signature_verified,
            sender_vasp_domain=sender_vasp_domain,
            travel_rule_info=travel_rule_info,
        )

    # -------------------------------------------------------------------------
    # 5. Build Pay Response
    # -------------------------------------------------------------------------

    async def build_pay_response(
        self,
        *,
        invoice: str,
        receiver_ivms101: IVMS101Payload | None = None,
        compliance_requirements: ComplianceRequirement,
        sender_encryption_pub_key: str | None = None,
        payer_identifier: str | None = None,
        payee_identifier: str | None = None,
        payee_name: str | None = None,
    ) -> UMAPayResponse:
        """
        Construct a UMA pay response to be returned to the sending VASP.

        Args:
            invoice:                   BOLT-11 invoice string
            receiver_ivms101:          Optional IVMS101 payload for the receiver
            compliance_requirements:   Compliance requirements for this transaction
            sender_encryption_pub_key: Optional PEM-encoded sender public key
            payer_identifier:          Optional payer UMA address (for audit)
        """
        self._log.debug("Building pay response")

        signature_nonce = generate_nonce(16)
        signature_timestamp = datetime.now(tz=UTC).isoformat()
        invoice_hash = hash_data(invoice)

        canonical_payload: dict[str, Any] = {
            "invoiceHash": invoice_hash,
            "nonce": signature_nonce,
            "timestamp": signature_timestamp,
            "issuer": self._vasp_domain,
        }

        sig_result = sign_payload_with_pem(
            canonical_payload,
            self._signing_key,
            self._vasp_domain,
            _SIGNATURE_TTL_SECONDS,
        )
        signature = sig_result.token

        encrypted_receiver_travel_rule: str | None = None
        if (
            receiver_ivms101 is not None
            and sender_encryption_pub_key is not None
            and compliance_requirements.travel_rule_required
        ):
            encrypted_receiver_travel_rule = await self._encrypt_travel_rule_info(
                receiver_ivms101, sender_encryption_pub_key
            )

        compliance_response = ResponseComplianceData(
            kyc_status=KycStatus.VERIFIED,
            signature=signature,
            signature_nonce=signature_nonce,
            signature_timestamp=signature_timestamp,
        )
        if encrypted_receiver_travel_rule is not None:
            compliance_response.encrypted_travel_rule_info = encrypted_receiver_travel_rule

        pay_response = UMAPayResponse(
            encoded_invoice=invoice,
            payee_data=_PayeeData(
                identifier=payee_identifier,
                name=payee_name,
                compliance=compliance_response,
            ),
            routes=[],
            uma_version=self._uma_version,
        )

        log_audit_event(
            "pay_response_built",
            vasp_domain=self._vasp_domain,
            invoice_hash=invoice_hash,
            payer_identifier=payer_identifier,
        )

        self._log.info(
            "Pay response built",
            has_receiver_travel_rule=encrypted_receiver_travel_rule is not None,
        )

        return pay_response

    # -------------------------------------------------------------------------
    # 6. Travel Rule Encryption / Decryption
    # -------------------------------------------------------------------------

    async def decrypt_travel_rule_info(self, encrypted: str) -> IVMS101Payload:
        """
        Decrypt a JWE-encrypted IVMS101 payload using this VASP's encryption private key.

        Args:
            encrypted: JWE compact serialisation

        Returns:
            Decrypted IVMS101Payload
        """
        self._log.debug("Decrypting travel rule info")

        decrypted = decrypt_payload_with_pem(encrypted, self._encryption_key)

        if not isinstance(decrypted, dict):
            raise ValueError("Decrypted travel rule info is not an object")

        payload = IVMS101Payload.model_validate(decrypted)
        if payload.originator is None or payload.beneficiary is None:
            raise ValueError(
                "Decrypted IVMS101 payload is missing required fields (originator / beneficiary)"
            )

        return payload

    # -------------------------------------------------------------------------
    # 7. Message Signing / Verification
    # -------------------------------------------------------------------------

    async def sign_message(self, message: str) -> str:
        """
        Sign an arbitrary message string with the VASP's signing key.
        Returns a JWS compact serialisation (JWT).

        Args:
            message: Message string to sign
        """
        result = sign_payload_with_pem(
            {"message": message, "hash": hash_data(message)},
            self._signing_key,
            self._vasp_domain,
            _SIGNATURE_TTL_SECONDS,
        )
        return result.token

    async def verify_signature(
        self,
        message: str,
        signature: str,
        sender_pub_key: str,
    ) -> bool:
        """
        Verify a JWS signature against a given public key.

        Args:
            message:       Original message that was signed
            signature:     JWS compact serialisation
            sender_pub_key: PEM-encoded public key of the signer

        Returns:
            True if the signature is valid and the message hash matches
        """
        result = verify_payload_with_pem(signature, sender_pub_key)

        if not result.valid or result.payload is None:
            self._log.debug("Signature verification failed", error=result.error)
            return False

        expected_hash = hash_data(message)
        claimed_hash = result.payload.get("hash")

        if claimed_hash != expected_hash:
            self._log.warning(
                "Message hash mismatch in signature",
                expected=expected_hash,
                received=claimed_hash,
            )
            return False

        return True

    # -------------------------------------------------------------------------
    # 8. Compliance Evaluation
    # -------------------------------------------------------------------------

    def evaluate_compliance_requirements(self, amount_eur: float) -> ComplianceRequirement:
        """
        Evaluate whether a transaction requires travel rule data exchange.
        Travel rule threshold: 1000 EUR per EU TFR 2023/1113.

        Args:
            amount_eur: Transaction amount in EUR
        """
        travel_rule_required = amount_eur >= self._travel_rule_threshold_eur

        requirement = ComplianceRequirement(
            travel_rule_required=travel_rule_required,
            travel_rule_threshold_eur=self._travel_rule_threshold_eur,
            kyc_required=True,
            eidas_signature_accepted=self._eidas_enabled,
            required_fields=(
                ["identifier", "name", "compliance"]
                if travel_rule_required
                else ["identifier", "name"]
            ),
        )

        if travel_rule_required:
            requirement.reason_code = "AMOUNT_THRESHOLD"

        self._log.debug(
            "Compliance requirements evaluated",
            amount_eur=amount_eur,
            travel_rule_required=travel_rule_required,
            threshold=self._travel_rule_threshold_eur,
        )

        return requirement

    # -------------------------------------------------------------------------
    # 9. Transaction Metadata
    # -------------------------------------------------------------------------

    def create_transaction_metadata(
        self, params: dict[str, Any]
    ) -> MiCATransactionMetadata:
        """
        Create an immutable MiCATransactionMetadata record for audit purposes.

        Args:
            params: Partial MiCATransactionMetadata fields as a dict.
        """
        transaction_id: str = params.get("transaction_id") or str(uuid.uuid4())
        timestamp: str = params.get("timestamp") or datetime.now(tz=UTC).isoformat()
        amount_eur: float = params.get("amount_eur") or 0.0
        travel_rule_required = amount_eur >= self._travel_rule_threshold_eur

        compliance_status = params.get("compliance_status")
        if not compliance_status:
            travel_rule_exchanged = params.get("travel_rule_exchanged", False)
            compliance_status = (
                "NON_COMPLIANT"
                if travel_rule_required and not travel_rule_exchanged
                else "COMPLIANT"
            )

        metadata = MiCATransactionMetadata(
            transaction_id=transaction_id,
            timestamp=timestamp,
            amount_eur=amount_eur,
            currency=params.get("currency") or "EUR",
            amount=params.get("amount") or 0,
            sender_vasp=params.get("sender_vasp") or self._vasp_domain,
            receiver_vasp=params.get("receiver_vasp") or "",
            travel_rule_exchanged=params.get("travel_rule_exchanged") or False,
            eidas_signed=params.get("eidas_signed") or False,
            compliance_status=compliance_status,
        )

        if params.get("ivms101_payload_hash") is not None:
            metadata.ivms101_payload_hash = params["ivms101_payload_hash"]
        if params.get("sender_address") is not None:
            metadata.sender_address = params["sender_address"]
        if params.get("receiver_address") is not None:
            metadata.receiver_address = params["receiver_address"]
        if params.get("payment_hash") is not None:
            metadata.payment_hash = params["payment_hash"]

        log_audit_event(
            "transaction_metadata_created",
            transaction_id=transaction_id,
            amount_eur=amount_eur,
            sender_vasp=metadata.sender_vasp,
            receiver_vasp=metadata.receiver_vasp,
            travel_rule_exchanged=metadata.travel_rule_exchanged,
            compliance_status=metadata.compliance_status,
        )

        return metadata

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _parse_uma_address(self, uma_address: str) -> dict[str, str]:
        """Parse a UMA address ($user@vasp.domain) into user and domain parts."""
        cleaned = uma_address.lstrip("$")
        at_index = cleaned.find("@")
        if at_index <= 0 or at_index == len(cleaned) - 1:
            raise ValueError(
                f'Invalid UMA address: "{uma_address}". Expected format: $user@vasp.domain'
            )
        return {
            "user": cleaned[:at_index],
            "domain": cleaned[at_index + 1 :],
        }

    async def _verify_lnurlp_signature(
        self, response: dict[str, Any], vasp_domain: str
    ) -> bool:
        """Verify the compliance signature on an LNURLP response."""
        compliance = response.get("compliance") or {}
        if not compliance.get("signature"):
            return False

        try:
            pub_key_pem = await self._fetch_vasp_signing_public_key(vasp_domain)
        except Exception:
            return False

        result = verify_payload_with_pem(compliance["signature"], pub_key_pem, vasp_domain)
        return result.valid

    async def _fetch_vasp_signing_public_key(self, vasp_domain: str) -> str:
        """Fetch the signing public key from a VASP's UMA configuration endpoint."""
        uma_config = await self._fetch_uma_configuration(vasp_domain)
        signing_key = self._extract_signing_key_from_uma_configuration(uma_config)
        if not signing_key:
            raise ValueError(
                f"UMA configuration at {vasp_domain} does not include a signing public key"
            )

        return signing_key

    async def _fetch_uma_configuration(self, vasp_domain: str) -> UMAConfiguration:
        """Fetch a VASP's UMA configuration document."""
        config_url = build_service_url(vasp_domain, "/.well-known/uma-configuration")

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    config_url,
                    headers={"Accept": "application/json"},
                )
            response.raise_for_status()
            return UMAConfiguration.model_validate(response.json())
        except Exception as exc:
            raise ValueError(
                f"Failed to fetch UMA configuration from {vasp_domain}: {exc}"
            ) from exc

    def _extract_signing_key_from_uma_configuration(
        self,
        uma_config: UMAConfiguration,
    ) -> str | None:
        """Extract a PEM signing key from a UMA configuration document."""
        if uma_config.signing_cert_chain:
            first = uma_config.signing_cert_chain[0]
            if first:
                return first
        return uma_config.signing_pub_key

    async def _encrypt_travel_rule_info(
        self, info: IVMS101Payload, recipient_pub_key: str
    ) -> str:
        """
        Encrypt an IVMS101 payload as JWE for transmission to another VASP.
        Algorithm: ECDH-ES+A256KW / A256GCM.

        Args:
            info:             IVMS101 payload to encrypt
            recipient_pub_key: PEM-encoded public key of the receiving VASP

        Returns:
            JWE compact serialisation
        """
        self._log.debug("Encrypting travel rule info")

        payload_dict = info.model_dump()
        payload_dict["payloadCreatedAt"] = datetime.now(tz=UTC).isoformat()
        payload_dict["ivmsVersion"] = "2020-1"

        result = encrypt_payload_with_pem(payload_dict, recipient_pub_key)
        return result.jwe
