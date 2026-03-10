"""
ReceivingVASP – Beneficiary-side MiCA-compliant VASP implementation

Orchestrates the complete inbound payment acceptance flow:

1. Handle LNURL-pay discovery request → advertise compliance capabilities
2. Handle UMA pay request → parse and decrypt travel rule payload
3. Verify eIDAS Verifiable Presentation (if provided)
4. Run sanctions screening and risk assessment
5. Create BOLT11 Lightning invoice via Spark wallet
6. Build and return the UMA pay response
7. Handle incoming travel rule data from out-of-band protocol adapters
8. Write audit record for every inbound payment attempt

MiCA Article 83 / EU TFR 2023/1113 compliance:
- Accepts travel rule data via TRISA, TRP, or inline (UMA-embedded, encrypted)
- Optionally requests and verifies eIDAS qualified signatures
- Sanctions screening before issuing an invoice
- Full audit trail retained per Article 17 record-keeping requirements
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from opago_mica.compliance.travel_rule_manager import TravelRuleManager
from opago_mica.compliance.travel_rule_provider import TravelRuleTransfer
from opago_mica.core.compliance_engine import ComplianceEngine
from opago_mica.core.uma_mica import UMAMiCAProtocol
from opago_mica.eidas.eidas_wallet import EIDASWalletBridge
from opago_mica.types.eidas import EIDASSignatureResponse, VerifiablePresentation
from opago_mica.types.uma import (
    LnurlpResponse,
    MandatoryField,
    PayerDataOptions,
    UMACurrency,
    VASPComplianceInfo,
)
from opago_mica.types.uma_extended import (
    ComplianceRequirement,
    EIDASAttestation,
    KycStatus,
    ParsedPayRequest,
    UMAPayResponse,
)
from opago_mica.utils.logger import create_logger
from opago_mica.utils.url import build_service_url
from opago_mica.wallet.spark_wallet import SparkWalletManager

logger = create_logger("ReceivingVASP")

# Protocol literals accepted by handleTravelRuleData
TravelRuleProtocolLiteral = Literal["trisa", "trp", "trust", "gtr", "direct"]


# ---------------------------------------------------------------------------
# Public Pydantic models
# ---------------------------------------------------------------------------


class ReceivePaymentResult(BaseModel):
    """Result of processing an inbound payment."""

    model_config = ConfigDict(populate_by_name=True)

    #: Unique payment identifier assigned by this VASP.
    payment_id: str
    #: Amount received in satoshis.
    amount_sats: int
    #: Whether the sender's identity was successfully identified.
    sender_identified: bool
    #: Whether valid travel rule data was received.
    travel_rule_received: bool
    #: Whether the sender's eIDAS presentation was verified.
    eidas_verified: bool
    #: Final compliance decision.
    compliance_status: str


class VASPUser(BaseModel):
    """A registered user of the receiving VASP."""

    model_config = ConfigDict(populate_by_name=True)

    username: str
    display_name: str
    account_id: str


class InboundPaymentAuditRecord(BaseModel):
    """Audit record for an inbound payment attempt."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    timestamp: datetime
    payment_id: str
    sender_vasp: str
    receiver_vasp: str
    amount_sats: int
    travel_rule_received: bool
    eidas_verified: bool
    compliance_status: str
    error: str | None = None


# ---------------------------------------------------------------------------
# ReceivingVASP
# ---------------------------------------------------------------------------


class ReceivingVASP:
    """
    Receiving (beneficiary) VASP implementation.

    Handles the complete MiCA-compliant payment acceptance flow.
    Instantiate once and wire to the HTTP server.

    Example::

        vasp = ReceivingVASP(
            wallet=wallet, uma_protocol=uma, travel_rule=tr, compliance=comp,
            vasp_domain='receiver.vasp.com', vasp_name='Receiver VASP'
        )
        lnurlp = await vasp.handle_lnurlp_request('alice')
        pay_response = await vasp.handle_pay_request(raw_request, 'alice')
    """

    def __init__(
        self,
        wallet: SparkWalletManager,
        uma_protocol: UMAMiCAProtocol,
        travel_rule: TravelRuleManager,
        compliance: ComplianceEngine,
        vasp_domain: str,
        vasp_name: str,
        mica_license_number: str | None = None,
        eidas_enabled: bool = True,
    ) -> None:
        self._wallet = wallet
        self._uma_protocol = uma_protocol
        self._travel_rule = travel_rule
        self._compliance = compliance
        self._vasp_domain = vasp_domain
        self._vasp_name = vasp_name
        self._mica_license_number = mica_license_number
        self._eidas_enabled = eidas_enabled

        #: Registered users (production: database lookup).
        self._users: dict[str, VASPUser] = {
            "alice": VASPUser(
                username="alice",
                display_name="Alice Demo",
                account_id="acc_alice_001",
            ),
            "bob": VASPUser(
                username="bob",
                display_name="Bob Demo",
                account_id="acc_bob_001",
            ),
        }

        #: In-memory audit log (production: persist to database).
        self._audit_log: list[InboundPaymentAuditRecord] = []

    # ---------------------------------------------------------------------------
    # Step 1: Handle LNURL-pay discovery request
    # ---------------------------------------------------------------------------

    async def handle_lnurlp_request(self, username: str) -> LnurlpResponse:
        """
        Handle a LNURL-pay discovery request for a specific username.

        Returns this VASP's compliance capabilities including:
        - Callback URL for the UMA pay request
        - Accepted currencies and min/max amounts
        - Travel rule requirements (threshold, protocols)
        - eIDAS signature acceptance

        Args:
            username: The recipient username at this VASP.

        Returns:
            LNURL-pay first response.

        Raises:
            ValueError: If the username is not found.
        """
        logger.info("Handling LNURL-pay discovery request", username=username)

        user = self._users.get(username)
        if not user:
            raise ValueError(f"User not found: {username}")

        accepted_eidas_types: list[str] = (
            ["PersonIdentificationData", "EUDigitalIdentityCredential"]
            if self._eidas_enabled
            else []
        )

        receiver_identifier = f"${username}@{self._vasp_domain}"
        compliance_info = VASPComplianceInfo(
            **self._uma_protocol.build_lnurlp_compliance(
                receiver_identifier=receiver_identifier,
                is_subject_to_travel_rule=True,
                kyc_status=KycStatus.VERIFIED,
            ),
            is_mica_regulated=True,
            travel_rule_protocols=["TRISA", "TRP", "TRUST", "GTR"],
            jurisdiction="DE",
            accepted_eidas_credential_types=accepted_eidas_types,
            mica_license_number=self._mica_license_number,
        )

        response = LnurlpResponse(
            tag="payRequest",
            callback=build_service_url(self._vasp_domain, f"/api/uma/payreq/{username}"),
            min_sendable=1_000,
            max_sendable=100_000_000_000,
            metadata=json.dumps([
                ["text/plain", f"Pay {user.display_name} at {self._vasp_name}"],
                ["text/identifier", f"${username}@{self._vasp_domain}"],
            ]),
            currencies=[
                UMACurrency(
                    code="SAT",
                    name="Satoshi",
                    symbol="sat",
                    decimals=0,
                    multiplier=1000,
                ),
                UMACurrency(
                    code="EUR",
                    name="Euro",
                    symbol="EUR",
                    decimals=2,
                    multiplier=40,
                ),
            ],
            payer_data=PayerDataOptions(
                name=MandatoryField(mandatory=False),
                identifier=MandatoryField(mandatory=False),
                compliance=MandatoryField(mandatory=True),
            ),
            eidas_signature_accepted=self._eidas_enabled,
            uma_version="1.0",
            compliance=compliance_info,
        )

        logger.info(
            "LNURL-pay response built",
            username=username,
            eidas_accepted=self._eidas_enabled,
        )

        return response

    # ---------------------------------------------------------------------------
    # Step 2: Handle UMA pay request
    # ---------------------------------------------------------------------------

    async def handle_pay_request(
        self,
        raw_request: Any,
        username: str,
    ) -> UMAPayResponse:
        """
        Handle a UMA pay request (second step in the UMA flow).

        Flow:
        1. Parse and decrypt travel rule data (via UMAMiCAProtocol.parse_pay_request)
        2. Verify eIDAS presentation if provided
        3. Run compliance checks (sanctions, risk score)
        4. Create a Lightning invoice via Spark wallet
        5. Build and return the UMA pay response

        Args:
            raw_request: The raw request body from the HTTP endpoint.
            username: The recipient username.

        Returns:
            UMA pay response with BOLT11 invoice.

        Raises:
            Exception: If compliance check rejects the payment.
        """
        payment_id = f"recv_{uuid.uuid4()}"
        logger.info("Handling UMA pay request", payment_id=payment_id, username=username)

        travel_rule_received = False
        eidas_verified = False
        sender_identified = False
        amount_sats = 0
        matched_transfer: TravelRuleTransfer | None = None

        try:
            # -------------------------------------------------------------------
            # Parse and decrypt the pay request
            # -------------------------------------------------------------------
            parsed: ParsedPayRequest = await self._uma_protocol.parse_pay_request(raw_request)

            amount_sats = self._extract_amount_sats(parsed.request.amount)
            sender_vasp_domain = parsed.sender_vasp_domain
            matched_transfer = self._resolve_travel_rule_transfer(
                parsed.request.travel_rule_transfer_id
            )

            if matched_transfer is not None:
                self._validate_referenced_transfer(
                    matched_transfer,
                    parsed.request,
                    username=username,
                    attestation=parsed.request.eidas_attestation,
                )
                travel_rule_received = True
                logger.info(
                    "Matched out-of-band travel rule transfer",
                    payment_id=payment_id,
                    transfer_id=matched_transfer.transfer_id,
                    protocol=matched_transfer.protocol,
                    status=matched_transfer.status,
                )

            if parsed.travel_rule_info:
                travel_rule_received = True
                sender_identified = True
                logger.info(
                    "Travel rule data received and decrypted",
                    payment_id=payment_id,
                    sender_vasp_domain=sender_vasp_domain,
                )

                # Validate IVMS101 structure
                validation = self._compliance.validate_ivms101(
                    parsed.travel_rule_info,
                    "originator",
                )
                if not validation.valid:
                    logger.warning(
                        "IVMS101 validation warnings",
                        payment_id=payment_id,
                        errors=[e.message for e in validation.errors],
                    )

            if parsed.signature_verified:
                sender_identified = True
                logger.info("Sender VASP signature verified", payment_id=payment_id)

            # -------------------------------------------------------------------
            # Verify eIDAS presentation (if included in payer data)
            # -------------------------------------------------------------------
            raw_dict = raw_request if isinstance(raw_request, dict) else {}
            nested_eidas_presentation = None
            if parsed.request.payer_data and parsed.request.payer_data.compliance_data:
                nested_eidas_presentation = (
                    parsed.request.payer_data.compliance_data.eidas_credential_presentation
                )
            eidas_presentation_str = (
                nested_eidas_presentation
                or parsed.request.eidas_presentation
                or raw_dict.get("eidasPresentation")
            )
            if self._eidas_enabled and isinstance(eidas_presentation_str, str):
                eidas_verified = await self._verify_eidas_presentation(eidas_presentation_str)
                if eidas_verified:
                    sender_identified = True
                    logger.info("eIDAS presentation verified", payment_id=payment_id)

            if self._eidas_enabled and parsed.request.eidas_attestation is not None:
                signature_verified = await self._verify_eidas_attestation(
                    parsed.request.eidas_attestation,
                    eidas_presentation_str,
                    expected_payment_reference=(
                        matched_transfer.tx_hash if matched_transfer is not None else None
                    ),
                )
                if signature_verified:
                    eidas_verified = True
                    sender_identified = True
                    logger.info("eIDAS transaction signature verified", payment_id=payment_id)

            # -------------------------------------------------------------------
            # Compliance check
            # -------------------------------------------------------------------
            amount_eur = amount_sats * 0.0004  # conservative conversion
            compliance_decision = self._compliance.evaluate_transaction(
                amount_eur, "EUR", "DE", "DE"
            )

            logger.info(
                "Compliance decision",
                payment_id=payment_id,
                outcome=compliance_decision.outcome,
                travel_rule_required=compliance_decision.travel_rule_required,
                amount_eur=f"{amount_eur:.2f}",
            )

            if compliance_decision.outcome == "BLOCK":
                error = f"Payment blocked: {', '.join(compliance_decision.reasons)}"
                logger.warning(
                    "Payment blocked by compliance",
                    payment_id=payment_id,
                    reasons=compliance_decision.reasons,
                )
                self._write_audit_record(
                    payment_id=payment_id,
                    sender_vasp=sender_vasp_domain,
                    amount_sats=amount_sats,
                    travel_rule_received=travel_rule_received,
                    eidas_verified=eidas_verified,
                    compliance_status="REJECTED",
                    error=error,
                )
                raise RuntimeError(error)

            if compliance_decision.travel_rule_required and not travel_rule_received:
                error = "Payment rejected: travel rule data required but not received."
                logger.warning(error, payment_id=payment_id)
                self._write_audit_record(
                    payment_id=payment_id,
                    sender_vasp=sender_vasp_domain,
                    amount_sats=amount_sats,
                    travel_rule_received=False,
                    eidas_verified=eidas_verified,
                    compliance_status="REJECTED",
                    error=error,
                )
                raise RuntimeError(error)

            if matched_transfer is not None and matched_transfer.status == "pending":
                await self._travel_rule.respond(matched_transfer.transfer_id, accepted=True)
                logger.info(
                    "Accepted matched travel rule transfer before issuing invoice",
                    payment_id=payment_id,
                    transfer_id=matched_transfer.transfer_id,
                )

            # -------------------------------------------------------------------
            # Create Lightning invoice
            # -------------------------------------------------------------------
            comment = raw_dict.get("comment")
            invoice_memo = (
                str(comment)
                if isinstance(comment, str)
                else f"Payment to ${username}@{self._vasp_domain}"
            )

            invoice_result = await self._wallet.create_invoice(
                amount_sats=amount_sats,
                memo=invoice_memo,
            )

            logger.info(
                "Lightning invoice created",
                payment_id=payment_id,
                amount_sats=amount_sats,
                payment_hash=invoice_result.payment_hash,
            )

            # -------------------------------------------------------------------
            # Build compliance requirements for pay response
            # -------------------------------------------------------------------
            compliance_requirements: ComplianceRequirement = (
                self._uma_protocol.evaluate_compliance_requirements(amount_eur)
            )

            # -------------------------------------------------------------------
            # Build UMA pay response
            # -------------------------------------------------------------------
            sender_encryption_key = (
                parsed.request.payer_data.model_dump().get("encryptionPubKey")
                if parsed.request.payer_data
                else None
            )
            pay_response: UMAPayResponse = await self._uma_protocol.build_pay_response(
                invoice=invoice_result.invoice,
                compliance_requirements=compliance_requirements,
                payer_identifier=parsed.request.payer_data.identifier
                if parsed.request.payer_data
                else None,
                payee_identifier=f"${username}@{self._vasp_domain}",
                payee_name=self._users.get(username).display_name
                if self._users.get(username) is not None
                else username,
                **(
                    {"sender_encryption_pub_key": sender_encryption_key}
                    if isinstance(sender_encryption_key, str)
                    else {}
                ),
            )

            # -------------------------------------------------------------------
            # Write audit record
            # -------------------------------------------------------------------
            self._write_audit_record(
                payment_id=payment_id,
                sender_vasp=sender_vasp_domain,
                amount_sats=amount_sats,
                travel_rule_received=travel_rule_received,
                eidas_verified=eidas_verified,
                compliance_status=compliance_decision.outcome,
            )

            logger.info(
                "Pay request handled successfully",
                payment_id=payment_id,
                amount_sats=amount_sats,
                sender_identified=sender_identified,
                eidas_verified=eidas_verified,
                travel_rule_received=travel_rule_received,
                compliance_outcome=compliance_decision.outcome,
            )

            return pay_response

        except Exception as exc:
            error_message = str(exc)

            error_lower = error_message.lower()
            if "blocked" not in error_lower and "rejected" not in error_lower:
                # Only write if we haven't already written a REJECTED record
                self._write_audit_record(
                    payment_id=payment_id,
                    sender_vasp="unknown",
                    amount_sats=amount_sats,
                    travel_rule_received=travel_rule_received,
                    eidas_verified=eidas_verified,
                    compliance_status="ERROR",
                    error=error_message,
                )

            raise

    # ---------------------------------------------------------------------------
    # Protocol adapter entry points
    # ---------------------------------------------------------------------------

    async def handle_travel_rule_data(
        self,
        protocol: TravelRuleProtocolLiteral,
        data: Any,
        sender_vasp: str,
    ) -> TravelRuleTransfer:
        """
        Handle travel rule data received via a protocol adapter (TRP, TRISA).

        Called when travel rule data arrives out-of-band (not embedded in the
        UMA pay request). The data is routed to the appropriate registered adapter.

        Args:
            protocol: The protocol identifier.
            data: The raw payload.
            sender_vasp: The originating VASP domain.
        """
        logger.info(
            "Receiving out-of-band travel rule data",
            protocol=protocol,
            sender_vasp=sender_vasp,
        )

        try:
            transfer = await self._travel_rule.handle_incoming(protocol, data)
            logger.info(
                "Travel rule transfer stored",
                transfer_id=transfer.transfer_id if hasattr(transfer, "transfer_id") else None,
                protocol=protocol,
                sender_vasp=sender_vasp,
            )

            # Validate the received IVMS101 data
            ivms101_data = getattr(transfer, "ivms101", None)
            if ivms101_data is not None:
                validation = self._compliance.validate_ivms101(ivms101_data, "originator")
                if not validation.valid:
                    logger.warning(
                        "Received IVMS101 has validation errors",
                        transfer_id=getattr(transfer, "transfer_id", None),
                        errors=[e.message for e in validation.errors],
                    )
            return transfer
        except Exception as exc:
            logger.error(
                "Failed to handle incoming travel rule data",
                protocol=protocol,
                sender_vasp=sender_vasp,
                error=str(exc),
            )
            raise

    async def request_eidas_data(self, sender_domain: str) -> bool:
        """
        Request eIDAS data from a sender VASP.

        Used when the receiver requires eIDAS signatures but the sender
        did not include one. Sends an OpenID4VP challenge to the sender.

        Args:
            sender_domain: The sender VASP's domain.

        Returns:
            ``True`` if the request was sent successfully.
        """
        if not self._eidas_enabled:
            logger.debug("eIDAS disabled, skipping request")
            return False

        logger.info(
            "Requesting eIDAS data from sender VASP (simulated)",
            sender_domain=sender_domain,
        )
        # Production: send OpenID4VP Authorization Request to senderDomain
        return True

    # ---------------------------------------------------------------------------
    # Queries
    # ---------------------------------------------------------------------------

    def get_audit_log(self) -> list[InboundPaymentAuditRecord]:
        """Get all audit records."""
        return list(self._audit_log)

    def get_user(self, username: str) -> VASPUser | None:
        """Get a user by username."""
        return self._users.get(username)

    def list_users(self) -> list[VASPUser]:
        """List all registered users."""
        return list(self._users.values())

    # ---------------------------------------------------------------------------
    # Private: eIDAS verification
    # ---------------------------------------------------------------------------

    async def _verify_eidas_presentation(self, presentation_json: str) -> bool:
        """
        Verify an eIDAS Verifiable Presentation received in the pay request.

        Args:
            presentation_json: JSON-serialised VerifiablePresentation.

        Returns:
            ``True`` if valid.
        """
        try:
            data = json.loads(presentation_json)
            presentation = VerifiablePresentation.model_validate(data)
        except (json.JSONDecodeError, Exception) as err:
            logger.warning("Failed to parse eIDAS presentation JSON", error=str(err))
            return False

        result = await EIDASWalletBridge.verify_presentation(presentation)

        if not result.valid:
            logger.warning(
                "eIDAS presentation verification failed",
                errors=result.errors,
                issuer=result.issuer,
            )

        return result.valid

    def _resolve_travel_rule_transfer(
        self,
        transfer_id: str | None,
    ) -> TravelRuleTransfer | None:
        """Resolve a referenced transfer and fail fast when it is unknown."""
        if transfer_id is None:
            return None

        transfer = self._travel_rule.get_transfer(transfer_id)
        if transfer is None:
            raise RuntimeError(
                f"Payment rejected: referenced travel rule transfer not found: {transfer_id}"
            )
        if transfer.status == "rejected":
            raise RuntimeError(
                f"Payment rejected: referenced travel rule transfer was rejected: {transfer_id}"
            )
        return transfer

    def _extract_amount_sats(self, amount: int | str) -> int:
        """Convert the request amount into satoshis for the current Lightning-only demo."""
        amount_str = str(amount)

        if "." in amount_str:
            value, _, currency = amount_str.partition(".")
            if currency.upper() == "SAT":
                return int(value)
            raise RuntimeError(
                f"Payment rejected: unsupported UMA amount format for this demo: {amount_str}"
            )

        millisats = int(amount_str)
        if millisats < 0:
            raise RuntimeError("Payment rejected: negative UMA amount is invalid")
        if millisats % 1000 != 0:
            raise RuntimeError(
                f"Payment rejected: UMA millisat amount {millisats} is not a whole satoshi"
            )
        return millisats // 1000

    def _validate_referenced_transfer(
        self,
        transfer: TravelRuleTransfer,
        request: Any,
        *,
        username: str,
        attestation: EIDASAttestation | None,
    ) -> None:
        """Ensure the referenced out-of-band transfer matches this pay request."""
        mismatches: list[str] = []

        try:
            transfer_amount = Decimal(transfer.amount)
            request_amount = Decimal(self._extract_amount_sats(request.amount))
        except InvalidOperation:
            transfer_amount = Decimal("-1")
            request_amount = Decimal(self._extract_amount_sats(request.amount))

        if transfer_amount != request_amount:
            mismatches.append(
                f"amount mismatch (transfer={transfer.amount}, request={request.amount})"
            )

        request_identifier = request.payer_data.identifier if request.payer_data else None
        originator_accounts = transfer.ivms101.originator.account_number
        originator_account = originator_accounts[0] if originator_accounts else None
        if request_identifier is None or originator_account is None:
            mismatches.append(
                "originator account is missing from the referenced transfer or pay request"
            )
        elif originator_account != request_identifier:
            mismatches.append(
                "originator account mismatch between referenced transfer and pay request"
            )

        expected_beneficiary = f"${username}@{self._vasp_domain}"
        beneficiary_accounts = transfer.ivms101.beneficiary.account_number
        beneficiary_account = beneficiary_accounts[0] if beneficiary_accounts else None
        if beneficiary_account is None:
            mismatches.append("beneficiary account is missing from the referenced transfer")
        elif beneficiary_account != expected_beneficiary:
            mismatches.append(
                "beneficiary account mismatch between referenced transfer and receiving user"
            )

        if attestation is not None:
            if transfer.tx_hash is None:
                mismatches.append(
                    "referenced transfer is missing the payment reference needed for eIDAS binding"
                )
            elif attestation.payment_reference != transfer.tx_hash:
                mismatches.append(
                    "eIDAS attestation payment reference does not match the referenced transfer"
                )

        if mismatches:
            raise RuntimeError(
                "Payment rejected: referenced travel rule transfer does not match current "
                f"pay request ({'; '.join(mismatches)})"
            )

    async def _verify_eidas_attestation(
        self,
        attestation: EIDASAttestation,
        presentation_json: str | None,
        *,
        expected_payment_reference: str | None,
    ) -> bool:
        """Verify the transaction-bound eIDAS attestation from the sender."""
        if expected_payment_reference is None:
            logger.warning(
                "Cannot bind eIDAS attestation to the current payment without a matched transfer"
            )
            return False

        if attestation.payment_reference != expected_payment_reference:
            logger.warning(
                "eIDAS attestation payment reference mismatch",
                expected_payment_reference=expected_payment_reference,
                received_payment_reference=attestation.payment_reference,
            )
            return False

        presentation: VerifiablePresentation | None = None
        if presentation_json:
            try:
                presentation = VerifiablePresentation.model_validate_json(
                    presentation_json
                )
            except Exception as err:  # noqa: BLE001
                logger.warning(
                    "Failed to parse eIDAS presentation for signature verification",
                    error=str(err),
                )

        signature_level = attestation.signature_level
        if signature_level and "." in signature_level:
            signature_level = signature_level.rsplit(".", 1)[-1]

        response = EIDASSignatureResponse(
            approved=True,
            signature=attestation.signature,
            signing_certificate=attestation.signing_certificate,
            signed_at=attestation.signed_at,
            timestamp=attestation.signed_at,
            signature_level=signature_level,
            credential_presentation=presentation,
        )
        return await EIDASWalletBridge.verify_signature(response)

    # ---------------------------------------------------------------------------
    # Private: audit record
    # ---------------------------------------------------------------------------

    def _write_audit_record(
        self,
        payment_id: str,
        sender_vasp: str,
        amount_sats: int,
        travel_rule_received: bool,
        eidas_verified: bool,
        compliance_status: str,
        error: str | None = None,
    ) -> None:
        record = InboundPaymentAuditRecord(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=UTC),
            payment_id=payment_id,
            sender_vasp=sender_vasp,
            receiver_vasp=self._vasp_domain,
            amount_sats=amount_sats,
            travel_rule_received=travel_rule_received,
            eidas_verified=eidas_verified,
            compliance_status=compliance_status,
            error=error,
        )
        self._audit_log.append(record)
        logger.debug(
            "Audit record written",
            audit_id=record.id,
            payment_id=payment_id,
        )
