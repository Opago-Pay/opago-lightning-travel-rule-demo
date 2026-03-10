"""
SendingVASP – Originator-side MiCA-compliant VASP implementation

Orchestrates the complete outbound payment flow:

1. Resolve the receiver's UMA address and capabilities
2. Determine compliance requirements (travel rule threshold, eIDAS)
3. Build IVMS101 originator data (from VASP KYC or eIDAS wallet)
4. Optionally obtain an eIDAS qualified signature
5. Create the MiCA-compliant UMA pay request (with encrypted travel rule data)
6. Send the pay request to the receiver and receive a BOLT11 invoice
7. Pay the invoice via Spark wallet
8. Write an audit record

MiCA Article 83 / EU TFR 2023/1113 compliance:
- Originator and beneficiary information transmitted for all transfers ≥ EUR 1,000
- eIDAS qualified signature available for self-custodial users when requested
- All IVMS101 payloads encrypted with the receiver's ECDH public key
- Full audit trail retained per Article 17 record-keeping requirements
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict

from opago_mica.compliance.travel_rule_manager import (
    InitiateTransferParams,
    TravelRuleManager,
)
from opago_mica.core.compliance_engine import ComplianceEngine
from opago_mica.core.uma_mica import UMAMiCAProtocol
from opago_mica.eidas.eidas_wallet import EIDASWalletBridge
from opago_mica.types.ivms101 import (
    Beneficiary,
    IVMS101Payload,
    NaturalPerson,
    NaturalPersonName,
    NaturalPersonNameIdentifier,
    Originator,
    PersonType,
)
from opago_mica.types.uma_extended import (
    EIDASAttestation,
    KycStatus,
    ReceiverCapabilities,
    UMAPayRequest,
)
from opago_mica.utils.logger import create_logger
from opago_mica.utils.url import build_service_url
from opago_mica.wallet.spark_wallet import SparkWalletManager

logger = create_logger("SendingVASP")


# ---------------------------------------------------------------------------
# Public Pydantic models
# ---------------------------------------------------------------------------


class SendPaymentParams(BaseModel):
    """Parameters for initiating a payment."""

    model_config = ConfigDict(populate_by_name=True)

    #: Receiver's UMA address, e.g. '$alice@receiver.vasp.com'
    receiver_uma: str
    #: Amount in satoshis.
    amount_sats: int
    #: ISO 4217 currency code (default: 'SAT').
    currency: str | None = None
    #: Sender's legal full name (from VASP KYC).
    sender_name: str
    #: Sender's UMA identifier, e.g. '$bob@sender.vasp.com'.
    sender_account: str
    #: Optional payment memo.
    memo: str | None = None
    #: If ``True``, attempt to obtain an eIDAS qualified signature from the
    #: user's EU Digital Identity Wallet. Only used when the receiver also
    #: requests it AND the user explicitly approves.
    use_eidas: bool | None = None


class SendPaymentResult(BaseModel):
    """Result returned after attempting a payment."""

    model_config = ConfigDict(populate_by_name=True)

    #: Whether the payment completed successfully.
    success: bool
    #: Unique payment identifier.
    payment_id: str
    #: Travel rule transfer ID (present if travel rule was required).
    travel_rule_transfer_id: str | None = None
    #: Whether an eIDAS qualified signature was used.
    eidas_signed: bool
    #: Final compliance decision.
    compliance_status: str
    #: Lightning payment preimage (proof of payment).
    preimage: str | None = None
    #: Error message if the payment failed.
    error: str | None = None


class PaymentAuditRecord(BaseModel):
    """Audit record for a completed (or failed) payment."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    timestamp: datetime
    payment_id: str
    sender_vasp: str
    receiver_vasp: str
    amount_sats: int
    currency: str
    travel_rule_transfer_id: str | None = None
    eidas_signed: bool
    compliance_status: str
    error: str | None = None


# ---------------------------------------------------------------------------
# SendingVASP
# ---------------------------------------------------------------------------


class SendingVASP:
    """
    Sending (originator) VASP implementation.

    Handles the complete MiCA-compliant payment flow from the sender side.
    Instantiate once and call :meth:`send_payment` for each outbound transfer.

    Example::

        vasp = SendingVASP(
            wallet=wallet, uma_protocol=uma, travel_rule=tr, eidas_bridge=eidas,
            compliance=comp, vasp_domain='sender.vasp.com', vasp_name='Sender VASP'
        )
        result = await vasp.send_payment(SendPaymentParams(
            receiver_uma='$bob@receiver.vasp.com',
            amount_sats=50000,
            sender_name='Alice Mustermann',
            sender_account='$alice@sender.vasp.com',
        ))
    """

    def __init__(
        self,
        wallet: SparkWalletManager,
        uma_protocol: UMAMiCAProtocol,
        travel_rule: TravelRuleManager,
        eidas_bridge: EIDASWalletBridge,
        compliance: ComplianceEngine,
        vasp_domain: str,
        vasp_name: str,
    ) -> None:
        self._wallet = wallet
        self._uma_protocol = uma_protocol
        self._travel_rule = travel_rule
        self._eidas_bridge = eidas_bridge
        self._compliance = compliance
        self._vasp_domain = vasp_domain
        self._vasp_name = vasp_name
        #: In-memory audit log (production: persist to database).
        self._audit_log: list[PaymentAuditRecord] = []

        logger.info(
            "SendingVASP initialized",
            vasp_domain=self._vasp_domain,
            vasp_name=self._vasp_name,
            registered_protocols=self._travel_rule.get_registered_protocols(),
        )

    # ---------------------------------------------------------------------------
    # Main payment flow
    # ---------------------------------------------------------------------------

    async def send_payment(self, params: SendPaymentParams) -> SendPaymentResult:
        """
        Execute a complete MiCA-compliant outbound payment.

        Steps:
        1. Resolve receiver UMA address → capabilities
        2. Evaluate compliance requirements
        3. Build IVMS101 originator data (KYC or eIDAS wallet)
        4. Create MiCA pay request (with encrypted IVMS101 if travel rule required)
        5. Get BOLT11 invoice from receiver
        6. Pay invoice via Spark wallet
        7. Write audit record

        Args:
            params: Payment parameters.

        Returns:
            :class:`SendPaymentResult` including compliance status and preimage.
        """
        payment_id = f"pay_{uuid.uuid4()}"
        eidas_signed = False
        travel_rule_transfer_id: str | None = None

        logger.info(
            "Initiating MiCA-compliant payment",
            payment_id=payment_id,
            receiver_uma=params.receiver_uma,
            amount_sats=params.amount_sats,
            use_eidas=params.use_eidas or False,
        )

        try:
            # -------------------------------------------------------------------
            # Step 1: Resolve receiver capabilities
            # -------------------------------------------------------------------
            receiver_capabilities: ReceiverCapabilities = (
                await self._uma_protocol.resolve_receiver(params.receiver_uma)
            )

            logger.info(
                "Receiver resolved",
                payment_id=payment_id,
                vasp_domain=receiver_capabilities.vasp_domain,
                requires_travel_rule=receiver_capabilities.requires_travel_rule,
            )

            # -------------------------------------------------------------------
            # Step 2: Evaluate compliance requirements
            # -------------------------------------------------------------------
            # Convert satoshis to EUR equivalent for threshold comparison
            # Using a conservative rate: 1 sat ≈ EUR 0.0004 at $40k BTC
            amount_eur = params.amount_sats * 0.0004
            compliance_requirements = self._uma_protocol.evaluate_compliance_requirements(
                amount_eur
            )

            logger.info(
                "Compliance requirements evaluated",
                payment_id=payment_id,
                travel_rule_required=compliance_requirements.travel_rule_required,
                eidas_accepted=compliance_requirements.eidas_signature_accepted,
                amount_eur=f"{amount_eur:.2f}",
            )

            # Evaluate via compliance engine (sanctions screening, risk score)
            compliance_decision = self._compliance.evaluate_transaction(
                amount_eur,
                "EUR",
                "DE",  # Sender jurisdiction
                "DE",  # Receiver jurisdiction (TODO: resolve from receiver VASP)
            )

            if compliance_decision.outcome == "BLOCK":
                error = f"Payment blocked: {', '.join(compliance_decision.reasons)}"
                logger.warning(
                    "Payment blocked by compliance engine",
                    payment_id=payment_id,
                    outcome=compliance_decision.outcome,
                    reasons=compliance_decision.reasons,
                )
                self._write_audit_record(
                    payment_id=payment_id,
                    params=params,
                    receiver_capabilities=receiver_capabilities,
                    eidas_signed=False,
                    compliance_status="REJECTED",
                    error=error,
                )
                return SendPaymentResult(
                    success=False,
                    payment_id=payment_id,
                    eidas_signed=False,
                    compliance_status="REJECTED",
                    error=error,
                )

            # -------------------------------------------------------------------
            # Step 3: Build IVMS101 originator data
            # -------------------------------------------------------------------
            currency = params.currency or "SAT"
            originator_data = await self._build_originator_data(
                payment_reference=payment_id,
                sender_name=params.sender_name,
                sender_account=params.sender_account,
                receiver_uma=params.receiver_uma,
                use_eidas=params.use_eidas or False,
                receiver_requires_eidas=compliance_requirements.eidas_signature_accepted,
                receiver_domain=receiver_capabilities.vasp_domain,
            )
            ivms101: IVMS101Payload = originator_data["ivms101"]
            eidas_signed = originator_data["eidas_signed"]
            eidas_presentation: str | None = originator_data.get("eidas_presentation")
            eidas_attestation: EIDASAttestation | None = originator_data.get(
                "eidas_attestation"
            )

            logger.info(
                "IVMS101 originator data ready",
                payment_id=payment_id,
                eidas_signed=eidas_signed,
                travel_rule_required=compliance_requirements.travel_rule_required,
            )

            # -------------------------------------------------------------------
            # Step 4: Send travel rule data out-of-band when a provider is configured
            # -------------------------------------------------------------------
            if (
                compliance_requirements.travel_rule_required
                and self._travel_rule.get_registered_protocols()
            ):
                transfer = await self._travel_rule.initiate_transfer(
                    self._build_travel_rule_transfer_params(
                        ivms101=ivms101,
                        counterparty_domain=receiver_capabilities.vasp_domain,
                        payment_reference=payment_id,
                        asset=currency,
                        amount_sats=params.amount_sats,
                    )
                )
                travel_rule_transfer_id = transfer.transfer_id
                logger.info(
                    "Travel rule transfer completed before invoice request",
                    payment_id=payment_id,
                    transfer_id=travel_rule_transfer_id,
                    protocol=transfer.protocol,
                    status=transfer.status,
                )

            # -------------------------------------------------------------------
            # Step 5: Create MiCA pay request
            # -------------------------------------------------------------------
            pay_request: UMAPayRequest = await self._uma_protocol.create_mica_pay_request(
                receiver_address=params.receiver_uma,
                amount=params.amount_sats,
                currency=currency,
                sender_ivms101=ivms101,
                receiver_encryption_key=receiver_capabilities.encryption_pub_key,
                payer_identifier=params.sender_account,
                payer_name=params.sender_name,
                kyc_status=KycStatus.VERIFIED,
            )
            pay_request.comment = params.memo
            pay_request.travel_rule_transfer_id = travel_rule_transfer_id
            if (
                eidas_presentation is not None
                and pay_request.payer_data
                and pay_request.payer_data.compliance_data
            ):
                pay_request.payer_data.compliance_data.eidas_credential_presentation = (
                    eidas_presentation
                )
            pay_request.eidas_attestation = eidas_attestation

            if (
                travel_rule_transfer_id
                and pay_request.payer_data
                and pay_request.payer_data.compliance_data
            ):
                # The travel rule payload already moved over TRISA/TRP/etc.; keep the
                # UMA pay request as the invoice request plus transfer reference.
                pay_request.payer_data.compliance_data.encrypted_travel_rule_info = None
                pay_request.payer_data.compliance_data.travel_rule_info = None

            # -------------------------------------------------------------------
            # Step 6: Send pay request to receiver and get invoice
            # -------------------------------------------------------------------
            pay_request_url = self._build_pay_request_url(
                receiver_capabilities,
                params.receiver_uma,
            )

            logger.info(
                "Sending UMA pay request",
                payment_id=payment_id,
                url=pay_request_url,
            )

            pay_response = await self._send_pay_request(pay_request_url, pay_request)

            logger.info(
                "Pay response received",
                payment_id=payment_id,
            )

            # -------------------------------------------------------------------
            # Step 7: Pay the invoice via Spark wallet
            # -------------------------------------------------------------------
            logger.info("Paying Lightning invoice", payment_id=payment_id)
            payment_result = await self._wallet.pay_invoice(pay_response["encodedInvoice"])

            if payment_result.status != "completed":
                error = f"Lightning payment failed: status={payment_result.status}"
                logger.warning(
                    "Invoice payment failed",
                    payment_id=payment_id,
                    status=payment_result.status,
                )
                self._write_audit_record(
                    payment_id=payment_id,
                    params=params,
                    receiver_capabilities=receiver_capabilities,
                    eidas_signed=eidas_signed,
                    compliance_status="ERROR",
                    travel_rule_transfer_id=travel_rule_transfer_id,
                    error=error,
                )
                return SendPaymentResult(
                    success=False,
                    payment_id=payment_id,
                    eidas_signed=eidas_signed,
                    compliance_status="ERROR",
                    error=error,
                    travel_rule_transfer_id=travel_rule_transfer_id,
                )

            # -------------------------------------------------------------------
            # Step 8: Write audit record
            # -------------------------------------------------------------------
            self._write_audit_record(
                payment_id=payment_id,
                params=params,
                receiver_capabilities=receiver_capabilities,
                eidas_signed=eidas_signed,
                compliance_status="APPROVED",
                travel_rule_transfer_id=travel_rule_transfer_id,
            )

            logger.info(
                "Payment completed successfully",
                payment_id=payment_id,
                amount_sats=params.amount_sats,
                eidas_signed=eidas_signed,
                travel_rule_transfer_id=travel_rule_transfer_id,
                preimage=payment_result.preimage[:16] + "..." if payment_result.preimage else None,
            )

            return SendPaymentResult(
                success=True,
                payment_id=payment_id,
                travel_rule_transfer_id=travel_rule_transfer_id,
                eidas_signed=eidas_signed,
                compliance_status="APPROVED",
                preimage=payment_result.preimage,
            )

        except Exception as exc:
            error_message = str(exc)
            logger.error(
                "Payment failed with unexpected error",
                payment_id=payment_id,
                error=error_message,
            )
            return SendPaymentResult(
                success=False,
                payment_id=payment_id,
                eidas_signed=eidas_signed,
                compliance_status="ERROR",
                error=error_message,
                travel_rule_transfer_id=travel_rule_transfer_id,
            )

    # ---------------------------------------------------------------------------
    # Audit log
    # ---------------------------------------------------------------------------

    def get_audit_log(self) -> list[PaymentAuditRecord]:
        """Get all audit records."""
        return list(self._audit_log)

    # ---------------------------------------------------------------------------
    # Private: build IVMS101 originator data
    # ---------------------------------------------------------------------------

    async def _build_originator_data(
        self,
        payment_reference: str,
        sender_name: str,
        sender_account: str,
        receiver_uma: str,
        use_eidas: bool,
        receiver_requires_eidas: bool,
        receiver_domain: str,
    ) -> dict[str, Any]:
        """
        Build the IVMS101 originator data from VASP KYC records, or from the
        user's eIDAS wallet if available and the user approves.

        The eIDAS path is ONLY taken when:
        - ``use_eidas`` is True (user opted in)
        - The eIDAS wallet is available
        - The receiver accepts eIDAS signatures

        Returns:
            Dict with keys ``ivms101`` (:class:`IVMS101Payload`) and
            ``eidas_signed`` (bool).
        """
        should_try_eidas = (
            use_eidas
            and self._eidas_bridge.is_available()
            and receiver_requires_eidas
        )

        if should_try_eidas:
            logger.info(
                "Attempting eIDAS wallet flow for originator data",
                receiver_domain=receiver_domain,
            )

            try:
                consent = await self._eidas_bridge.request_user_consent(
                    relying_party_name=receiver_domain,
                    relying_party_domain=receiver_domain,
                    requested_attributes=["given_name", "family_name", "birth_date", "nationality"],
                    purpose=(
                        f"MiCA Travel Rule identity disclosure for payment to {receiver_domain}"
                    ),
                )

                if consent and consent.approved:
                    result = await self._eidas_bridge.build_originator_from_credentials(consent)
                    natural_person: NaturalPerson = result["natural_person"]
                    ivms101 = self._build_ivms101_payload(
                        natural_person,
                        sender_account,
                        receiver_uma,
                    )
                    presentation = await self._eidas_bridge.create_presentation(
                        requested_attributes=[
                            "given_name",
                            "family_name",
                            "birth_date",
                            "nationality",
                        ],
                        relying_party_domain=receiver_domain,
                        challenge=payment_reference,
                    )
                    attestation_result = await self._eidas_bridge.sign_transaction(
                        transaction_hash=payment_reference,
                        ivms101_data=ivms101.model_dump(mode="json"),
                        relying_party=receiver_domain,
                    )
                    attestation = EIDASAttestation(
                        payment_reference=payment_reference,
                        signature=attestation_result.signature or "",
                        signing_certificate=(
                            attestation_result.signing_certificate
                            or attestation_result.certificate
                        ),
                        signed_at=(
                            attestation_result.timestamp or attestation_result.signed_at
                        ),
                        signature_level=(
                            attestation_result.signature_level.value
                            if attestation_result.signature_level is not None
                            else None
                        ),
                    )
                    logger.info("eIDAS originator data obtained", consent_id=consent.consent_id)
                    return {
                        "ivms101": ivms101,
                        "eidas_signed": True,
                        "eidas_presentation": presentation.model_dump_json(by_alias=True),
                        "eidas_attestation": attestation,
                    }

                logger.info("User declined eIDAS consent, falling back to VASP KYC data")

            except Exception as err:  # noqa: BLE001
                logger.warning("eIDAS wallet error, falling back to KYC data", error=str(err))

        # Fallback: use VASP KYC data
        natural_person = self._build_natural_person_from_kyc(sender_name)
        ivms101 = self._build_ivms101_payload(
            natural_person,
            sender_account,
            receiver_uma,
        )
        return {"ivms101": ivms101, "eidas_signed": False}

    def _build_natural_person_from_kyc(self, full_name: str) -> NaturalPerson:
        """Build a NaturalPerson record from VASP KYC data."""
        parts = full_name.strip().split()
        if len(parts) > 1:
            family_name = parts[-1]
            given_name: str | None = " ".join(parts[:-1])
        else:
            family_name = full_name
            given_name = None

        if given_name is not None:
            name_identifier = NaturalPersonNameIdentifier(
                primary_identifier=family_name,
                secondary_identifier=given_name,
                name_identifier_type="LEGL",
            )
        else:
            name_identifier = NaturalPersonNameIdentifier(
                primary_identifier=family_name,
                name_identifier_type="LEGL",
            )

        return NaturalPerson(
            name=[NaturalPersonName(name_identifiers=[name_identifier])],
        )

    def _build_ivms101_payload(
        self,
        originator_person: NaturalPerson,
        sender_account_id: str,
        receiver_account_id: str,
    ) -> IVMS101Payload:
        """Assemble a full IVMS101 payload for the negotiated payment."""
        originator = Originator(
            originator_persons=[PersonType(natural_person=originator_person)],
            account_number=[sender_account_id],
        )

        beneficiary_handle = receiver_account_id.lstrip("$")
        beneficiary_name = beneficiary_handle.split("@", 1)[0] or "UNKNOWN"

        beneficiary = Beneficiary(
            beneficiary_persons=[
                PersonType(
                    natural_person=NaturalPerson(
                        name=[
                            NaturalPersonName(
                                name_identifiers=[
                                    NaturalPersonNameIdentifier(
                                        primary_identifier=beneficiary_name,
                                        name_identifier_type="LEGL",
                                    )
                                ]
                            )
                        ]
                    )
                )
            ],
            account_number=[receiver_account_id],
        )

        return IVMS101Payload(originator=originator, beneficiary=beneficiary)

    # ---------------------------------------------------------------------------
    # Private: send pay request
    # ---------------------------------------------------------------------------

    async def _send_pay_request(
        self,
        url: str,
        pay_request: UMAPayRequest,
    ) -> dict[str, Any]:
        """
        Send a UMA pay request to the receiver's callback URL and return the response.

        In production, this would:
        - Sign the pay request with this VASP's signing key
        - Send via HTTPS POST
        - Verify the response signature

        Args:
            url: The receiver's pay request callback URL.
            pay_request: The UMA pay request.

        Returns:
            Dict with ``encodedInvoice`` and optional ``compliance`` keys.
        """
        logger.debug("Sending pay request", url=url, amount=pay_request.amount)
        payload = pay_request.model_dump(by_alias=True, exclude_none=True)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "User-Agent": "opago-mica/1.0",
                    },
                )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to send pay request to {url}: {exc}") from exc

        try:
            body: dict[str, Any] = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Receiver returned non-JSON pay response with status {response.status_code}"
            ) from exc

        if response.is_error:
            error_message = body.get("error") or body.get("details") or response.text
            raise RuntimeError(
                f"Receiver rejected pay request with status {response.status_code}: {error_message}"
            )

        encoded_invoice = (
            body.get("encodedInvoice")
            or body.get("encoded_invoice")
            or body.get("pr")
        )
        if not isinstance(encoded_invoice, str) or not encoded_invoice:
            raise RuntimeError("Receiver pay response did not include a Lightning invoice")

        payee_data = body.get("payeeData") or body.get("payee_data") or {}
        # The current sender flow treats invoice issuance as receiver acceptance.
        # Response-signature verification is not wired yet.
        compliance = payee_data.get("compliance") or body.get("compliance") or {}

        logger.info("Pay request sent", url=url, amount=pay_request.amount)
        return {"encodedInvoice": encoded_invoice, "compliance": compliance}

    def _build_travel_rule_transfer_params(
        self,
        *,
        ivms101: IVMS101Payload,
        counterparty_domain: str,
        payment_reference: str,
        asset: str,
        amount_sats: int,
    ) -> InitiateTransferParams:
        # Lightning does not expose the final settlement hash before invoice issuance,
        # so the travel rule exchange binds to the payment reference created locally.
        return InitiateTransferParams(
            ivms101=ivms101,
            counterparty_domain=counterparty_domain,
            tx_hash=payment_reference,
            asset=asset,
            amount=str(amount_sats),
        )

    def _build_pay_request_url(
        self,
        capabilities: ReceiverCapabilities,
        uma_address: str,
    ) -> str:
        """Build the pay request callback URL from receiver capabilities."""
        at_idx = uma_address.rfind("@")
        if at_idx >= 0:
            domain = uma_address[at_idx + 1:]
            raw_user = uma_address[:at_idx]
            username = raw_user[1:] if raw_user.startswith("$") else raw_user
        else:
            domain = capabilities.vasp_domain
            username = "unknown"
        return build_service_url(domain, f"/api/uma/payreq/{quote(username, safe='')}")

    # ---------------------------------------------------------------------------
    # Private: audit record
    # ---------------------------------------------------------------------------

    def _write_audit_record(
        self,
        payment_id: str,
        params: SendPaymentParams,
        receiver_capabilities: ReceiverCapabilities,
        eidas_signed: bool,
        compliance_status: str,
        travel_rule_transfer_id: str | None = None,
        error: str | None = None,
    ) -> None:
        record = PaymentAuditRecord(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=UTC),
            payment_id=payment_id,
            sender_vasp=self._vasp_domain,
            receiver_vasp=receiver_capabilities.vasp_domain,
            amount_sats=params.amount_sats,
            currency=params.currency or "SAT",
            eidas_signed=eidas_signed,
            compliance_status=compliance_status,
            travel_rule_transfer_id=travel_rule_transfer_id,
            error=error,
        )
        self._audit_log.append(record)
        logger.debug(
            "Audit record written",
            audit_id=record.id,
            payment_id=payment_id,
        )
