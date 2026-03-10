"""
Compliance Engine

Evaluates regulatory compliance requirements for MiCA / EU Transfer of
Funds Regulation (TFR 2023/1113) transactions.

Port of src/core/compliance-engine.ts.
"""

from __future__ import annotations

import time
from datetime import UTC
from typing import Literal

from pydantic import BaseModel, ConfigDict

from opago_mica.types.ivms101 import (
    Beneficiary,
    IVMS101Payload,
    LegalPerson,
    NaturalPerson,
    Originator,
    PersonType,
)
from opago_mica.types.uma_extended import ComplianceStatus, MiCATransactionMetadata
from opago_mica.utils.logger import create_logger, log_audit_event

# ---------------------------------------------------------------------------
# Config type
# ---------------------------------------------------------------------------


class ComplianceEngineConfig(BaseModel):
    """Configuration for ComplianceEngine constructor."""

    model_config = ConfigDict(populate_by_name=True)

    vasp_domain: str
    travel_rule_threshold_eur: float | None = None


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

ComplianceDecisionOutcome = Literal[
    "ALLOW",
    "REQUIRE_TRAVEL_RULE",
    "REQUIRE_ENHANCED_DD",
    "BLOCK",
    "MANUAL_REVIEW",
]


class ComplianceDecision(BaseModel):
    """Result of a compliance evaluation for a transaction."""

    model_config = ConfigDict(populate_by_name=True)

    outcome: ComplianceDecisionOutcome
    travel_rule_required: bool
    enhanced_due_diligence_required: bool
    reasons: list[str]
    applicable_regulations: list[str]
    threshold_eur: float


#: Alias used for backward compatibility with index exports.
ComplianceEvaluationResult = ComplianceDecision


class ValidationIssue(BaseModel):
    """A single validation issue found in an IVMS101 payload."""

    model_config = ConfigDict(populate_by_name=True)

    field: str
    severity: Literal["ERROR", "WARNING"]
    message: str


class ValidationResult(BaseModel):
    """Result of IVMS101 payload validation."""

    model_config = ConfigDict(populate_by_name=True)

    valid: bool
    errors: list[ValidationIssue]
    warnings: list[ValidationIssue]
    completeness_score: float


ScreeningOutcome = Literal["CLEAR", "POTENTIAL_MATCH", "CONFIRMED_MATCH", "ERROR"]


class ScreeningMatch(BaseModel):
    """A sanctions screening match entry."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    list_name: str
    match_score: float
    details: str | None = None


class ScreeningResult(BaseModel):
    """Result of a sanctions screening operation."""

    model_config = ConfigDict(populate_by_name=True)

    outcome: ScreeningOutcome
    names_screened: list[str]
    matches: list[ScreeningMatch] | None = None
    screened_at: str
    provider: str


class TravelRuleComplianceInfo(BaseModel):
    """Travel rule compliance section of a ComplianceReport."""

    model_config = ConfigDict(populate_by_name=True)

    required: bool
    exchanged: bool
    ivms101_payload_hash: str | None = None


class KycComplianceInfo(BaseModel):
    """KYC compliance section of a ComplianceReport."""

    model_config = ConfigDict(populate_by_name=True)

    sender_kyc_verified: bool
    receiver_kyc_verified: bool


class ComplianceReport(BaseModel):
    """Structured compliance report for a completed transaction."""

    model_config = ConfigDict(populate_by_name=True)

    report_id: str
    generated_at: str
    transaction_id: str
    vasp_domain: str
    compliance_status: ComplianceStatus
    regulatory_frameworks: list[str]
    travel_rule_compliance: TravelRuleComplianceInfo
    kyc_compliance: KycComplianceInfo
    screening_result: ScreeningResult | None = None
    summary: str
    action_items: list[str]


# ---------------------------------------------------------------------------
# ComplianceEngine
# ---------------------------------------------------------------------------

_EU_TFR_THRESHOLD_EUR: float = 1000.0

_HIGH_RISK_JURISDICTIONS: frozenset[str] = frozenset([
    "AF", "BY", "BI", "CF", "CD", "CU", "ET", "IR", "IQ",
    "LY", "ML", "MZ", "NI", "KP", "RU", "SO", "SS", "SY",
    "TJ", "TN", "TR", "UG", "UA", "VE", "YE", "ZW",
])

_EU_JURISDICTIONS: frozenset[str] = frozenset([
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",
])

# EUR conversion rates (units of each currency per 1 EUR)
_RATES_PER_EUR: dict[str, float] = {
    "EUR": 1.0,
    "USD": 1.08,
    "GBP": 0.86,
    "CHF": 0.94,
    "JPY": 162.0,
    "BTC": 0.000_010,
    "SAT": 0.000_000_010,
    "MSAT": 0.000_000_000_010,
}


class ComplianceEngine:
    """
    Stateless compliance evaluation engine.

    Example::

        engine = ComplianceEngine(ComplianceEngineConfig(vasp_domain='vasp.example.com'))
        decision = engine.evaluate_transaction(950, 'EUR', 'DE', 'FR')
    """

    def __init__(self, config: ComplianceEngineConfig) -> None:
        self._vasp_domain = config.vasp_domain
        self._travel_rule_threshold_eur: float = (
            config.travel_rule_threshold_eur
            if config.travel_rule_threshold_eur is not None
            else _EU_TFR_THRESHOLD_EUR
        )
        self._log = create_logger("ComplianceEngine", vasp_domain=self._vasp_domain)

    # -------------------------------------------------------------------------
    # 1. Transaction Compliance Evaluation
    # -------------------------------------------------------------------------

    def evaluate_transaction(
        self,
        amount: float,
        currency: str,
        sender_jurisdiction: str,
        receiver_jurisdiction: str,
    ) -> ComplianceDecision:
        """
        Evaluate whether a transaction requires travel rule data exchange,
        enhanced due diligence, or should be blocked.

        Args:
            amount:               Transaction amount (in currency units)
            currency:             ISO 4217 currency code
            sender_jurisdiction:  ISO 3166-1 alpha-2 country code of sender VASP
            receiver_jurisdiction: ISO 3166-1 alpha-2 country code of receiver VASP
        """
        self._log.debug(
            "Evaluating transaction compliance",
            amount=amount,
            currency=currency,
            sender_jurisdiction=sender_jurisdiction,
            receiver_jurisdiction=receiver_jurisdiction,
        )

        reasons: list[str] = []
        applicable_regulations: list[str] = []

        amount_eur = self._convert_to_eur(amount, currency)

        sender_high_risk = sender_jurisdiction.upper() in _HIGH_RISK_JURISDICTIONS
        receiver_high_risk = receiver_jurisdiction.upper() in _HIGH_RISK_JURISDICTIONS

        if sender_high_risk or receiver_high_risk:
            risk_jurisdiction = (
                sender_jurisdiction if sender_high_risk else receiver_jurisdiction
            )
            reasons.append(
                f"Transaction involves high-risk jurisdiction: {risk_jurisdiction}"
            )
            applicable_regulations.append("FATF High-Risk Country Requirements")

            log_audit_event(
                "high_risk_jurisdiction_detected",
                sender_jurisdiction=sender_jurisdiction,
                receiver_jurisdiction=receiver_jurisdiction,
                amount_eur=amount_eur,
            )

            return ComplianceDecision(
                outcome="REQUIRE_ENHANCED_DD",
                travel_rule_required=True,
                enhanced_due_diligence_required=True,
                reasons=reasons,
                applicable_regulations=applicable_regulations,
                threshold_eur=self._travel_rule_threshold_eur,
            )

        sender_eu = sender_jurisdiction.upper() in _EU_JURISDICTIONS
        receiver_eu = receiver_jurisdiction.upper() in _EU_JURISDICTIONS
        travel_rule_required = amount_eur >= self._travel_rule_threshold_eur

        if travel_rule_required:
            applicable_regulations.append("EU Transfer of Funds Regulation 2023/1113")
            if sender_eu or receiver_eu:
                reasons.append(
                    f"Amount €{amount_eur:.2f} meets or exceeds EU TFR threshold "
                    f"of €{self._travel_rule_threshold_eur}"
                )
            else:
                reasons.append(
                    f"Amount €{amount_eur:.2f} meets or exceeds FATF Travel Rule threshold "
                    f"of €{self._travel_rule_threshold_eur}"
                )
                applicable_regulations.append("FATF Travel Rule")

            return ComplianceDecision(
                outcome="REQUIRE_TRAVEL_RULE",
                travel_rule_required=True,
                enhanced_due_diligence_required=False,
                reasons=reasons,
                applicable_regulations=applicable_regulations,
                threshold_eur=self._travel_rule_threshold_eur,
            )

        reasons.append(
            f"Amount €{amount_eur:.2f} is below travel rule threshold "
            f"of €{self._travel_rule_threshold_eur}"
        )
        applicable_regulations.append("EU MiCA Article 68 (KYC)")

        return ComplianceDecision(
            outcome="ALLOW",
            travel_rule_required=False,
            enhanced_due_diligence_required=False,
            reasons=reasons,
            applicable_regulations=applicable_regulations,
            threshold_eur=self._travel_rule_threshold_eur,
        )

    # -------------------------------------------------------------------------
    # 2. IVMS101 Payload Validation
    # -------------------------------------------------------------------------

    def validate_ivms101(
        self,
        payload: IVMS101Payload,
        role: Literal["originator", "beneficiary"],
    ) -> ValidationResult:
        """
        Validate an IVMS101 payload for completeness per EU TFR 2023/1113.

        Args:
            payload: IVMS101 payload to validate
            role:    Whether we're validating as originator or beneficiary data
        """
        errors: list[ValidationIssue] = []
        warnings: list[ValidationIssue] = []

        self._log.debug("Validating IVMS101 payload", role=role)

        if payload.originator is None:
            errors.append(
                ValidationIssue(
                    field="originator",
                    severity="ERROR",
                    message="originator is required",
                )
            )
        if payload.beneficiary is None:
            errors.append(
                ValidationIssue(
                    field="beneficiary",
                    severity="ERROR",
                    message="beneficiary is required",
                )
            )
        if payload.originating_vasp is None:
            warnings.append(
                ValidationIssue(
                    field="originatingVASP",
                    severity="WARNING",
                    message="originatingVASP is recommended for MiCA compliance",
                )
            )

        if payload.originator is not None:
            self._validate_originator(payload.originator, errors, warnings)
        if payload.beneficiary is not None:
            self._validate_beneficiary(payload.beneficiary, errors, warnings)

        if payload.originating_vasp is not None:
            vasp_person = payload.originating_vasp.originating_vasp.legal_person
            has_name_identifier = bool(
                (
                    vasp_person.legal_person_name_identifier
                    and len(vasp_person.legal_person_name_identifier) > 0
                )
                or (vasp_person.name and len(vasp_person.name) > 0)
            )
            if not has_name_identifier:
                errors.append(
                    ValidationIssue(
                        field="originatingVASP.legalPerson",
                        severity="ERROR",
                        message="Originating VASP must have at least one legal name identifier",
                    )
                )
            if vasp_person.national_identification is None:
                warnings.append(
                    ValidationIssue(
                        field="originatingVASP.legalPerson.nationalIdentification",
                        severity="WARNING",
                        message="Originating VASP LEI is recommended",
                    )
                )

        completeness_score = self._calculate_completeness_score(errors, warnings)
        valid = len(errors) == 0

        self._log.info(
            "IVMS101 validation complete",
            role=role,
            valid=valid,
            error_count=len(errors),
            warning_count=len(warnings),
            completeness_score=completeness_score,
        )

        return ValidationResult(
            valid=valid,
            errors=errors,
            warnings=warnings,
            completeness_score=completeness_score,
        )

    # -------------------------------------------------------------------------
    # 3. Sanctions Screening
    # -------------------------------------------------------------------------

    async def screen_transaction(
        self,
        originator: Originator,
        beneficiary: Beneficiary,
    ) -> ScreeningResult:
        """
        Screen originator and beneficiary names against sanctions lists.

        NOTE: Placeholder — integrate with a real provider before production.

        Args:
            originator:  Originator party from IVMS101 payload
            beneficiary: Beneficiary party from IVMS101 payload
        """
        names_screened: list[str] = []

        for person in (originator.originator_persons or []):
            names_screened.extend(self._extract_names_from_person(person))
        for person in (beneficiary.beneficiary_persons or []):
            names_screened.extend(self._extract_names_from_person(person))

        self._log.info("Sanctions screening requested", names_count=len(names_screened))

        log_audit_event(
            "sanctions_screening",
            names_screened=names_screened,
            provider="PLACEHOLDER",
        )

        self._log.warning(
            "Sanctions screening is using placeholder implementation – integrate real provider",
            names_screened=names_screened,
        )

        from datetime import datetime

        return ScreeningResult(
            outcome="CLEAR",
            names_screened=names_screened,
            screened_at=datetime.now(tz=UTC).isoformat(),
            provider="PLACEHOLDER – integrate real sanctions provider before production",
        )

    # -------------------------------------------------------------------------
    # 4. Compliance Report Generation
    # -------------------------------------------------------------------------

    def generate_compliance_report(
        self, metadata: MiCATransactionMetadata
    ) -> ComplianceReport:
        """
        Generate a structured compliance report for a completed transaction.

        Args:
            metadata: MiCATransactionMetadata for the transaction
        """
        from datetime import datetime

        report_id = f"RPT-{metadata.transaction_id}-{int(time.time() * 1000)}"
        generated_at = datetime.now(tz=UTC).isoformat()

        regulations = ["EU MiCA 2023/1114"]
        if metadata.travel_rule_exchanged:
            regulations.append("EU TFR 2023/1113")
        if metadata.eidas_signed:
            regulations.append("EU eIDAS 2.0 Regulation 2024/1183")

        action_items: list[str] = []

        if (
            metadata.amount_eur >= self._travel_rule_threshold_eur
            and not metadata.travel_rule_exchanged
        ):
            action_items.append(
                f"REQUIRED: IVMS101 travel rule data was not exchanged for transaction "
                f"exceeding €{self._travel_rule_threshold_eur}. Manual review required."
            )
        if metadata.compliance_status == "SCREENED_ALERT":
            action_items.append(
                "REQUIRED: Sanctions screening returned a potential match. Manual review required."
            )
        if metadata.compliance_status == "PENDING_REVIEW":
            action_items.append("REQUIRED: Transaction is pending compliance review.")

        travel_rule_compliance = TravelRuleComplianceInfo(
            required=metadata.amount_eur >= self._travel_rule_threshold_eur,
            exchanged=metadata.travel_rule_exchanged,
        )
        if metadata.ivms101_payload_hash is not None:
            travel_rule_compliance.ivms101_payload_hash = metadata.ivms101_payload_hash

        report = ComplianceReport(
            report_id=report_id,
            generated_at=generated_at,
            transaction_id=metadata.transaction_id,
            vasp_domain=self._vasp_domain,
            compliance_status=metadata.compliance_status,
            regulatory_frameworks=regulations,
            travel_rule_compliance=travel_rule_compliance,
            kyc_compliance=KycComplianceInfo(
                sender_kyc_verified=True,
                receiver_kyc_verified=True,
            ),
            summary=self._build_report_summary(metadata, action_items),
            action_items=action_items,
        )

        log_audit_event(
            "compliance_report_generated",
            report_id=report_id,
            transaction_id=metadata.transaction_id,
            compliance_status=metadata.compliance_status,
            action_item_count=len(action_items),
        )

        self._log.info(
            "Compliance report generated",
            report_id=report_id,
            transaction_id=metadata.transaction_id,
            compliance_status=metadata.compliance_status,
        )

        return report

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _validate_originator(
        self,
        originator: Originator,
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> None:
        """Validate originator persons and account numbers."""
        if not originator.originator_persons:
            errors.append(
                ValidationIssue(
                    field="originator.originatorPersons",
                    severity="ERROR",
                    message="At least one originator person is required",
                )
            )
            return
        if not originator.account_number:
            errors.append(
                ValidationIssue(
                    field="originator.accountNumber",
                    severity="ERROR",
                    message="At least one originator account number is required",
                )
            )
        for i, person in enumerate(originator.originator_persons):
            if person is not None:
                self._validate_person_type(
                    person,
                    f"originator.originatorPersons[{i}]",
                    "originator",
                    errors,
                    warnings,
                )

    def _validate_beneficiary(
        self,
        beneficiary: Beneficiary,
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> None:
        """Validate beneficiary persons and account numbers."""
        if not beneficiary.beneficiary_persons:
            errors.append(
                ValidationIssue(
                    field="beneficiary.beneficiaryPersons",
                    severity="ERROR",
                    message="At least one beneficiary person is required",
                )
            )
            return
        if not beneficiary.account_number:
            errors.append(
                ValidationIssue(
                    field="beneficiary.accountNumber",
                    severity="ERROR",
                    message="At least one beneficiary account number is required",
                )
            )
        for i, person in enumerate(beneficiary.beneficiary_persons):
            if person is not None:
                self._validate_person_type(
                    person,
                    f"beneficiary.beneficiaryPersons[{i}]",
                    "beneficiary",
                    errors,
                    warnings,
                )

    def _validate_person_type(
        self,
        person: PersonType,
        field_path: str,
        role: Literal["originator", "beneficiary"],
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> None:
        """Validate a PersonType as either NaturalPerson or LegalPerson."""
        if person.natural_person is not None:
            self._validate_natural_person(
                person.natural_person,
                f"{field_path}.naturalPerson",
                role,
                errors,
                warnings,
            )
        elif person.legal_person is not None:
            self._validate_legal_person(
                person.legal_person,
                f"{field_path}.legalPerson",
                errors,
                warnings,
            )
        else:
            errors.append(
                ValidationIssue(
                    field=field_path,
                    severity="ERROR",
                    message="Person must be either a naturalPerson or legalPerson",
                )
            )

    def _validate_natural_person(
        self,
        person: NaturalPerson,
        field_path: str,
        role: Literal["originator", "beneficiary"],
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> None:
        """Validate a NaturalPerson record per EU TFR Article 4."""
        # Collect name identifiers from flat and structured forms
        all_name_ids = list(person.name_identifier or [])
        for n in person.name or []:
            all_name_ids.extend(n.name_identifiers)

        if not all_name_ids:
            errors.append(
                ValidationIssue(
                    field=f"{field_path}.nameIdentifier",
                    severity="ERROR",
                    message="At least one name identifier is required",
                )
            )
        else:
            has_legal_name = any(
                n.name_identifier_type == "LEGL" for n in all_name_ids
            )
            if not has_legal_name:
                errors.append(
                    ValidationIssue(
                        field=f"{field_path}.nameIdentifier",
                        severity="ERROR",
                        message="At least one name identifier must have type LEGL (legal name)",
                    )
                )
            legl_name = next(
                (n for n in all_name_ids if n.name_identifier_type == "LEGL"), None
            )
            if legl_name is not None and not (
                legl_name.primary_identifier or ""
            ).strip():
                errors.append(
                    ValidationIssue(
                        field=f"{field_path}.nameIdentifier[LEGL].primaryIdentifier",
                        severity="ERROR",
                        message="Legal name primaryIdentifier (family name) must not be empty",
                    )
                )

        if role == "originator":
            has_national_id = bool(
                person.national_identification
                and person.national_identification.national_identifier
            )
            has_address = bool(person.geographic_address)
            has_customer_id = bool(
                person.customer_identification and person.date_and_place_of_birth
            )
            if not has_national_id and not has_address and not has_customer_id:
                errors.append(
                    ValidationIssue(
                        field=field_path,
                        severity="ERROR",
                        message=(
                            "EU TFR Article 4: Originator natural person must provide "
                            "at least one of: nationalIdentification, "
                            "geographicAddress, or customerIdentification + "
                            "dateOfBirth"
                        ),
                    )
                )

        if person.date_and_place_of_birth is None:
            warnings.append(
                ValidationIssue(
                    field=f"{field_path}.dateAndPlaceOfBirth",
                    severity="WARNING",
                    message="dateAndPlaceOfBirth is recommended",
                )
            )
        if person.country_of_residence is None:
            warnings.append(
                ValidationIssue(
                    field=f"{field_path}.countryOfResidence",
                    severity="WARNING",
                    message="countryOfResidence is recommended",
                )
            )

    def _validate_legal_person(
        self,
        person: LegalPerson,
        field_path: str,
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> None:
        """Validate a LegalPerson record."""
        has_name_identifier = bool(
            (person.legal_person_name_identifier and len(person.legal_person_name_identifier) > 0)
            or (person.name and len(person.name) > 0)
        )
        if not has_name_identifier:
            errors.append(
                ValidationIssue(
                    field=f"{field_path}.legalPersonNameIdentifier",
                    severity="ERROR",
                    message="At least one legal person name identifier is required",
                )
            )
        if person.national_identification is None:
            warnings.append(
                ValidationIssue(
                    field=f"{field_path}.nationalIdentification",
                    severity="WARNING",
                    message="LEI or other national identification is strongly recommended",
                )
            )

    def _calculate_completeness_score(
        self,
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> float:
        """Calculate a completeness score from error and warning counts."""
        score = 100.0 - len(errors) * 10.0 - len(warnings) * 3.0
        return max(0.0, min(100.0, score))

    def _extract_names_from_person(self, person: PersonType) -> list[str]:
        """Extract all name strings from a PersonType for sanctions screening."""
        names: list[str] = []

        if person.natural_person is not None:
            np = person.natural_person
            all_ids = list(np.name_identifier or [])
            for n in np.name or []:
                all_ids.extend(n.name_identifiers)
            for name_id in all_ids:
                full = " ".join(
                    part
                    for part in [
                        name_id.secondary_identifier,
                        name_id.primary_identifier,
                    ]
                    if part
                ).strip()
                if full:
                    names.append(full)
        elif person.legal_person is not None:
            lp = person.legal_person
            all_ids = list(lp.legal_person_name_identifier or [])
            for n in lp.name or []:
                all_ids.extend(n.name_identifiers)
            for name_id in all_ids:
                lp_name = (name_id.legal_person_name or "").strip()
                if lp_name:
                    names.append(lp_name)

        return names

    def _convert_to_eur(self, amount: float, currency: str) -> float:
        """
        Convert an amount to EUR using static approximation.
        Replace with live ECB rates in production.

        Args:
            amount:   Amount in original currency
            currency: ISO 4217 currency code
        """
        rate = _RATES_PER_EUR.get(currency.upper())
        if rate is None:
            self._log.warning(
                "Unknown currency for EUR conversion, treating 1:1",
                currency=currency,
            )
            return amount
        if currency.upper() == "EUR":
            return amount
        return amount / rate

    def _build_report_summary(
        self,
        metadata: MiCATransactionMetadata,
        action_items: list[str],
    ) -> str:
        """Build a human-readable summary for a compliance report."""
        lines = [
            f"Transaction {metadata.transaction_id}",
            f"Status: {metadata.compliance_status}",
            f"Amount: {metadata.amount} {metadata.currency} (€{metadata.amount_eur:.2f})",
            f"Sender VASP: {metadata.sender_vasp}",
            f"Receiver VASP: {metadata.receiver_vasp}",
            f"Travel Rule: {'Exchanged' if metadata.travel_rule_exchanged else 'Not exchanged'}",
            f"eIDAS: {'Signed' if metadata.eidas_signed else 'Not used'}",
        ]

        if action_items:
            lines.append(f"\nAction items ({len(action_items)}):")
            for i, item in enumerate(action_items, start=1):
                lines.append(f"  {i}. {item}")
        else:
            lines.append("No action items — transaction is fully compliant.")

        return "\n".join(lines)
