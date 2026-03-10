"""
eIDAS 2.0 Digital Identity Wallet Bridge

Integrates with EU Digital Identity Wallets (EUDIW) as defined in the
Architecture Reference Framework (ARF) v1.4. Enables self-custodial users
to sign travel rule data using their national eIDAS wallet app, giving
beneficiary VASPs cryptographic proof of identity that is legally equivalent
to a qualified electronic signature under EU law.

Key design principles:
- eIDAS signing is ONLY used when (1) the receiver explicitly requests identity
  information AND (2) the user explicitly approves sharing.
- Selective disclosure: only the specific attributes approved by the user are
  included in the Verifiable Presentation.
- W3C Verifiable Credentials Data Model 2.0 format throughout.
- In production, wallet interaction uses the OpenID4VP/ARF protocol over a
  deep-link or same-device redirect. This implementation simulates the wallet
  response to demonstrate the full compliance flow.

See:
  https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework
  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
  https://www.w3.org/TR/vc-data-model-2.0/
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from opago_mica.types.eidas import (
    CredentialType,
    EIDASCredential,
    EIDASSignatureRequest,
    EIDASSignatureResponse,
    LinkedDataProof,
    SignatureLevel,
    VerifiablePresentation,
)
from opago_mica.types.ivms101 import (
    DateAndPlaceOfBirth,
    NaturalPerson,
    NaturalPersonName,
    NaturalPersonNameIdentifier,
)
from opago_mica.utils.crypto import generate_nonce, sha256_hex
from opago_mica.utils.logger import create_logger
from opago_mica.utils.runtime_env import current_app_env

logger = create_logger("EIDASWalletBridge")

# ---------------------------------------------------------------------------
# Supporting Pydantic models (exported from this module)
# ---------------------------------------------------------------------------


class ConsentResult(BaseModel):
    """Result of the user consent flow."""

    model_config = ConfigDict(populate_by_name=True)

    #: Whether the user approved sharing.
    approved: bool
    #: The attributes the user agreed to share (key → value).
    shared_attributes: dict[str, str]
    #: The underlying eIDAS credential.
    credential: EIDASCredential
    #: When the consent was granted.
    timestamp: datetime
    #: Unique consent identifier for audit purposes.
    consent_id: str


class VerificationResult(BaseModel):
    """Result of verifying a Verifiable Presentation."""

    model_config = ConfigDict(populate_by_name=True)

    #: Whether the presentation is cryptographically valid.
    valid: bool
    #: DID of the issuing authority.
    issuer: str
    #: Credential type string (first non-VerifiableCredential type).
    credential_type: str
    #: The disclosed attributes.
    attributes: dict[str, str]
    #: Whether the JWS signature is valid.
    signature_valid: bool
    #: Whether the certificate chain leads to a trusted root CA.
    certificate_chain_valid: bool
    #: Validation errors (empty if valid).
    errors: list[str] | None = None


# ---------------------------------------------------------------------------
# Simulated wallet credential (demo)
# ---------------------------------------------------------------------------

# A simulated eIDAS Personal Identification Data (PID) credential.
# In production this comes from the user's EUDIW app.
_DEMO_CREDENTIAL_DATA: dict[str, Any] = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://eudi.europa.eu/context/pid/v1",
    ],
    "type": ["VerifiableCredential", "EUDigitalIdentityCredential", "PersonIdentificationData"],
    "credentialType": CredentialType.IDENTITY,
    "id": "https://issuer.demo.eudi.eu/credentials/pid/demo-001",
    "issuer": "did:web:issuer.demo.eudi.eu",
    "issuanceDate": "2024-01-01T00:00:00Z",
    "expirationDate": "2027-01-01T00:00:00Z",
    "credentialSubject": {
        "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "given_name": "Alice",
        "family_name": "Musterfrau",
        "birth_date": "1990-05-15",
        "nationality": "DE",
        "place_of_birth": "Berlin",
        "address": {
            "street_address": "Beispielstraße 42",
            "locality": "Berlin",
            "postal_code": "10115",
            "country_name": "Germany",
        },
    },
    "proof": {
        "type": "JsonWebSignature2020",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:web:issuer.demo.eudi.eu#key-1",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..demo-signature",
    },
}

# Simulated Ed25519 key material for signing presentations (demo only).
# Production wallets use the holder's device-bound key.
_DEMO_HOLDER_JWK: dict[str, str] = {
    "kty": "OKP",
    "crv": "Ed25519",
    # These are demo values only – never use in production
    "x": "y4DYvw9wn7NLlL7C1VXI1F5KlpB38N6f9lmPmDQ9Bcc",
    "d": "kWEMNdCIBLIcKEPMUTM8D0QAQjqV2tJSHZYqOnXlCGM",
}


def _make_demo_credential() -> EIDASCredential:
    """Construct the demo EIDASCredential from static data."""
    proof_data = _DEMO_CREDENTIAL_DATA["proof"]
    proof = LinkedDataProof(
        type=proof_data["type"],
        created=proof_data["created"],
        verification_method=proof_data["verificationMethod"],
        proof_purpose=proof_data["proofPurpose"],
        jws=proof_data["jws"],
    )
    return EIDASCredential(
        **{
            "@context": _DEMO_CREDENTIAL_DATA["@context"],
            "type": _DEMO_CREDENTIAL_DATA["type"],
            "credential_type": _DEMO_CREDENTIAL_DATA["credentialType"],
            "id": _DEMO_CREDENTIAL_DATA["id"],
            "issuer": _DEMO_CREDENTIAL_DATA["issuer"],
            "issuance_date": _DEMO_CREDENTIAL_DATA["issuanceDate"],
            "expiration_date": _DEMO_CREDENTIAL_DATA["expirationDate"],
            "credential_subject": _DEMO_CREDENTIAL_DATA["credentialSubject"],
            "proof": proof,
        }
    )


DEMO_CREDENTIAL: EIDASCredential = _make_demo_credential()


# ---------------------------------------------------------------------------
# EIDASWalletBridge
# ---------------------------------------------------------------------------


class EIDASWalletBridge:
    """
    Bridge between the VASP application and an EU Digital Identity Wallet.

    Simulates the EUDIW ARF protocol flow:
    1. Relying party sends an OpenID4VP Authorization Request.
    2. Wallet app presents a consent screen to the user.
    3. User approves selective attribute disclosure.
    4. Wallet returns a signed Verifiable Presentation.

    Example::

        bridge = EIDASWalletBridge(enabled=True, issuer_url='https://...')
        consent = await bridge.request_user_consent(...)
        if consent and consent.approved:
            vp = await bridge.create_presentation(...)
    """

    def __init__(
        self,
        enabled: bool,
        issuer_url: str,
        wallet_id: str | None = None,
    ) -> None:
        self._enabled = enabled
        self._issuer_url = issuer_url
        self._wallet_id = wallet_id or f"wallet_{uuid.uuid4().hex[:8]}"
        logger.info(
            "EIDASWalletBridge initialized",
            enabled=self._enabled,
            issuer_url=self._issuer_url,
            wallet_id=self._wallet_id,
        )

    # ---------------------------------------------------------------------------
    # Availability
    # ---------------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether the eIDAS wallet is available and properly configured.

        In production, this would attempt to open a channel to the device's
        EUDIW app and verify that a valid PID credential is installed.

        Returns:
            ``True`` if the wallet is ready to use.
        """
        if not self._enabled:
            logger.debug("eIDAS wallet disabled by configuration")
            return False
        if not self._issuer_url:
            logger.warning("eIDAS wallet enabled but issuer_url not configured")
            return False
        # In production: check wallet app availability via OS deep-link or SDK
        logger.debug("eIDAS wallet is available")
        return True

    # ---------------------------------------------------------------------------
    # User consent flow
    # ---------------------------------------------------------------------------

    async def request_user_consent(
        self,
        relying_party_name: str,
        relying_party_domain: str,
        requested_attributes: list[str],
        purpose: str,
    ) -> ConsentResult | None:
        """
        Request the user's consent to share identity attributes with a relying party.

        This is a critical UX gate: the user MUST explicitly approve each disclosure.
        Without approval, no identity data is ever sent.

        In production, this triggers the EUDIW app's consent screen via:
        - Same-device: deep-link / App Clip / Universal Link
        - Cross-device: QR code (OpenID4VP cross-device flow)

        Args:
            relying_party_name: Display name of the relying party.
            relying_party_domain: Domain of the relying party.
            requested_attributes: Credential attribute names requested.
            purpose: Human-readable reason for the request.

        Returns:
            :class:`ConsentResult` if approved, or ``None`` if declined.
        """
        if not self.is_available():
            logger.warning("eIDAS wallet not available, skipping consent request")
            return None

        logger.info(
            "Requesting eIDAS user consent",
            relying_party=relying_party_name,
            requested_attributes=requested_attributes,
            purpose=purpose,
        )

        # Production flow (ARF §6.3.2):
        # 1. Construct OpenID4VP Authorization Request
        # 2. Encode as QR code or deep-link to wallet app
        # 3. Poll or await callback with Authorization Response
        # 4. Validate VP Token and presentation submission
        #
        # Simulated flow: automatically approve in dev/test mode,
        # selecting only the requested attributes from the demo credential.
        is_simulated = current_app_env() != "production"
        if not is_simulated:
            logger.error("Production eIDAS wallet interaction not implemented")
            return None

        # Simulate user approving the consent (in production: wait for wallet callback)
        approved = True  # In production, this is the user's decision
        if not approved:
            logger.info("User declined eIDAS consent sharing")
            return None

        # Select only the requested attributes from the credential
        subject = _DEMO_CREDENTIAL_DATA["credentialSubject"]
        shared_attributes: dict[str, str] = {}
        for attr in requested_attributes:
            value = subject.get(attr)
            if value is not None:
                shared_attributes[attr] = value if isinstance(value, str) else json.dumps(value)

        consent_result = ConsentResult(
            approved=True,
            shared_attributes=shared_attributes,
            credential=DEMO_CREDENTIAL,
            timestamp=datetime.now(tz=UTC),
            consent_id=str(uuid.uuid4()),
        )

        logger.info(
            "eIDAS consent granted",
            consent_id=consent_result.consent_id,
            shared_attributes=list(shared_attributes.keys()),
            relying_party=relying_party_name,
        )

        return consent_result

    # ---------------------------------------------------------------------------
    # Verifiable Presentation creation
    # ---------------------------------------------------------------------------

    async def create_presentation(
        self,
        requested_attributes: list[str],
        relying_party_domain: str,
        challenge: str,
    ) -> VerifiablePresentation:
        """
        Create a W3C Verifiable Presentation with selective disclosure.

        Only the specific attributes approved by the user are included.
        The presentation is signed by the holder's wallet key (Ed25519).

        Args:
            requested_attributes: Attribute names to include.
            relying_party_domain: Domain of the relying party (audience).
            challenge: Nonce provided by the relying party (prevents replay).

        Returns:
            Signed :class:`VerifiablePresentation`.

        Raises:
            RuntimeError: If the eIDAS wallet is not available.
        """
        if not self.is_available():
            raise RuntimeError("eIDAS wallet is not available")

        logger.info(
            "Creating Verifiable Presentation",
            requested_attributes=requested_attributes,
            relying_party_domain=relying_party_domain,
        )

        source_subject: dict[str, Any] = dict(_DEMO_CREDENTIAL_DATA["credentialSubject"])

        # Build a selective-disclosure credential containing only requested attributes
        filtered_subject: dict[str, Any] = {}
        if "id" in source_subject:
            filtered_subject["id"] = source_subject["id"]
        for attr in requested_attributes:
            if attr in source_subject:
                filtered_subject[attr] = source_subject[attr]

        # Rebuild credential with filtered subject.
        # Use model_construct to bypass Union coercion of credential_subject,
        # keeping it as a plain dict so attributes are preserved.
        selective_credential = EIDASCredential.model_construct(
            context=_DEMO_CREDENTIAL_DATA["@context"],
            type=_DEMO_CREDENTIAL_DATA["type"],
            credential_type=_DEMO_CREDENTIAL_DATA["credentialType"],
            id=f"urn:uuid:{uuid.uuid4()}",
            issuer=_DEMO_CREDENTIAL_DATA["issuer"],
            issuance_date=_DEMO_CREDENTIAL_DATA["issuanceDate"],
            expiration_date=_DEMO_CREDENTIAL_DATA.get("expirationDate"),
            credential_subject=filtered_subject,
            proof=DEMO_CREDENTIAL.proof,
        )

        # Sign the presentation with the holder's key
        proof = await self._sign_presentation(selective_credential, challenge, relying_party_domain)

        holder_did = source_subject.get("id")
        presentation = VerifiablePresentation.model_construct(
            context=[
                "https://www.w3.org/2018/credentials/v1",
                "https://eudi.europa.eu/context/pid/v1",
            ],
            type=["VerifiablePresentation"],
            verifiable_credential=[selective_credential],
            proof=proof,
            holder=holder_did if holder_did else None,
        )

        logger.info(
            "Verifiable Presentation created",
            holder=presentation.holder,
            credential_count=len(presentation.verifiable_credential),
            attributes=requested_attributes,
        )

        return presentation

    # ---------------------------------------------------------------------------
    # Transaction signing
    # ---------------------------------------------------------------------------

    async def sign_transaction(
        self,
        transaction_hash: str,
        ivms101_data: object,
        relying_party: str,
    ) -> EIDASSignatureResponse:
        """
        Sign transaction data with a eIDAS qualified electronic signature.

        The signature covers the transaction hash AND the IVMS101 payload,
        binding the user's legal identity to this specific payment.

        Args:
            transaction_hash: Hash of the Lightning transaction.
            ivms101_data: The IVMS101 payload object to bind.
            relying_party: Domain of the relying party (audience).

        Returns:
            :class:`EIDASSignatureResponse` with certificate chain.

        Raises:
            RuntimeError: If the eIDAS wallet is not available.
        """
        if not self.is_available():
            raise RuntimeError("eIDAS wallet is not available")

        logger.info(
            "Signing transaction with eIDAS wallet",
            relying_party=relying_party,
            transaction_hash=transaction_hash[:16] + "...",
        )

        # Build the data-to-sign structure
        payload_str = json.dumps({"transactionHash": transaction_hash, "ivms101": ivms101_data})
        document_hash = sha256_hex(payload_str)

        data_to_sign_req = EIDASSignatureRequest(
            document_hash=document_hash,
            data_to_sign=document_hash,
            signature_algorithm="EdDSA",
            hash_algorithm="SHA-256",
            relying_party=relying_party,
            signature_reason="MiCA Travel Rule Identity Attestation",
            nonce=generate_nonce(),
        )

        subject_id = _DEMO_CREDENTIAL_DATA["credentialSubject"].get("id")
        issuer_val = _DEMO_CREDENTIAL_DATA["issuer"]
        issuer_str = issuer_val if isinstance(issuer_val, str) else issuer_val["id"]

        # Simulate a JWS: in production, use python-jose or PyJWT with Ed25519
        # For the demo, produce a plausible 3-part JWT structure
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_claims = {
            "iss": issuer_str,
            "aud": relying_party,
            "iat": int(time.time()),
            "nonce": data_to_sign_req.nonce,
            "dataToSign": data_to_sign_req.data_to_sign,
            "transactionHash": transaction_hash,
        }
        if subject_id:
            payload_claims["sub"] = subject_id
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_claims).encode()
        ).rstrip(b"=").decode()
        # Demo signature — not cryptographically valid
        sig_b64 = base64.urlsafe_b64encode(
            b"demo-eidas-sig-" + transaction_hash[:8].encode()
        ).rstrip(b"=").decode()
        jws = f"{header}.{payload_b64}.{sig_b64}"

        cert_data = json.dumps({
            "subject": subject_id,
            "issuer": issuer_str,
            "notBefore": _DEMO_CREDENTIAL_DATA["issuanceDate"],
            "notAfter": _DEMO_CREDENTIAL_DATA.get("expirationDate", ""),
        }).encode()
        signing_certificate = base64.b64encode(cert_data).decode()

        response = EIDASSignatureResponse(
            approved=True,
            signature=jws,
            signing_certificate=signing_certificate,
            timestamp=datetime.now(tz=UTC).isoformat(),
            signature_level=SignatureLevel.QES,
        )

        logger.info(
            "Transaction signed with eIDAS QES",
            signature_level=str(response.signature_level),
            timestamp=response.timestamp,
        )

        return response

    # ---------------------------------------------------------------------------
    # IVMS101 originator data from credentials
    # ---------------------------------------------------------------------------

    async def build_originator_from_credentials(
        self,
        consent_result: ConsentResult,
    ) -> dict[str, Any]:
        """
        Build an IVMS101 NaturalPerson record from the attributes the user
        approved sharing in the consent flow.

        Only includes attributes the user explicitly agreed to share.

        Args:
            consent_result: The result of the user consent flow.

        Returns:
            Dict with ``natural_person`` (:class:`NaturalPerson`) and
            ``signed`` (bool) indicating whether eIDAS was used.

        Raises:
            ValueError: If ``family_name`` is missing from shared attributes.
        """
        attrs = consent_result.shared_attributes

        given_name = attrs.get("given_name")
        family_name = attrs.get("family_name")

        if not family_name:
            raise ValueError("family_name is required to build IVMS101 originator data")

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

        natural_person = NaturalPerson(
            name=[NaturalPersonName(name_identifiers=[name_identifier])],
        )

        # Date and place of birth
        birth_date = attrs.get("birth_date")
        place_of_birth = attrs.get("place_of_birth")
        if birth_date:
            natural_person.date_and_place_of_birth = DateAndPlaceOfBirth(
                date_of_birth=birth_date,
                place_of_birth=place_of_birth or "",
            )

        # Country of residence
        nationality = attrs.get("nationality")
        if nationality:
            natural_person.country_of_residence = nationality

        logger.info(
            "Built IVMS101 originator from eIDAS credentials",
            consent_id=consent_result.consent_id,
            fields_included=list(attrs.keys()),
        )

        return {"natural_person": natural_person, "signed": True}

    # ---------------------------------------------------------------------------
    # Static verification methods
    # ---------------------------------------------------------------------------

    @staticmethod
    async def verify_presentation(
        presentation: VerifiablePresentation,
    ) -> VerificationResult:
        """
        Verify a Verifiable Presentation received from a counterparty.

        Checks:
        1. JSON-LD structure validity
        2. Credential expiry
        3. Holder proof (JWS signature)
        4. Issuer DID resolution and certificate chain

        Args:
            presentation: The VP to verify.

        Returns:
            :class:`VerificationResult` with attribute values.
        """
        logger.info(
            "Verifying eIDAS Verifiable Presentation",
            holder=presentation.holder,
            credential_count=len(presentation.verifiable_credential),
        )

        errors: list[str] = []

        # 1. Basic structure check
        if not presentation.context:
            errors.append("Missing @context")
        if not presentation.verifiable_credential:
            errors.append("No credentials in presentation")

        if not presentation.verifiable_credential:
            return VerificationResult(
                valid=False,
                issuer="",
                credential_type="",
                attributes={},
                signature_valid=False,
                certificate_chain_valid=False,
                errors=[*errors, "No credential found in presentation"],
            )

        credential = presentation.verifiable_credential[0]

        # 2. Check expiry
        if credential.expiration_date:
            try:
                expiry = datetime.fromisoformat(
                    credential.expiration_date.replace("Z", "+00:00")
                )
                if expiry < datetime.now(tz=UTC):
                    errors.append(f"Credential expired at {credential.expiration_date}")
            except ValueError:
                errors.append(f"Invalid expiration_date format: {credential.expiration_date}")

        # 3. Signature verification (simulated in reference impl)
        signature_valid = False
        try:
            proof = credential.proof
            if proof and proof.jws:
                # In production: resolve the issuer DID and verify with the issuer's public key
                # For reference: accept demo signatures and well-formed JWTs
                signature_valid = (
                    proof.jws.startswith("eyJ") or "demo-signature" in proof.jws
                )
        except Exception as err:  # noqa: BLE001
            errors.append(f"Signature verification error: {err}")

        # 4. Certificate chain (simulated)
        issuer_val = credential.issuer
        issuer_str = issuer_val if isinstance(issuer_val, str) else issuer_val.id
        certificate_chain_valid = issuer_str.startswith("did:")

        # 5. Extract attributes
        subject = credential.credential_subject
        attributes: dict[str, str] = {}
        # credential_subject may be a Pydantic model or a plain dict
        subject_dict: dict
        if isinstance(subject, dict):
            subject_dict = subject
        else:
            # Pydantic model — use model_dump to get all fields
            subject_dict = subject.model_dump(exclude_none=True)
        for key, value in subject_dict.items():
            if key != "id" and value is not None:
                attributes[key] = value if isinstance(value, str) else json.dumps(value)

        # Derive credential type
        credential_type = next(
            (t for t in credential.type if t != "VerifiableCredential"),
            "Unknown",
        )

        valid = len(errors) == 0 and signature_valid and certificate_chain_valid

        logger.info(
            "Presentation verification complete",
            valid=valid,
            issuer=issuer_str,
            signature_valid=signature_valid,
            attribute_count=len(attributes),
        )

        return VerificationResult(
            valid=valid,
            issuer=issuer_str,
            credential_type=credential_type,
            attributes=attributes,
            signature_valid=signature_valid,
            certificate_chain_valid=certificate_chain_valid,
            errors=errors if errors else None,
        )

    @staticmethod
    async def verify_signature(response: EIDASSignatureResponse) -> bool:
        """
        Verify a qualified electronic signature.

        In production, this would:
        1. Decode the JWS header to find the key ID
        2. Resolve the signer's certificate from a QTSP
        3. Verify the JWS signature
        4. Check certificate chain to a trusted eIDAS QTSP root
        5. Check revocation (OCSP / CRL)

        Args:
            response: The eIDAS signature response to verify.

        Returns:
            ``True`` if the signature is valid.
        """
        logger.info(
            "Verifying eIDAS qualified electronic signature",
            signature_level=str(response.signature_level),
            timestamp=response.timestamp,
        )

        if not response.signature:
            logger.warning("Empty signature")
            return False

        # Simulated verification: accept well-formed JWTs
        # In production: use joserfc or cryptography with resolved QTSP public key
        is_well_formed = len(response.signature.split(".")) == 3

        ts = response.timestamp or response.signed_at
        is_not_expired = True
        if ts:
            try:
                ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                is_not_expired = (
                    datetime.now(tz=UTC) - ts_dt
                ).total_seconds() < 86_400
            except ValueError:
                is_not_expired = True  # unparseable: assume not expired

        logger.info(
            "Signature verification result",
            is_well_formed=is_well_formed,
            is_not_expired=is_not_expired,
            signature_level=str(response.signature_level),
        )

        return is_well_formed and is_not_expired

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    async def _sign_presentation(
        self,
        credential: EIDASCredential,
        challenge: str,
        audience: str,
    ) -> LinkedDataProof:
        """Sign a Verifiable Presentation with the holder's key (demo implementation)."""
        credential_json = credential.model_dump_json()
        credential_hash = sha256_hex(credential_json)

        # Produce a plausible demo JWT (not cryptographically valid)
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "typ": "VP+JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_claims = {
            "vp_hash": credential_hash,
            "challenge": challenge,
            "aud": audience,
            "iat": int(time.time()),
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_claims).encode()
        ).rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(
            b"demo-vp-sig-" + challenge[:8].encode()
        ).rstrip(b"=").decode()
        jws = f"{header}.{payload_b64}.{sig_b64}"

        holder_did = _DEMO_CREDENTIAL_DATA["credentialSubject"].get("id")

        return LinkedDataProof(
            type="JsonWebSignature2020",
            created=datetime.now(tz=UTC).isoformat(),
            verification_method=f"{holder_did or 'did:key:demo'}#key-1",
            proof_purpose="authentication",
            jws=jws,
        )
