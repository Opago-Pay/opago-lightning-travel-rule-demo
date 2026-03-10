"""
eIDAS Wallet Types.

Defines data structures for EU eIDAS 2.0 / European Digital Identity (EUDI)
wallet integration in the MiCA compliance context.

References:
  - eIDAS 2.0 Regulation (EU) 2024/1183
  - EUDI Wallet Architecture Reference Framework (ARF) v1.4
  - W3C Verifiable Credentials Data Model 2.0
  - OpenID4VP (OpenID for Verifiable Presentations)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Credential Types
# ---------------------------------------------------------------------------


class CredentialType(StrEnum):
    """Credential types supported by the EUDI wallet integration."""

    #: National identity credential (eID).
    IDENTITY = "IDENTITY"
    #: Professional qualification credential.
    PROFESSIONAL = "PROFESSIONAL"
    #: Age verification credential (GDPR-privacy-preserving).
    AGE_VERIFICATION = "AGE_VERIFICATION"
    #: Address proof credential.
    ADDRESS_PROOF = "ADDRESS_PROOF"
    #: Bank account ownership credential (PSD2 / OpenBanking).
    BANK_ACCOUNT = "BANK_ACCOUNT"


# ---------------------------------------------------------------------------
# Signature Level
# ---------------------------------------------------------------------------


class SignatureLevel(StrEnum):
    """eIDAS electronic signature assurance levels."""

    #: Qualified Electronic Signature (highest level).
    QES = "QES"
    #: Advanced Electronic Signature.
    AdES = "AdES"
    #: Simple Electronic Signature.
    SES = "SES"


# ---------------------------------------------------------------------------
# Proof
# ---------------------------------------------------------------------------


class LinkedDataProof(BaseModel):
    """
    Linked data proof as per W3C VC Data Model 2.0, section 4.8.
    """

    model_config = ConfigDict(populate_by_name=True)

    #: Proof type (e.g. 'JsonWebSignature2020', 'Ed25519Signature2020').
    type: str
    #: ISO 8601 creation timestamp.
    created: str
    #: DID URL of the verification method used.
    verification_method: str
    #: Purpose of the proof (e.g. 'assertionMethod', 'authentication').
    proof_purpose: str
    #: JWS compact serialisation or base64url signature value.
    jws: str | None = None
    proof_value: str | None = None
    #: Challenge for replay protection (when requested by relying party).
    challenge: str | None = None
    #: Domain for which the proof was created.
    domain: str | None = None


# ---------------------------------------------------------------------------
# Credential Subject
# ---------------------------------------------------------------------------


class IdentityCredentialSubject(BaseModel):
    """
    Subject claims within an eIDAS IDENTITY credential.
    Corresponds to EUDI PID (Person Identification Data) attribute set.
    """

    model_config = ConfigDict(populate_by_name=True)

    #: DID or other identifier of the subject.
    id: str | None = None
    #: Given name.
    given_name: str
    #: Family name.
    family_name: str
    #: ISO 8601 date of birth.
    birth_date: str
    birth_place: str | None = None
    #: ISO 3166-1 alpha-2 nationality.
    nationality: str | None = None
    #: ISO 3166-1 alpha-2 country of residence.
    resident_country: str | None = None
    resident_address: str | None = None
    #: National document number.
    personal_identifier: str | None = None
    #: Gender code (M / F / X).
    gender: str | None = None


class AgeVerificationCredentialSubject(BaseModel):
    """
    Subject claims within an AGE_VERIFICATION credential.
    Uses selective disclosure / ZKP – only reveals age_over_18 or exact date.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    #: Whether the holder is 18 or older (privacy-preserving boolean).
    age_over_18: bool | None = None
    #: Minimum age confirmed (if more granularity is needed).
    age_over: int | None = None
    #: Exact birth date (only shared if explicitly consented to).
    birth_date: str | None = None


#: Union of all supported credential subject types.
CredentialSubject = IdentityCredentialSubject | AgeVerificationCredentialSubject | dict[str, Any]

# ---------------------------------------------------------------------------
# eIDAS Verifiable Credential
# ---------------------------------------------------------------------------


class _CredentialStatus(BaseModel):
    """Status endpoint for revocation check."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str


class _CredentialSchema(BaseModel):
    """Schema definition for a credential type."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str


class _IssuerObject(BaseModel):
    """Issuer represented as an object with optional name."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str | None = None


class EIDASCredential(BaseModel):
    """A single eIDAS-compliant Verifiable Credential (W3C VC Data Model 2.0)."""

    model_config = ConfigDict(populate_by_name=True)

    #: W3C context URLs.
    context: list[str] = Field(alias="@context")

    #: Unique credential identifier (URI).
    id: str | None = None

    #: Credential type array (always includes 'VerifiableCredential').
    type: list[str]

    credential_type: CredentialType

    #: DID of the issuing authority (e.g. national eID provider).
    issuer: str | _IssuerObject

    #: ISO 8601 issuance date.
    issuance_date: str

    #: ISO 8601 expiration date.
    expiration_date: str | None = None

    credential_subject: CredentialSubject

    #: Cryptographic proof over the credential.
    proof: LinkedDataProof | None = None

    #: Status endpoint for revocation check.
    credential_status: _CredentialStatus | None = None

    #: Schema definition for this credential type.
    credential_schema: _CredentialSchema | None = None


# ---------------------------------------------------------------------------
# Verifiable Presentation
# ---------------------------------------------------------------------------


class VerifiablePresentation(BaseModel):
    """
    W3C Verifiable Presentation holding one or more VCs.
    Used in OpenID4VP flows to present credentials to relying parties.
    """

    model_config = ConfigDict(populate_by_name=True)

    context: list[str] = Field(alias="@context")

    #: Always includes 'VerifiablePresentation'.
    type: list[str]

    #: The embedded verifiable credentials.
    verifiable_credential: list[EIDASCredential]

    #: DID of the holder.
    holder: str | None = None

    #: Proof over the presentation (signed by the holder's wallet).
    proof: LinkedDataProof | None = None

    #: Presentation ID (UUID).
    id: str | None = None


# ---------------------------------------------------------------------------
# EUDI Wallet Configuration
# ---------------------------------------------------------------------------


class EIDASWalletConfig(BaseModel):
    """Configuration for the EUDI wallet integration at a VASP."""

    model_config = ConfigDict(populate_by_name=True)

    #: Whether eIDAS wallet integration is enabled.
    enabled: bool

    #: Issuer URL (OpenID Connect Issuer URL of the trusted eID provider).
    issuer_url: str | None = None

    #: Wallet instance identifier (assigned by the wallet provider).
    wallet_id: str | None = None

    #: Credential types this VASP accepts from customers.
    supported_credential_types: list[CredentialType]

    #: Trusted issuer DID list.
    trusted_issuers: list[str] | None = None

    #: Whether to require selective disclosure (privacy-by-design).
    require_selective_disclosure: bool | None = None

    #: Nonce TTL in seconds for replay protection (default: 300).
    nonce_ttl_seconds: int | None = None


# ---------------------------------------------------------------------------
# eIDAS Signature Request & Response
# ---------------------------------------------------------------------------


class _RelyingParty(BaseModel):
    """Structured relying party info presented to the wallet user."""

    model_config = ConfigDict(populate_by_name=True)

    #: VASP legal name.
    name: str
    #: VASP domain.
    domain: str
    #: Reason for requesting the signature (shown to wallet user).
    purpose: str
    #: VASP logo URL (optional).
    logo_url: str | None = None


class EIDASSignatureRequest(BaseModel):
    """
    Request sent to the EUDI wallet to create an eIDAS signature.
    Follows the OpenID4VP + HAIP (High Assurance Interoperability Profile) flow.
    """

    model_config = ConfigDict(populate_by_name=True)

    #: SHA-256 hash (hex) of the document / payload to be signed.
    document_hash: str

    #: Pre-computed hash of the data to be signed (alias used internally).
    data_to_sign: str | None = None

    #: Hashing algorithm used (default: 'SHA-256').
    hash_algorithm: str | None = None

    #: Signature algorithm (e.g. 'EdDSA', 'ES256').
    signature_algorithm: str | None = None

    #: Single-use random nonce for anti-replay protection.
    nonce: str | None = None

    #: Credential type to use for signing.
    credential_type: CredentialType | None = None

    #: Selective disclosure: list of credential fields to include.
    selective_disclosure: list[str] | None = None

    #: Relying party (VASP) information presented to the wallet user.
    relying_party: _RelyingParty | str

    #: Human-readable reason for requesting the signature.
    signature_reason: str | None = None

    #: Challenge nonce for binding the wallet response to this request.
    challenge: str | None = None

    #: Request expiry (ISO 8601).
    expires_at: str | None = None


class _SignatureError(BaseModel):
    """Error details when an eIDAS signature request is rejected."""

    model_config = ConfigDict(populate_by_name=True)

    code: str
    message: str


class EIDASSignatureResponse(BaseModel):
    """Response from the EUDI wallet after the user approves the signature."""

    model_config = ConfigDict(populate_by_name=True)

    #: Whether the user approved the request.
    approved: bool

    #: Raw JWS / PKCS#7 signature created by the wallet.
    signature: str | None = None

    #: PEM-encoded qualified certificate of the signer.
    certificate: str | None = None

    #: Base64-encoded DER qualified certificate (alternative to certificate).
    signing_certificate: str | None = None

    #: ISO 8601 timestamp when the signature was created.
    signed_at: str | None = None

    #: ISO 8601 timestamp of signature creation (alias of signed_at).
    timestamp: str | None = None

    #: eIDAS signature level.
    signature_level: SignatureLevel | None = None

    #: Verifiable Presentation with disclosed attributes.
    credential_presentation: VerifiablePresentation | None = None

    #: QTSP that issued the certificate.
    qtsp_id: str | None = None

    #: Error details if approved=False.
    error: _SignatureError | None = None


# ---------------------------------------------------------------------------
# Verification Result
# ---------------------------------------------------------------------------


class EIDASVerificationResult(BaseModel):
    """Result of verifying an eIDAS credential or signature."""

    model_config = ConfigDict(populate_by_name=True)

    valid: bool
    #: Whether the credential/certificate has a qualified status.
    qualified: bool
    #: Whether the credential is within its validity period.
    not_expired: bool
    #: Whether the issuer is on the EU Trusted List.
    trusted_issuer: bool
    #: Whether the signature cryptographically verifies.
    signature_valid: bool
    #: Error messages (if not valid).
    errors: list[str]
    #: Warnings (non-fatal issues).
    warnings: list[str]
    #: Verified attribute claims extracted from the credential.
    verified_claims: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------

#: Alias for CredentialSubject — used by pre-existing eidas-wallet modules.
EIDASCredentialSubject = CredentialSubject

#: Alias for LinkedDataProof — used by pre-existing eidas-wallet modules.
EIDASProof = LinkedDataProof


class EIDASAddress(BaseModel):
    """Geographic address type used in eIDAS credentials."""

    model_config = ConfigDict(populate_by_name=True)

    street: str | None = None
    house_number: str | None = None
    postal_code: str | None = None
    city: str | None = None
    country: str


# ---------------------------------------------------------------------------
# OpenID4VP types
# ---------------------------------------------------------------------------


class _FieldConstraint(BaseModel):
    """A single field constraint in a DIF Input Descriptor."""

    model_config = ConfigDict(populate_by_name=True)

    path: list[str]
    filter: dict[str, Any] | None = None
    optional: bool | None = None


class _InputDescriptorConstraints(BaseModel):
    """Constraints block within an Input Descriptor."""

    model_config = ConfigDict(populate_by_name=True)

    fields: list[_FieldConstraint] | None = None
    limit_disclosure: Literal["required", "preferred"] | None = None


class InputDescriptor(BaseModel):
    """
    DIF Presentation Exchange — Input Descriptor.
    See: https://identity.foundation/presentation-exchange/
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str | None = None
    purpose: str | None = None
    format: dict[str, Any] | None = None
    constraints: _InputDescriptorConstraints


class PresentationDefinition(BaseModel):
    """
    DIF Presentation Exchange — Presentation Definition.
    See: https://identity.foundation/presentation-exchange/
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str | None = None
    purpose: str | None = None
    format: dict[str, Any] | None = None
    input_descriptors: list[InputDescriptor]


class OpenID4VPAuthorizationRequest(BaseModel):
    """
    OpenID for Verifiable Presentations — Authorization Request.
    See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
    """

    model_config = ConfigDict(populate_by_name=True)

    response_type: Literal["vp_token"]
    presentation_definition: PresentationDefinition
    client_id: str
    client_metadata: dict[str, Any] | None = None
    nonce: str
    state: str | None = None
    response_mode: Literal["direct_post", "fragment", "query"] | None = None
    response_uri: str | None = None
