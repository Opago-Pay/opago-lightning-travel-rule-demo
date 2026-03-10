"""
IVMS101 Data Model Types

Implements the InterVASP Messaging Standard 101 (IVMS101) for Travel Rule compliance
as required by EU Transfer of Funds Regulation (TFR) / MiCA Article 68-72.

Reference: https://intervasp.org/ivms101
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

#: Name identifier type per IVMS101 section 2.2.
NaturalPersonNameTypeCode = Literal["ALIA", "BIRT", "MAID", "LEGL", "MISC"]

#: Legal person name identifier type per IVMS101 section 2.3.
LegalPersonNameTypeCode = Literal["LEGL", "SHRT", "TRAD"]

#: Address type per IVMS101 section 2.7.
AddressTypeCode = Literal["HOME", "BIZZ", "GEOG"]

#: National identifier type codes per IVMS101 section 2.8.
NationalIdentifierTypeCode = Literal[
    "ARNU",  # Alien registration number
    "CCPT",  # Passport number
    "RAID",  # Registration authority identifier
    "DRLC",  # Driver's licence number
    "FIIN",  # Foreign investment identity number
    "TXID",  # Tax identification number
    "SOCS",  # Social security number
    "IDCD",  # Identity card number
    "LEIX",  # Legal entity identifier (LEI)
    "MISC",  # Unspecified
]


# ---------------------------------------------------------------------------
# Natural Person
# ---------------------------------------------------------------------------


class NaturalPersonNameIdentifier(BaseModel):
    """A single name identifier for a natural person."""

    model_config = ConfigDict(populate_by_name=True)

    #: Family name / surname.
    primary_identifier: str
    #: Given name(s) / forename(s).
    secondary_identifier: str | None = None
    name_identifier_type: NaturalPersonNameTypeCode


class NaturalPersonName(BaseModel):
    """Name record for a natural person (wrapper that groups identifiers)."""

    model_config = ConfigDict(populate_by_name=True)

    name_identifiers: list[NaturalPersonNameIdentifier]
    local_name_identifiers: list[NaturalPersonNameIdentifier] | None = None
    phonetic_name_identifiers: list[NaturalPersonNameIdentifier] | None = None


class DateAndPlaceOfBirth(BaseModel):
    """Date of birth with place."""

    model_config = ConfigDict(populate_by_name=True)

    #: ISO 8601 date: YYYY-MM-DD.
    date_of_birth: str
    place_of_birth: str


class NationalIdentification(BaseModel):
    """National identification for natural persons."""

    model_config = ConfigDict(populate_by_name=True)

    national_identifier: str
    national_identifier_type: NationalIdentifierTypeCode
    #: ISO 3166-1 alpha-2.
    country_of_issue: str | None = None
    registration_authority: str | None = None


class NaturalPerson(BaseModel):
    """
    Natural person as defined by IVMS101.
    name holds structured name records; name_identifier is a flat shorthand.
    """

    model_config = ConfigDict(populate_by_name=True)

    #: Structured name records (IVMS101 wire format).
    name: list[NaturalPersonName] | None = None
    #: Flat name identifier list (shorthand used by core modules).
    name_identifier: list[NaturalPersonNameIdentifier] | None = None
    geographic_address: list[GeographicAddress] | None = None
    national_identification: NationalIdentification | None = None
    customer_identification: str | None = None
    date_and_place_of_birth: DateAndPlaceOfBirth | None = None
    #: ISO 3166-1 alpha-2 country code.
    country_of_residence: str | None = None


# ---------------------------------------------------------------------------
# Legal Person
# ---------------------------------------------------------------------------


class LegalPersonNameIdentifier(BaseModel):
    """A single name identifier for a legal person."""

    model_config = ConfigDict(populate_by_name=True)

    legal_person_name: str
    legal_person_name_identifier_type: LegalPersonNameTypeCode


class LegalPersonName(BaseModel):
    """Name record for a legal person."""

    model_config = ConfigDict(populate_by_name=True)

    name_identifiers: list[LegalPersonNameIdentifier]
    local_name_identifiers: list[LegalPersonNameIdentifier] | None = None
    phonetic_name_identifiers: list[LegalPersonNameIdentifier] | None = None


class LegalPersonNationalIdentification(BaseModel):
    """National identification / registration details for a legal person."""

    model_config = ConfigDict(populate_by_name=True)

    #: LEI or other registration number.
    national_identifier: str
    national_identifier_type: NationalIdentifierTypeCode
    #: ISO 3166-1 alpha-2 country code where registered.
    country_of_issue: str | None = None
    #: Registration authority code (GLEIF / national registry).
    registration_authority: str | None = None
    registration_authority_name: str | None = None


class LegalPerson(BaseModel):
    """Legal person as defined by IVMS101."""

    model_config = ConfigDict(populate_by_name=True)

    #: Structured name records (IVMS101 wire format).
    name: list[LegalPersonName] | None = None
    #: Flat name identifier list (shorthand).
    legal_person_name_identifier: list[LegalPersonNameIdentifier] | None = None
    geographic_address: list[GeographicAddress] | None = None
    national_identification: (
        NationalIdentification | LegalPersonNationalIdentification | None
    ) = None
    customer_number: str | None = None
    customer_identification: str | None = None
    #: ISO 3166-1 alpha-2 country of registration.
    country_of_registration: str | None = None


# ---------------------------------------------------------------------------
# Shared sub-types
# ---------------------------------------------------------------------------


class GeographicAddress(BaseModel):
    """Structured geographic address (postal address)."""

    model_config = ConfigDict(populate_by_name=True)

    address_type: AddressTypeCode
    street_name: str | None = None
    building_number: str | None = None
    building_name: str | None = None
    floor: str | None = None
    post_box: str | None = None
    room: str | None = None
    post_code: str | None = None
    town_name: str
    town_location_name: str | None = None
    district_name: str | None = None
    #: ISO 3166-2 sub-division code.
    country_sub_division: str | None = None
    #: ISO 3166-1 alpha-2 country code.
    country: str
    address_line: list[str] | None = None


#: Address is an alias for GeographicAddress (IVMS101 wire format name).
Address = GeographicAddress


# ---------------------------------------------------------------------------
# Person discriminated union
# ---------------------------------------------------------------------------


class PersonType(BaseModel):
    """
    PersonType represents a person record that may be either a natural person
    or a legal person. Both fields are optional so the type is compatible with
    both strict discriminated union access and direct property access
    (person.natural_person, person.legal_person) used by IVMS101 wire format adapters.
    """

    model_config = ConfigDict(populate_by_name=True)

    natural_person: NaturalPerson | None = None
    legal_person: LegalPerson | None = None


# ---------------------------------------------------------------------------
# Originator & Beneficiary (MiCA / uma-mica variant)
# ---------------------------------------------------------------------------


class Originator(BaseModel):
    """Originator (sender / payer) — flat person array variant."""

    model_config = ConfigDict(populate_by_name=True)

    originator_persons: list[PersonType]
    account_number: list[str]


class Beneficiary(BaseModel):
    """Beneficiary (receiver / payee) — flat person array variant."""

    model_config = ConfigDict(populate_by_name=True)

    beneficiary_persons: list[PersonType]
    account_number: list[str]


# ---------------------------------------------------------------------------
# Originator / Beneficiary person wrappers (IVMS101 wire format)
# ---------------------------------------------------------------------------


class OriginatorPerson(BaseModel):
    """A person record tagged as originator (IVMS101 wire format)."""

    model_config = ConfigDict(populate_by_name=True)

    natural_person: NaturalPerson | None = None
    legal_person: LegalPerson | None = None


class BeneficiaryPerson(BaseModel):
    """A person record tagged as beneficiary (IVMS101 wire format)."""

    model_config = ConfigDict(populate_by_name=True)

    natural_person: NaturalPerson | None = None
    legal_person: LegalPerson | None = None


# ---------------------------------------------------------------------------
# VASP Information
# ---------------------------------------------------------------------------


class _LegalPersonWrapper(BaseModel):
    """Internal wrapper — associates a LegalPerson with a VASP role."""

    model_config = ConfigDict(populate_by_name=True)

    legal_person: LegalPerson


class OriginatingVASP(BaseModel):
    """Identifies the originating VASP."""

    model_config = ConfigDict(populate_by_name=True)

    originating_vasp: _LegalPersonWrapper


class BeneficiaryVASP(BaseModel):
    """Identifies the beneficiary VASP (optional if self-hosted)."""

    model_config = ConfigDict(populate_by_name=True)

    beneficiary_vasp: _LegalPersonWrapper


# ---------------------------------------------------------------------------
# Transfer Path
# ---------------------------------------------------------------------------


class TransferPathEntry(BaseModel):
    """A single hop in a multi-hop transfer path."""

    model_config = ConfigDict(populate_by_name=True)

    vasp: _LegalPersonWrapper
    sequence_number: int
    transmission_timestamp: str | None = None


class TransferPathPerson(BaseModel):
    """A single hop in the transfer path (IVMS101 wire format)."""

    model_config = ConfigDict(populate_by_name=True)

    legal_person: LegalPerson | None = None
    natural_person: NaturalPerson | None = None
    intermediary_sequence: int | None = None


class TransferPath(BaseModel):
    """Full transfer path."""

    model_config = ConfigDict(populate_by_name=True)

    #: MiCA / uma-mica variant.
    transfer_path: list[TransferPathEntry] | None = None
    #: IVMS101 wire format variant.
    transfer_path_persons: list[TransferPathPerson] | None = None


# ---------------------------------------------------------------------------
# Payload metadata
# ---------------------------------------------------------------------------


class TransliterationMethod(BaseModel):
    """Transliteration method code container."""

    model_config = ConfigDict(populate_by_name=True)

    transliteration_method_code: str


class PayloadMetadata(BaseModel):
    """Payload-level metadata for IVMS101 messages."""

    model_config = ConfigDict(populate_by_name=True)

    transliteration_method: list[TransliterationMethod] | None = None


# ---------------------------------------------------------------------------
# Top-level IVMS101 payload
# ---------------------------------------------------------------------------


class IVMS101Payload(BaseModel):
    """
    Complete IVMS101 payload as sent between VASPs.
    Supports both the MiCA/uma-mica variant (with originating_vasp) and
    the raw IVMS101 wire format (without).
    """

    model_config = ConfigDict(populate_by_name=True)

    originator: Originator
    beneficiary: Beneficiary
    #: MiCA variant: originatingVASP object.
    originating_vasp: OriginatingVASP | None = None
    #: MiCA variant: beneficiaryVASP object.
    beneficiary_vasp: BeneficiaryVASP | None = None
    transfer_path: TransferPath | None = None
    payload_metadata: PayloadMetadata | None = None
    #: ISO 8601 timestamp of payload creation.
    payload_created_at: str | None = None
    #: Payload version.
    ivms_version: Literal["2020-1"] | None = None
