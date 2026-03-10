"""
Cryptographic Utilities

Comprehensive crypto helpers for MiCA-compliant UMA messaging:
 - SHA-256 hashing (hash_data, sha256_hex, sha256_base64url)
 - Random nonce generation
 - Base64url encoding/decoding
 - ECDH P-256 key pair generation (for JWE travel rule encryption)
 - Ed25519 key pair generation (for signatures / eIDAS proofs)
 - JWE encryption / decryption (ECDH-ES+A256KW / A256GCM) via joserfc
 - JWS signing / verification (ES256) via python-jose
 - Simple AES-256-GCM symmetric encryption (legacy / testing)
 - JWK import / export helpers

Uses ``joserfc`` for JWE compact encryption/decryption, ``python-jose`` for
JWS/JWT signing and verification, ``cryptography`` for key handling and
low-level primitives, and Python's built-in :mod:`hashlib` / :mod:`os` /
:mod:`secrets` modules.

JWE (ECDH-ES+A256KW / A256GCM) is implemented via the ``joserfc`` library.
JWT / JWS (ES256) is implemented via the ``python-jose[cryptography]`` library.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import jwt as jose_jwt
from jose.constants import ALGORITHMS
from joserfc import jwe as joserfc_jwe
from joserfc.jwk import ECKey as JosercECKey

from opago_mica.utils.logger import logger

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def sha256_hex(data: str) -> str:
    """
    Compute the SHA-256 hash of a string and return it as a hex string.

    Args:
        data: UTF-8 string to hash.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_base64url(data: str) -> str:
    """
    Compute the SHA-256 hash of a string and return it as a base64url string.

    Args:
        data: UTF-8 string to hash.
    """
    digest = hashlib.sha256(data.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def hash_data(data: str | bytes) -> str:
    """
    Compute a SHA-256 hash and return the hex-encoded digest.
    Accepts both string and bytes inputs.

    Args:
        data: String or bytes to hash.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def hash_object(obj: Any) -> str:
    """
    Compute a SHA-256 hash of a JSON-serialisable object.
    Uses sorted keys for deterministic serialisation.

    Args:
        obj: Any JSON-serialisable value.
    """
    if isinstance(obj, dict):
        serialised = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    else:
        serialised = json.dumps(obj, separators=(",", ":"))
    return hash_data(serialised)


# ---------------------------------------------------------------------------
# Random nonces
# ---------------------------------------------------------------------------


def generate_nonce(byte_count: int = 16) -> str:
    """
    Generate a cryptographically random nonce as a hex string.

    Args:
        byte_count: Number of random bytes (default 16 → 32 hex chars).
    """
    return secrets.token_hex(byte_count)


def generate_base64url_nonce(byte_length: int = 16) -> str:
    """
    Generate a URL-safe base64 nonce suitable for JWS ``jti`` claims.

    Args:
        byte_length: Number of random bytes (default 16).
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(byte_length)).rstrip(b"=").decode("ascii")


def generate_uuid_nonce() -> str:
    """
    Generate a UUID-format nonce (8-4-4-4-12 hex chars).
    Uses UUIDv4 (random).
    """
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------


def to_base64url(data: bytes | str) -> str:
    """
    Encode bytes or a string to base64url (no padding).

    Args:
        data: Bytes or UTF-8 string to encode.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def from_base64url(data: str) -> str:
    """
    Decode a base64url string to a UTF-8 string.
    Non-UTF-8 bytes are replaced with the Unicode replacement character.

    Args:
        data: Base64url-encoded string (padding optional).
    """
    return from_base64url_bytes(data).decode("utf-8", errors="replace")


def from_base64url_bytes(data: str) -> bytes:
    """
    Decode a base64url string to raw bytes.

    Args:
        data: Base64url-encoded string (padding optional).
    """
    # Add missing padding
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


# ---------------------------------------------------------------------------
# Public key extraction from JWK dict
# ---------------------------------------------------------------------------

_PRIVATE_FIELDS = frozenset(["d", "p", "q", "dp", "dq", "qi"])


def extract_public_jwk(private_jwk: dict[str, Any]) -> dict[str, Any]:
    """
    Strips private key fields (d, p, q, dp, dq, qi) from a JWK dict.

    Args:
        private_jwk: JWK dict that may contain private key material.

    Returns:
        A copy of the JWK with all private fields removed.
    """
    return {k: v for k, v in private_jwk.items() if k not in _PRIVATE_FIELDS}


# ---------------------------------------------------------------------------
# ECDH P-256 key pair (for JWE travel rule payload encryption)
# ---------------------------------------------------------------------------


@dataclass
class ECDHKeyPair:
    """An ECDH key pair in JWK dict format."""

    public_key: dict[str, Any]
    private_key: dict[str, Any]


def _ec_key_to_jwk(
    private_key: EllipticCurvePrivateKey,
    use: str = "enc",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Export a P-256 EllipticCurvePrivateKey to JWK dicts (private + public)."""

    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    key_size_bytes = (private_key.key_size + 7) // 8

    x = base64.urlsafe_b64encode(
        public_numbers.x.to_bytes(key_size_bytes, "big")
    ).rstrip(b"=").decode("ascii")
    y = base64.urlsafe_b64encode(
        public_numbers.y.to_bytes(key_size_bytes, "big")
    ).rstrip(b"=").decode("ascii")
    d = base64.urlsafe_b64encode(
        private_numbers.private_value.to_bytes(key_size_bytes, "big")
    ).rstrip(b"=").decode("ascii")

    private_jwk: dict[str, Any] = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "d": d, "use": use}
    public_jwk: dict[str, Any] = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": use}
    return private_jwk, public_jwk


def generate_ecdh_key_pair() -> ECDHKeyPair:
    """
    Generate an ECDH P-256 key pair for travel rule data encryption.
    The public key can be published in UMA configuration.

    Returns:
        :class:`ECDHKeyPair` with ``public_key`` and ``private_key`` as JWK dicts.
    """
    private_key = generate_private_key(SECP256R1())
    priv_jwk, pub_jwk = _ec_key_to_jwk(private_key, use="enc")
    return ECDHKeyPair(public_key=pub_jwk, private_key=priv_jwk)


# ---------------------------------------------------------------------------
# EC P-256 key pair (for JWS ES256 signing)
# ---------------------------------------------------------------------------


@dataclass
class KeyPair:
    """An EC P-256 key pair in both JWK dict and PEM format."""

    private_key_jwk: dict[str, Any]
    public_key_jwk: dict[str, Any]
    private_key_pem: str
    public_key_pem: str


def generate_key_pair(use: str = "sig") -> KeyPair:
    """
    Generate an EC P-256 key pair suitable for both JWE (ECDH-ES) and
    JWS (ES256) operations.

    Args:
        use: Key use: ``'enc'`` for encryption or ``'sig'`` for signing.

    Returns:
        :class:`KeyPair` with JWK dicts and PEM strings.
    """
    private_key = generate_private_key(SECP256R1())
    priv_jwk, pub_jwk = _ec_key_to_jwk(private_key, use=use)

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return KeyPair(
        private_key_jwk=priv_jwk,
        public_key_jwk=pub_jwk,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )


# ---------------------------------------------------------------------------
# Ed25519 key pair (for signing / eIDAS proofs)
# ---------------------------------------------------------------------------


@dataclass
class Ed25519KeyPair:
    """An Ed25519 key pair in JWK dict format."""

    public_key: dict[str, Any]
    private_key: dict[str, Any]


def generate_ed25519_key_pair() -> Ed25519KeyPair:
    """
    Generate an Ed25519 key pair.
    Used for signing IVMS101 data and Verifiable Presentations.

    Returns:
        :class:`Ed25519KeyPair` with ``public_key`` and ``private_key`` as JWK dicts.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Export raw bytes for JWK
    priv_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    d = base64.urlsafe_b64encode(priv_raw).rstrip(b"=").decode("ascii")
    x = base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")

    private_jwk: dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}
    public_jwk: dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": x}
    return Ed25519KeyPair(public_key=public_jwk, private_key=private_jwk)


# ---------------------------------------------------------------------------
# JWK helpers
# ---------------------------------------------------------------------------


def export_public_key_base64(jwk: dict[str, Any]) -> str:
    """
    Export a JWK public key as a compact base64url string.
    Used in UMA configuration and LNURL responses.

    Args:
        jwk: JWK dict (public or private; private fields are stripped).
    """
    return to_base64url(json.dumps(extract_public_jwk(jwk)))


def import_public_key_base64(base64_key: str) -> dict[str, Any]:
    """
    Import a base64url-encoded JWK public key.

    Args:
        base64_key: Base64url-encoded JSON JWK string.

    Returns:
        JWK dict.
    """
    raw = from_base64url(base64_key)
    return json.loads(raw)


# ---------------------------------------------------------------------------
# JWE Encryption — JWK-based (ECDH-ES+A256KW / A256GCM)
# ---------------------------------------------------------------------------


@dataclass
class EncryptionResult:
    """Result of a JWE encryption operation."""

    jwe: str
    encrypted_at: str


def _jwk_dict_to_ec_public_key(jwk: dict[str, Any]) -> EllipticCurvePublicKey:
    """Reconstruct a P-256 public key from a JWK dict."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        EllipticCurvePublicNumbers,
    )

    def _decode_b64url(s: str) -> int:
        padded = s + "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    x = _decode_b64url(jwk["x"])
    y = _decode_b64url(jwk["y"])
    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    return pub_numbers.public_key()


def _jwk_dict_to_ec_private_key(jwk: dict[str, Any]) -> EllipticCurvePrivateKey:
    """Reconstruct a P-256 private key from a JWK dict."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicNumbers,
    )

    def _decode_b64url(s: str) -> int:
        padded = s + "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    x = _decode_b64url(jwk["x"])
    y = _decode_b64url(jwk["y"])
    d = _decode_b64url(jwk["d"])
    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    priv_numbers = EllipticCurvePrivateNumbers(private_value=d, public_numbers=pub_numbers)
    return priv_numbers.private_key()


def encrypt_payload_with_jwk(
    payload: Any,
    recipient_public_key_jwk: dict[str, Any],
) -> EncryptionResult:
    """
    Encrypt a payload using JWE with ECDH-ES+A256KW key agreement and
    A256GCM content encryption.

    Args:
        payload: Object or string to encrypt.
        recipient_public_key_jwk: JWK dict of the recipient's public key.

    Returns:
        :class:`EncryptionResult` with ``jwe`` compact serialisation and timestamp.
    """
    plaintext_bytes: bytes = (
        payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
    )
    # Strip private fields so joserfc accepts the key as a public key
    pub_jwk = extract_public_jwk(recipient_public_key_jwk)
    recipient_key = JosercECKey.import_key(pub_jwk)
    jwe_token: str = joserfc_jwe.encrypt_compact(
        {"alg": "ECDH-ES+A256KW", "enc": "A256GCM", "cty": "json"},
        plaintext_bytes,
        recipient_key,
    )
    return EncryptionResult(
        jwe=jwe_token,
        encrypted_at=datetime.now(tz=UTC).isoformat(),
    )


def decrypt_payload_with_jwk(
    jwe_token: str,
    private_key_jwk: dict[str, Any],
) -> Any:
    """
    Decrypt a JWE compact serialisation using the recipient's private JWK.

    Args:
        jwe_token: JWE compact serialisation string.
        private_key_jwk: JWK dict of the recipient's private key.

    Returns:
        Decrypted payload (parsed as JSON if possible, otherwise plain text string).
    """
    recipient_key = JosercECKey.import_key(private_key_jwk)
    result = joserfc_jwe.decrypt_compact(jwe_token, recipient_key)
    text = result.plaintext.decode("utf-8")
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text


def encrypt_payload_with_pem(
    payload: Any,
    recipient_public_key_pem: str,
) -> EncryptionResult:
    """
    Encrypt a payload using a PEM-encoded SPKI public key.

    Args:
        payload: Object or string to encrypt.
        recipient_public_key_pem: PEM-encoded SPKI public key string.

    Returns:
        :class:`EncryptionResult` with ``jwe`` compact serialisation and timestamp.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    public_key = load_pem_public_key(recipient_public_key_pem.encode("utf-8"))
    assert isinstance(public_key, EllipticCurvePublicKey), "Expected EC public key"

    pub_numbers = public_key.public_numbers()
    key_size_bytes = (public_key.key_size + 7) // 8
    x = base64.urlsafe_b64encode(
        pub_numbers.x.to_bytes(key_size_bytes, "big")
    ).rstrip(b"=").decode("ascii")
    y = base64.urlsafe_b64encode(
        pub_numbers.y.to_bytes(key_size_bytes, "big")
    ).rstrip(b"=").decode("ascii")
    pub_jwk: dict[str, Any] = {"kty": "EC", "crv": "P-256", "x": x, "y": y}

    return encrypt_payload_with_jwk(payload, pub_jwk)


def decrypt_payload_with_pem(
    jwe_token: str,
    private_key_pem: str,
) -> Any:
    """
    Decrypt a JWE using a PEM-encoded PKCS#8 private key.

    Args:
        jwe_token: JWE compact serialisation string.
        private_key_pem: PEM-encoded PKCS#8 private key string.

    Returns:
        Decrypted payload (parsed as JSON if possible).
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey), "Expected EC private key"

    priv_jwk, _ = _ec_key_to_jwk(private_key, use="enc")
    return decrypt_payload_with_jwk(jwe_token, priv_jwk)


def derive_public_key_pem(private_key_pem: str) -> str:
    """Derive a PEM-encoded public key from a PEM-encoded private key."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey), "Expected EC private key"
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


# ---------------------------------------------------------------------------
# JWS Signing (ES256)
# ---------------------------------------------------------------------------


@dataclass
class SignatureResult:
    """Result of a JWS / JWT signing operation."""

    token: str
    nonce: str
    issued_at: int


def sign_payload_with_jwk(
    payload: dict[str, Any],
    private_key_jwk: dict[str, Any],
    issuer: str,
    expires_in: int = 300,
) -> SignatureResult:
    """
    Sign a payload as a JWT using ES256 with a JWK private key.

    Args:
        payload: Claims to include in the JWT.
        private_key_jwk: JWK dict of the signing key (must include 'd' field).
        issuer: VASP domain as issuer claim.
        expires_in: Token lifetime in seconds (default: 300).

    Returns:
        :class:`SignatureResult` with ``token`` JWT string, ``nonce``, and ``issued_at``.
    """
    nonce = generate_nonce()
    issued_at = int(time.time())
    claims = {
        **payload,
        "nonce": nonce,
        "iss": issuer,
        "iat": issued_at,
        "exp": issued_at + expires_in,
        "jti": nonce,
    }
    token = jose_jwt.encode(claims, private_key_jwk, algorithm=ALGORITHMS.ES256)
    return SignatureResult(token=token, nonce=nonce, issued_at=issued_at)


def sign_payload_with_pem(
    payload: dict[str, Any],
    private_key_pem: str,
    issuer: str,
    expires_in: int = 300,
) -> SignatureResult:
    """
    Sign a payload as a JWT using ES256 with a PEM-encoded PKCS#8 private key.

    Args:
        payload: Claims to include in the JWT.
        private_key_pem: PEM-encoded PKCS#8 private key string.
        issuer: VASP domain as issuer claim.
        expires_in: Token lifetime in seconds (default: 300).

    Returns:
        :class:`SignatureResult` with ``token`` JWT string, ``nonce``, and ``issued_at``.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey), "Expected EC private key"
    priv_jwk, _ = _ec_key_to_jwk(private_key, use="sig")
    return sign_payload_with_jwk(payload, priv_jwk, issuer, expires_in)


# ---------------------------------------------------------------------------
# JWS Verification
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Result of a JWS / JWT verification operation."""

    valid: bool
    payload: dict[str, Any] | None = None
    error: str | None = None


def verify_payload_with_jwk(
    token: str,
    public_key_jwk: dict[str, Any],
    expected_issuer: str | None = None,
) -> VerificationResult:
    """
    Verify a JWS / JWT signed with ES256 using a JWK public key.

    Args:
        token: JWT / JWS compact serialisation.
        public_key_jwk: JWK dict of the verifying public key.
        expected_issuer: Optional issuer claim to validate.

    Returns:
        :class:`VerificationResult` with ``valid`` flag and decoded ``payload``.
    """
    try:
        options: dict[str, Any] = {}
        if expected_issuer is not None:
            options["issuer"] = expected_issuer
        decoded: dict[str, Any] = jose_jwt.decode(
            token,
            public_key_jwk,
            algorithms=[ALGORITHMS.ES256],
            **options,
        )
        return VerificationResult(valid=True, payload=decoded)
    except Exception as exc:
        logger.warning("JWS verification failed", error=str(exc))
        return VerificationResult(valid=False, error=str(exc))


def verify_payload_with_pem(
    token: str,
    public_key_pem: str,
    expected_issuer: str | None = None,
) -> VerificationResult:
    """
    Verify a JWT using a PEM-encoded SPKI public key.

    Args:
        token: JWT / JWS compact serialisation.
        public_key_pem: PEM-encoded SPKI public key string.
        expected_issuer: Optional issuer claim to validate.

    Returns:
        :class:`VerificationResult` with ``valid`` flag and decoded ``payload``.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
        assert isinstance(public_key, EllipticCurvePublicKey), "Expected EC public key"
        pub_numbers = public_key.public_numbers()
        key_size_bytes = (public_key.key_size + 7) // 8
        x = base64.urlsafe_b64encode(
            pub_numbers.x.to_bytes(key_size_bytes, "big")
        ).rstrip(b"=").decode("ascii")
        y = base64.urlsafe_b64encode(
            pub_numbers.y.to_bytes(key_size_bytes, "big")
        ).rstrip(b"=").decode("ascii")
        pub_jwk: dict[str, Any] = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": "sig"}
        return verify_payload_with_jwk(token, pub_jwk, expected_issuer)
    except Exception as exc:
        logger.warning("JWS verification failed", error=str(exc))
        return VerificationResult(valid=False, error=str(exc))


# ---------------------------------------------------------------------------
# Simple AES-256-GCM symmetric encryption (legacy / test helper)
# ---------------------------------------------------------------------------


def encrypt_payload(payload: object, key: str) -> str:
    """
    Encrypt a JSON object using AES-256-GCM.
    In production, key exchange should use ECDH-ES (JOSE JWE).

    Args:
        payload: The object to encrypt.
        key: 32-byte hex key (64 hex chars).

    Returns:
        Base64url-encoded ciphertext with prepended 12-byte IV and 16-byte auth tag.
    """
    key_bytes = bytes.fromhex(key)
    iv = os.urandom(12)
    plaintext = json.dumps(payload).encode("utf-8")
    aesgcm = AESGCM(key_bytes)
    # AESGCM.encrypt returns ciphertext + 16-byte tag appended
    encrypted = aesgcm.encrypt(iv, plaintext, None)
    # Layout: IV (12) | tag (16) | ciphertext
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]
    combined = iv + tag + ciphertext
    return base64.urlsafe_b64encode(combined).rstrip(b"=").decode("ascii")


def decrypt_payload(encoded: str, key: str) -> Any:
    """
    Decrypt an AES-256-GCM payload previously encrypted with :func:`encrypt_payload`.

    Args:
        encoded: Base64url-encoded ciphertext (IV + tag + ciphertext).
        key: 32-byte hex key (64 hex chars).

    Returns:
        The decrypted and JSON-parsed object.
    """
    padded = encoded + "=" * (-len(encoded) % 4)
    combined = base64.urlsafe_b64decode(padded)
    iv = combined[:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    key_bytes = bytes.fromhex(key)
    aesgcm = AESGCM(key_bytes)
    # AESGCM.decrypt expects ciphertext + tag concatenated
    plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
    return json.loads(plaintext.decode("utf-8"))
