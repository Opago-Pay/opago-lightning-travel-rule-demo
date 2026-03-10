"""Spark SDK-backed wallet integration for Lightning operations."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, field_validator

from opago_mica.utils.logger import logger


class WalletNotInitializedError(Exception):
    """Raised when a wallet operation runs before `initialize()`."""

    def __init__(self, operation: str) -> None:
        super().__init__(f"Wallet not initialized. Call initialize() before {operation}.")


class PaymentFailedError(Exception):
    """Raised when a Lightning payment fails."""

    def __init__(
        self,
        message: str,
        invoice: str,
        inner_cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.invoice = invoice
        self.inner_cause = inner_cause


class InsufficientBalanceError(Exception):
    """Raised when the available balance cannot cover a payment."""

    def __init__(self, required_sats: int, available_sats: int) -> None:
        super().__init__(
            f"Insufficient balance: required {required_sats} sats, available {available_sats} sats."
        )
        self.required_sats = required_sats
        self.available_sats = available_sats


class WalletConfig(BaseModel):
    """Configuration for the Spark wallet bridge."""

    model_config = ConfigDict(populate_by_name=True)

    network: Literal["mainnet", "regtest", "signet", "local"] = "regtest"
    mnemonic: str | None = None
    master_key: str | None = None
    node_binary: str = "node"
    bridge_script_path: str | None = None

    @field_validator("network", mode="before")
    @classmethod
    def _normalize_network(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("network must be a string")
        normalized = value.strip().lower()
        if normalized not in {"mainnet", "regtest", "signet", "local"}:
            raise ValueError("network must be one of: mainnet, regtest, signet, local")
        return normalized


class PaymentResult(BaseModel):
    """Result of paying a Lightning invoice."""

    model_config = ConfigDict(populate_by_name=True)

    payment_id: str
    preimage: str
    amount_sats: int
    fee: int
    timestamp: datetime
    status: Literal["completed", "failed", "pending"]


class InvoiceResult(BaseModel):
    """Result of creating a Lightning invoice."""

    model_config = ConfigDict(populate_by_name=True)

    invoice: str
    payment_hash: str
    amount_sats: int
    expiry: int
    created_at: datetime


class WalletBalance(BaseModel):
    """Current spendable wallet balance."""

    model_config = ConfigDict(populate_by_name=True)

    balance_sats: int
    pending_sats: int


class TransactionRecord(BaseModel):
    """A single wallet transaction."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: Literal["send", "receive", "unknown"]
    amount_sats: int
    fee_sats: int
    status: Literal["completed", "pending", "failed"]
    created_at: datetime
    updated_at: datetime
    counterparty_pubkey: str | None = None
    spark_invoice: str | None = None


class RegtestFundingResult(BaseModel):
    """Result of funding a wallet through the local regtest faucet."""

    model_config = ConfigDict(populate_by_name=True)

    deposit_address: str
    tx_id: str
    amount_sats: int
    mined_blocks: int


class DepositUtxo(BaseModel):
    """A confirmed UTXO associated with a Spark deposit address."""

    model_config = ConfigDict(populate_by_name=True)

    txid: str
    vout: int


def _prefixed_env(prefix: str | None, name: str) -> str | None:
    """Read an environment variable with an optional prefix fallback."""
    if prefix:
        prefixed_name = f"{prefix}_{name}"
        if prefixed_name in os.environ:
            return os.environ[prefixed_name]
    return os.environ.get(name)


def _prefixed_only_env(prefix: str | None, name: str) -> str | None:
    """Read a role-scoped environment variable without global fallback."""
    if prefix:
        return os.environ.get(f"{prefix}_{name}")
    return os.environ.get(name)


def wallet_config_from_env(
    default_network: str = "regtest",
    prefix: str | None = None,
) -> WalletConfig:
    """Build wallet config from environment variables."""

    return WalletConfig(
        network=_prefixed_env(prefix, "SPARK_NETWORK") or default_network,
        mnemonic=_prefixed_only_env(prefix, "SPARK_MNEMONIC"),
        master_key=_prefixed_only_env(prefix, "SPARK_MASTER_KEY"),
        node_binary=_prefixed_env(prefix, "SPARK_NODE_BINARY") or "node",
        bridge_script_path=_prefixed_env(prefix, "SPARK_BRIDGE_SCRIPT"),
    )


class SparkWalletManager:
    """MiCA-aware wrapper around the real Spark SDK via a Node bridge."""

    def __init__(self, config: WalletConfig) -> None:
        self._config = config
        self._wallet: dict[str, Any] | None = None
        self._mnemonic_or_seed = config.mnemonic or config.master_key
        self._generated_mnemonic: str | None = None
        self._identity_public_key: str | None = None

    def _bridge_script_path(self) -> Path:
        if self._config.bridge_script_path:
            return Path(self._config.bridge_script_path)
        return (
            Path(__file__).resolve().parents[3]
            / "scripts"
            / "runtime"
            / "spark_wallet_bridge.mjs"
        )

    def _require_wallet(self) -> dict[str, Any]:
        if self._wallet is None:
            raise WalletNotInitializedError("wallet operation")
        return self._wallet

    def _bridge_payload(self, **extra: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {"network": self._config.network}
        if self._mnemonic_or_seed:
            payload["mnemonicOrSeed"] = self._mnemonic_or_seed
        payload.update(extra)
        return payload

    async def _run_bridge(self, operation: str, **payload: Any) -> Any:
        process = await asyncio.create_subprocess_exec(
            self._config.node_binary,
            str(self._bridge_script_path()),
            operation,
            json.dumps(payload),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        stderr_text = stderr.decode("utf-8", errors="replace").strip()

        if process.returncode != 0:
            message = stderr_text or stdout_text or "Spark bridge command failed."
            raise RuntimeError(message)

        try:
            parsed = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Spark bridge returned invalid JSON for {operation}: {stdout_text}"
            ) from exc

        return parsed

    def _parse_timestamp(self, value: str | None) -> datetime:
        if value:
            return datetime.fromisoformat(value)
        return datetime.now(UTC)

    def _extract_amount_sats(self, amount: Any | None) -> int:
        if amount is None:
            return 0
        if isinstance(amount, (int, float)):
            return int(amount)
        if isinstance(amount, str):
            return int(amount)
        if isinstance(amount, dict):
            if "totalValue" in amount:
                return int(amount["totalValue"])
            original_value = amount.get("originalValue")
            original_unit = str(amount.get("originalUnit", "")).upper()
            if original_value is not None:
                value = int(original_value)
                if original_unit == "MILLISATOSHI":
                    return value // 1000
                return value
        return 0

    def _map_status(self, status: Any) -> Literal["completed", "pending", "failed"]:
        status_name = str(status or "").upper()
        if any(token in status_name for token in ("COMPLETED", "SUCCESS", "CLAIMED")):
            return "completed"
        if any(
            token in status_name
            for token in ("CREATED", "PENDING", "INITIATED", "NOT_STARTED")
        ):
            return "pending"
        return "failed"

    def _map_transaction_type(
        self,
        transfer: dict[str, Any],
    ) -> Literal["send", "receive", "unknown"]:
        direction = str(transfer.get("transferDirection", "")).upper()
        if direction == "OUTGOING":
            return "send"
        if direction == "INCOMING":
            return "receive"
        return "unknown"

    def _decode_signature(self, signature: str) -> bytes:
        stripped = signature.strip()
        if len(stripped) % 2 == 0:
            try:
                return bytes.fromhex(stripped)
            except ValueError:
                pass
        return base64.b64decode(stripped, validate=True)

    def _load_public_key(self, public_key: str) -> ec.EllipticCurvePublicKey:
        stripped = public_key.strip()
        if stripped.startswith("-----BEGIN PUBLIC KEY-----"):
            loaded = serialization.load_pem_public_key(stripped.encode("ascii"))
            if not isinstance(loaded, ec.EllipticCurvePublicKey):
                raise ValueError("Expected an EC public key.")
            return loaded

        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            bytes.fromhex(stripped),
        )

    async def initialize(self) -> None:
        """Initialize a real Spark wallet through the Node bridge."""

        logger.info("Initializing Spark wallet", network=self._config.network)
        result = await self._run_bridge("initialize", **self._bridge_payload())

        mnemonic = result.get("mnemonic")
        if mnemonic:
            self._generated_mnemonic = str(mnemonic)
            self._mnemonic_or_seed = str(mnemonic)

        self._identity_public_key = result.get("identityPublicKey")
        self._wallet = {
            "network": self._config.network,
            "spark_address": result.get("sparkAddress"),
        }

        logger.info("Spark wallet initialized", network=self._config.network)

    async def close(self) -> None:
        """Release local bridge state."""

        self._wallet = None
        self._identity_public_key = None

    async def get_balance(self) -> WalletBalance:
        """Return the current Spark balance."""

        self._require_wallet()
        result = await self._run_bridge("get-balance", **self._bridge_payload())
        return WalletBalance(balance_sats=int(result["balanceSats"]), pending_sats=0)

    async def create_invoice(
        self,
        *,
        amount_sats: int,
        memo: str | None = None,
        expiry_secs: int | None = None,
    ) -> InvoiceResult:
        """Create a BOLT-11 invoice through Spark."""

        self._require_wallet()
        request = await self._run_bridge(
            "create-lightning-invoice",
            **self._bridge_payload(
                params={
                    "amountSats": amount_sats,
                    **({"memo": memo} if memo is not None else {}),
                    **(
                        {"expirySeconds": expiry_secs}
                        if expiry_secs is not None
                        else {}
                    ),
                }
            ),
        )
        invoice = request["invoice"]
        created_at = self._parse_timestamp(
            invoice.get("createdAt") or request.get("createdAt")
        )
        expires_at = self._parse_timestamp(invoice.get("expiresAt"))
        expiry = (
            max(0, int((expires_at - created_at).total_seconds()))
            if invoice.get("expiresAt")
            else (expiry_secs or 30 * 24 * 60 * 60)
        )

        return InvoiceResult(
            invoice=str(invoice["encodedInvoice"]),
            payment_hash=str(invoice["paymentHash"]),
            amount_sats=self._extract_amount_sats(invoice.get("amount")) or amount_sats,
            expiry=expiry,
            created_at=created_at,
        )

    async def pay_invoice(
        self,
        invoice: str,
        max_fee_sats: int = 1_000,
        amount_sats: int | None = None,
    ) -> PaymentResult:
        """Pay a BOLT-11 invoice through Spark."""

        self._require_wallet()
        balance = await self.get_balance()
        if amount_sats is not None and amount_sats + max_fee_sats > balance.balance_sats:
            raise InsufficientBalanceError(
                required_sats=amount_sats + max_fee_sats,
                available_sats=balance.balance_sats,
            )

        try:
            result = await self._run_bridge(
                "pay-lightning-invoice",
                **self._bridge_payload(
                    params={
                        "invoice": invoice,
                        "maxFeeSats": max_fee_sats,
                        **(
                            {"amountSatsToSend": amount_sats}
                            if amount_sats is not None
                            else {}
                        ),
                    }
                ),
            )
        except Exception as exc:  # noqa: BLE001
            raise PaymentFailedError("Spark invoice payment failed.", invoice, exc) from exc

        return PaymentResult(
            payment_id=str(result["id"]),
            preimage=str(result.get("paymentPreimage") or ""),
            amount_sats=(
                self._extract_amount_sats(result.get("amount"))
                or self._extract_amount_sats(result.get("invoice", {}).get("amount"))
                or self._extract_amount_sats(result.get("totalValue"))
                or amount_sats
                or 0
            ),
            fee=self._extract_amount_sats(result.get("fees")),
            timestamp=self._parse_timestamp(
                result.get("createdAt") or result.get("updatedAt")
            ),
            status=self._map_status(result.get("status")),
        )

    async def create_spark_invoice(
        self,
        *,
        amount_sats: int,
        memo: str | None = None,
    ) -> InvoiceResult:
        """Create a Spark sats invoice through the bridge."""

        self._require_wallet()
        result = await self._run_bridge(
            "create-sats-invoice",
            **self._bridge_payload(
                params={
                    "amount": amount_sats,
                    **({"memo": memo} if memo is not None else {}),
                }
            ),
        )
        created_at = self._parse_timestamp(result.get("createdAt"))

        return InvoiceResult(
            invoice=str(result["invoice"]),
            payment_hash=str(result.get("paymentHash") or result["invoice"]),
            amount_sats=amount_sats,
            expiry=int(result.get("expirySeconds") or 30 * 24 * 60 * 60),
            created_at=created_at,
        )

    async def pay_spark_invoice(
        self,
        invoice: str,
        amount_sats: int = 0,
    ) -> PaymentResult:
        """Fulfill a Spark invoice through the bridge."""

        self._require_wallet()
        result = await self._run_bridge(
            "fulfill-spark-invoice",
            **self._bridge_payload(
                params={
                    "invoice": invoice,
                    **({"amountSats": amount_sats} if amount_sats > 0 else {}),
                }
            ),
        )

        return PaymentResult(
            payment_id=str(result["id"]),
            preimage=str(result.get("paymentPreimage") or ""),
            amount_sats=self._extract_amount_sats(result.get("totalValue")) or amount_sats,
            fee=self._extract_amount_sats(result.get("fees")),
            timestamp=self._parse_timestamp(
                result.get("createdTime") or result.get("updatedTime")
            ),
            status=self._map_status(result.get("status")),
        )

    async def get_transaction_history(self) -> list[TransactionRecord]:
        """Fetch recent Spark transfer history."""

        self._require_wallet()
        result = await self._run_bridge(
            "get-transfers",
            **self._bridge_payload(limit=100, offset=0),
        )

        records: list[TransactionRecord] = []
        for transfer in result.get("transfers", []):
            direction = str(transfer.get("transferDirection", "")).upper()
            counterparty = (
                transfer.get("receiverIdentityPublicKey")
                if direction == "OUTGOING"
                else transfer.get("senderIdentityPublicKey")
            )
            records.append(
                TransactionRecord(
                    id=str(transfer["id"]),
                    type=self._map_transaction_type(transfer),
                    amount_sats=self._extract_amount_sats(transfer.get("totalValue")),
                    fee_sats=self._extract_amount_sats(transfer.get("fees")),
                    status=self._map_status(transfer.get("status")),
                    created_at=self._parse_timestamp(transfer.get("createdTime")),
                    updated_at=self._parse_timestamp(transfer.get("updatedTime")),
                    counterparty_pubkey=(
                        str(counterparty) if counterparty is not None else None
                    ),
                    spark_invoice=transfer.get("sparkInvoice"),
                )
            )

        return records

    async def sign_message(self, message: str) -> str:
        """Sign a message with Spark's identity key."""

        self._require_wallet()
        result = await self._run_bridge(
            "sign-message",
            **self._bridge_payload(message=message),
        )
        return str(result["signature"])

    async def verify_message(
        self,
        message: str,
        signature: str,
        public_key: str,
    ) -> bool:
        """Verify a DER or base64 signature against a Spark identity public key."""

        try:
            signature_bytes = self._decode_signature(signature)
            key = self._load_public_key(public_key)
            key.verify(
                signature_bytes,
                message.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, TypeError, ValueError, base64.binascii.Error):
            return False

        return True

    async def get_public_key(self) -> str:
        """Return Spark's compressed identity public key as hex."""

        self._require_wallet()
        if self._identity_public_key is None:
            result = await self._run_bridge(
                "get-identity-public-key",
                **self._bridge_payload(),
            )
            self._identity_public_key = str(result["identityPublicKey"])
        return self._identity_public_key

    def get_mnemonic_or_seed(self) -> str | None:
        """Return the mnemonic or seed currently backing the wallet."""
        return self._mnemonic_or_seed

    def get_spark_address(self) -> str | None:
        """Return the wallet's Spark address when initialized."""
        if self._wallet is None:
            return None
        spark_address = self._wallet.get("spark_address")
        return str(spark_address) if spark_address is not None else None

    async def get_static_deposit_address(self) -> str:
        """Return the wallet's reusable regtest deposit address."""

        self._require_wallet()
        result = await self._run_bridge(
            "get-static-deposit-address",
            **self._bridge_payload(),
        )
        return str(result["depositAddress"])

    async def fund_regtest_from_faucet(
        self,
        *,
        amount_sats: int,
        mine_blocks: int = 6,
        poll_timeout_secs: float = 30.0,
        poll_interval_secs: float = 1.0,
    ) -> RegtestFundingResult:
        """Fund this wallet on regtest using the Spark SDK's local faucet helper."""

        self._require_wallet()
        if self._config.network not in {"regtest", "local"}:
            raise ValueError(
                "Regtest faucet funding is only supported on the regtest/local networks."
            )

        result = await self._run_bridge(
            "fund-regtest-wallet",
            **self._bridge_payload(
                amountSats=amount_sats,
                mineBlocks=mine_blocks,
            ),
        )
        funding = RegtestFundingResult(
            deposit_address=str(result["depositAddress"]),
            tx_id=str(result["txId"]),
            amount_sats=int(result["amountSats"]),
            mined_blocks=int(result["minedBlocks"]),
        )

        # Poll until the funded wallet balance reflects the deposit.
        deadline = time.monotonic() + poll_timeout_secs
        while time.monotonic() < deadline:
            balance = await self.get_balance()
            if balance.balance_sats >= amount_sats:
                return funding
            await asyncio.sleep(poll_interval_secs)

        raise RuntimeError(
            "Timed out waiting for regtest faucet deposit to appear in wallet balance."
        )

    async def get_utxos_for_deposit_address(
        self,
        deposit_address: str,
        *,
        limit: int = 100,
        offset: int = 0,
        exclude_claimed: bool = True,
    ) -> list[DepositUtxo]:
        """Return confirmed UTXOs for a Spark static deposit address."""

        self._require_wallet()
        result = await self._run_bridge(
            "get-utxos-for-deposit-address",
            **self._bridge_payload(
                depositAddress=deposit_address,
                limit=limit,
                offset=offset,
                excludeClaimed=exclude_claimed,
            ),
        )
        return [DepositUtxo.model_validate(item) for item in result.get("utxos", [])]

    async def claim_static_deposit_with_max_fee(
        self,
        *,
        transaction_id: str,
        max_fee_sats: int,
        output_index: int | None = None,
    ) -> dict[str, Any]:
        """Claim a static deposit into the wallet with a maximum allowed fee."""

        self._require_wallet()
        result = await self._run_bridge(
            "claim-static-deposit-with-max-fee",
            **self._bridge_payload(
                transactionId=transaction_id,
                maxFee=max_fee_sats,
                **(
                    {"outputIndex": output_index}
                    if output_index is not None
                    else {}
                ),
            ),
        )
        if not isinstance(result, dict):
            raise RuntimeError("Spark bridge returned an invalid static deposit claim response.")
        return result

    async def health_check(self) -> bool:
        """Return True when the Spark bridge can fetch a balance."""

        if self._wallet is None:
            return False

        try:
            await self.get_balance()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Wallet health check failed", error=str(exc))
            return False
        return True
