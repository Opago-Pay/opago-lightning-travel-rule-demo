"""
Wallet Factory

Legacy mnemonic helpers for constructing SparkWalletManager instances in tests.

Port of src/wallet/wallet-factory.ts.

These helpers are retained for older tests and compatibility code paths.
The runtime Spark integration is configured via `SPARK_*` variables or a
runtime-generated mnemonic, not hosted account credentials.

Provides:
  - WalletFactory.create_from_mnemonic()  — restore an existing wallet
  - WalletFactory.create_new()            — create a brand-new wallet
  - WalletFactory.create_or_restore()     — auto-generate and persist if no mnemonic
  - WalletFactory.generate_mnemonic()     — generate a BIP-39 mnemonic

When no mnemonic is provided, a mnemonic is auto-generated and persisted to
a local file. This is legacy behavior and is not used by the live Spark
wallet flow.

Mnemonic persistence path defaults to ./data/.spark-mnemonic (mode 0o600).
"""

from __future__ import annotations

import os
from pathlib import Path

from opago_mica.utils.logger import logger
from opago_mica.wallet.spark_wallet import SparkWalletManager, WalletConfig

# ---------------------------------------------------------------------------
# Default mnemonic persistence path
# ---------------------------------------------------------------------------

_DEFAULT_MNEMONIC_PATH: Path = Path.home() / ".opago" / ".spark-mnemonic"

# ---------------------------------------------------------------------------
def _generate_mnemonic_bip39() -> str:
    """
    Generate a valid BIP-39 mnemonic phrase.

    The runtime dependency on ``mnemonic`` is intentional so legacy wallet
    factory flows never fall back to a non-standard seed representation.
    """
    try:
        from mnemonic import Mnemonic  # type: ignore[import-untyped]

        mnemo = Mnemonic("english")
        return mnemo.generate(strength=128)  # 12 words
    except ImportError:
        raise RuntimeError(
            "No BIP-39 library available; install the 'mnemonic' package to "
            "generate Spark wallet seed phrases."
        ) from None


# ---------------------------------------------------------------------------
# Mnemonic persistence helpers
# ---------------------------------------------------------------------------


def _read_persisted_mnemonic(file_path: Path) -> str | None:
    """
    Read a persisted mnemonic from disk.

    Args:
        file_path: Path to the mnemonic file.

    Returns:
        The mnemonic string, or None if not found.
    """
    try:
        if not file_path.exists():
            return None
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            return None
        logger.info("Loaded persisted mnemonic from disk", path=str(file_path))
        return content
    except Exception as exc:
        logger.warning(
            "Failed to read persisted mnemonic",
            path=str(file_path),
            error=str(exc),
        )
        return None


def _persist_mnemonic(file_path: Path, mnemonic: str) -> None:
    """
    Persist a mnemonic to disk. Creates parent directories if necessary.
    File is written with mode 0o600 (owner read/write only).

    Args:
        file_path: Destination path.
        mnemonic:  BIP-39 mnemonic string to persist.
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            file_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, mnemonic.encode("utf-8"))
        finally:
            os.close(fd)
        logger.info("Mnemonic persisted to disk", path=str(file_path))
    except Exception as exc:
        logger.error(
            "Failed to persist mnemonic to disk",
            path=str(file_path),
            error=str(exc),
        )
        raise OSError(
            f"Failed to persist mnemonic to {file_path}: {exc}. "
            "Ensure the directory is writable."
        ) from exc


# ---------------------------------------------------------------------------
# WalletFactory
# ---------------------------------------------------------------------------


class WalletFactory:
    """
    Static factory for SparkWalletManager instances.

    All factory methods call initialize() on the returned manager so callers
    receive a ready-to-use instance without a separate initialisation step.

    NOTE: The live wallet implementation now uses the real Spark SDK bridge.
    These helpers remain primarily for tests that mock `initialize()`.
    """

    @staticmethod
    async def create_or_restore(
        mnemonic: str | None,
        network: str,
        mnemonic_path: Path = _DEFAULT_MNEMONIC_PATH,
    ) -> dict:
        """
        Create or restore a wallet, with automatic mnemonic generation and
        persistence if no mnemonic is provided.

        Flow:
        1. If a mnemonic is provided, use it directly.
        2. If no mnemonic, check the persistence file for a previously stored one.
        3. If no persisted mnemonic, generate a new one and save it to disk.

        Args:
            mnemonic:      Optional BIP-39 mnemonic. If omitted, auto-generates.
            network:       Target network ('mainnet' | 'regtest').
            mnemonic_path: File path for mnemonic persistence.

        Returns:
            Dict with keys 'wallet' (SparkWalletManager), 'mnemonic' (str),
            and 'was_generated' (bool).
        """
        resolved_mnemonic: str
        was_generated = False

        if mnemonic is not None and mnemonic.strip():
            # Case 1: Mnemonic explicitly provided (e.g. via env var)
            resolved_mnemonic = mnemonic.strip()
            logger.info("Using provided mnemonic", network=network)
        else:
            # Case 2: Try to load from disk
            persisted = _read_persisted_mnemonic(mnemonic_path)
            if persisted is not None:
                resolved_mnemonic = persisted
                logger.info(
                    "Restored mnemonic from persistent storage",
                    network=network,
                    path=str(mnemonic_path),
                )
            else:
                # Case 3: Generate a new mnemonic and persist it
                logger.info(
                    "No mnemonic provided or found on disk; generating a new one",
                    network=network,
                )
                resolved_mnemonic = _generate_mnemonic_bip39()
                _persist_mnemonic(mnemonic_path, resolved_mnemonic)
                was_generated = True
                logger.info(
                    "New mnemonic generated and persisted",
                    network=network,
                    path=str(mnemonic_path),
                )

        config = WalletConfig(mnemonic=resolved_mnemonic, network=network)  # type: ignore[arg-type]
        manager = SparkWalletManager(config)
        await manager.initialize()

        logger.info("Wallet ready", network=network, was_generated=was_generated)
        return {
            "wallet": manager,
            "mnemonic": resolved_mnemonic,
            "was_generated": was_generated,
        }

    @staticmethod
    async def create_from_mnemonic(
        mnemonic: str,
        network: str,
    ) -> SparkWalletManager:
        """
        Restore an existing wallet from a BIP-39 mnemonic phrase and network.

        Args:
            mnemonic: 12 or 24-word BIP-39 mnemonic string.
            network:  Target network ('mainnet' | 'regtest').

        Returns:
            Initialised SparkWalletManager.
        """
        logger.info("WalletFactory.create_from_mnemonic", network=network)

        config = WalletConfig(mnemonic=mnemonic, network=network)  # type: ignore[arg-type]
        manager = SparkWalletManager(config)
        await manager.initialize()

        logger.info("Wallet created from mnemonic", network=network)
        return manager

    @staticmethod
    async def create_new(network: str) -> dict:
        """
        Create a brand-new wallet with a freshly generated mnemonic.

        The returned mnemonic is the **only** way to recover this wallet.
        Store it securely (e.g. encrypted in a KMS) before discarding.

        Args:
            network: Target network ('mainnet' | 'regtest').

        Returns:
            Dict with keys 'wallet' (SparkWalletManager) and 'mnemonic' (str).
        """
        logger.info("WalletFactory.create_new", network=network)

        mnemonic = _generate_mnemonic_bip39()
        config = WalletConfig(mnemonic=mnemonic, network=network)  # type: ignore[arg-type]
        manager = SparkWalletManager(config)
        await manager.initialize()

        logger.info("New wallet created", network=network)
        return {"wallet": manager, "mnemonic": mnemonic}

    @staticmethod
    async def generate_mnemonic() -> str:
        """Generate a BIP-39 mnemonic string asynchronously."""
        return _generate_mnemonic_bip39()

    @staticmethod
    def read_persisted_mnemonic(
        path: Path = _DEFAULT_MNEMONIC_PATH,
    ) -> str | None:
        """
        Read a persisted mnemonic from disk (for external callers).

        Args:
            path: Path to the mnemonic file.
        """
        return _read_persisted_mnemonic(path)

    @staticmethod
    def persist_mnemonic(
        mnemonic: str,
        path: Path = _DEFAULT_MNEMONIC_PATH,
    ) -> None:
        """
        Persist a mnemonic to disk (for external callers).

        Args:
            mnemonic: BIP-39 mnemonic string.
            path:     Destination path.
        """
        _persist_mnemonic(path, mnemonic)
