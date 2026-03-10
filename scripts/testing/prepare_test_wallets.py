#!/usr/bin/env python3
"""Prepare local Spark regtest wallets for sender and receiver VASPs."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from opago_mica.wallet.spark_wallet import SparkWalletManager, WalletConfig

DEFAULT_STATE_DIR = ".demo-state"
DEFAULT_STATE_FILE = "spark-wallets.json"
DEFAULT_TARGET_BALANCE_SATS = 50_000
DEFAULT_MAX_CLAIM_FEE_SATS = 5_000
DEFAULT_FAUCET_URL = "https://app.lightspark.com/regtest-faucet"
PREPARATION_NETWORK = "regtest"


@dataclass
class WalletPreparationResult:
    mnemonic: str
    balance_sats: int
    spark_address: str | None
    was_created: bool
    deposit_address: str | None = None
    claimed_tx_ids: list[str] = field(default_factory=list)
    faucet_url: str | None = None
    needs_faucet_funding: bool = False


def _log(message: str) -> None:
    print(message, file=sys.stderr)


def _load_state(state_path: Path) -> dict[str, str]:
    if not state_path.exists():
        return {}
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected wallet state format in {state_path}")
    return {str(key): str(value) for key, value in payload.items()}


def _save_state(state_path: Path, state: dict[str, str]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    state_path.chmod(0o600)


async def generate_wallet_mnemonic(node_binary: str, bridge_script_path: str | None) -> str:
    """Generate a Spark mnemonic by initializing a fresh regtest wallet."""
    wallet = SparkWalletManager(
        WalletConfig(
            network=PREPARATION_NETWORK,
            node_binary=node_binary,
            bridge_script_path=bridge_script_path,
        )
    )
    await wallet.initialize()
    try:
        mnemonic = wallet.get_mnemonic_or_seed()
        if not mnemonic:
            raise RuntimeError("Spark SDK did not return a mnemonic for the generated wallet.")
        return mnemonic
    finally:
        await wallet.close()


async def prepare_wallet(
    *,
    mnemonic: str,
    node_binary: str,
    bridge_script_path: str | None,
    target_balance_sats: int = 0,
    max_claim_fee_sats: int = DEFAULT_MAX_CLAIM_FEE_SATS,
) -> WalletPreparationResult:
    """Initialize a wallet and claim any hosted-regtest faucet deposits."""
    wallet = SparkWalletManager(
        WalletConfig(
            network=PREPARATION_NETWORK,
            mnemonic=mnemonic,
            node_binary=node_binary,
            bridge_script_path=bridge_script_path,
        )
    )
    await wallet.initialize()
    try:
        balance = await wallet.get_balance()
        deposit_address = await wallet.get_static_deposit_address()
        claimed_tx_ids: list[str] = []

        if target_balance_sats > 0:
            utxos = await wallet.get_utxos_for_deposit_address(
                deposit_address,
                exclude_claimed=True,
            )
            seen_txids: set[str] = set()
            for utxo in utxos:
                if utxo.txid in seen_txids:
                    continue
                seen_txids.add(utxo.txid)
                _log(f"Claiming hosted regtest deposit tx {utxo.txid} for {deposit_address}")
                await wallet.claim_static_deposit_with_max_fee(
                    transaction_id=utxo.txid,
                    max_fee_sats=max_claim_fee_sats,
                    output_index=utxo.vout,
                )
                claimed_tx_ids.append(utxo.txid)

            if claimed_tx_ids:
                balance = await wallet.get_balance()

        needs_faucet_funding = balance.balance_sats < target_balance_sats
        if needs_faucet_funding:
            _log(
                "Sender wallet still needs hosted regtest faucet funding. "
                f"Use {DEFAULT_FAUCET_URL} and fund {deposit_address} or "
                f"{wallet.get_spark_address()} in <= 50,000 sat increments, then rerun."
            )

        return WalletPreparationResult(
            mnemonic=mnemonic,
            balance_sats=balance.balance_sats,
            spark_address=wallet.get_spark_address(),
            was_created=False,
            deposit_address=deposit_address,
            claimed_tx_ids=claimed_tx_ids,
            faucet_url=DEFAULT_FAUCET_URL if needs_faucet_funding else None,
            needs_faucet_funding=needs_faucet_funding,
        )
    finally:
        await wallet.close()


async def ensure_mnemonic(
    *,
    env_var: str,
    state: dict[str, str],
    state_key: str,
    state_path: Path,
    node_binary: str,
    bridge_script_path: str | None,
) -> tuple[str, bool]:
    """Resolve a mnemonic from the environment or local state."""
    existing = os.environ.get(env_var)
    if existing:
        _log(f"Using {env_var} from environment.")
        return existing, False

    stored = state.get(state_key)
    if stored:
        _log(f"Loaded {env_var} from {state_path}.")
        return stored, False

    _log(f"Generating new mnemonic for {env_var} and storing it at {state_path}.")
    mnemonic = await generate_wallet_mnemonic(node_binary, bridge_script_path)
    state[state_key] = mnemonic
    _save_state(state_path, state)
    return mnemonic, True


async def main_async() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        choices=["shell", "json"],
        default="shell",
        help="Output format for prepared wallet values.",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("TRAVEL_RULE_STATE_DIR", DEFAULT_STATE_DIR),
    )
    parser.add_argument(
        "--sender-state-key",
        default="senderSparkMnemonic",
    )
    parser.add_argument(
        "--receiver-state-key",
        default="receiverSparkMnemonic",
    )
    parser.add_argument(
        "--sender-target-balance-sats",
        type=int,
        default=int(
            os.environ.get("SENDER_TARGET_BALANCE_SATS", str(DEFAULT_TARGET_BALANCE_SATS))
        ),
    )
    parser.add_argument(
        "--node-binary",
        default=os.environ.get("SPARK_NODE_BINARY", "node"),
    )
    parser.add_argument(
        "--bridge-script-path",
        default=os.environ.get("SPARK_BRIDGE_SCRIPT"),
    )
    parser.add_argument(
        "--static-deposit-max-fee-sats",
        type=int,
        default=int(
            os.environ.get("SPARK_STATIC_DEPOSIT_MAX_FEE_SATS", str(DEFAULT_MAX_CLAIM_FEE_SATS))
        ),
    )
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    state_path = state_dir / DEFAULT_STATE_FILE
    state = _load_state(state_path)

    sender_mnemonic, sender_created = await ensure_mnemonic(
        env_var="SENDER_SPARK_MNEMONIC",
        state=state,
        state_key=args.sender_state_key,
        state_path=state_path,
        node_binary=args.node_binary,
        bridge_script_path=args.bridge_script_path,
    )
    receiver_mnemonic, receiver_created = await ensure_mnemonic(
        env_var="RECEIVER_SPARK_MNEMONIC",
        state=state,
        state_key=args.receiver_state_key,
        state_path=state_path,
        node_binary=args.node_binary,
        bridge_script_path=args.bridge_script_path,
    )

    sender_result = await prepare_wallet(
        mnemonic=sender_mnemonic,
        node_binary=args.node_binary,
        bridge_script_path=args.bridge_script_path,
        target_balance_sats=args.sender_target_balance_sats,
        max_claim_fee_sats=args.static_deposit_max_fee_sats,
    )
    sender_result.was_created = sender_created

    receiver_result = await prepare_wallet(
        mnemonic=receiver_mnemonic,
        node_binary=args.node_binary,
        bridge_script_path=args.bridge_script_path,
        target_balance_sats=0,
        max_claim_fee_sats=args.static_deposit_max_fee_sats,
    )
    receiver_result.was_created = receiver_created

    payload = {
        "SENDER_SPARK_MNEMONIC": sender_result.mnemonic,
        "RECEIVER_SPARK_MNEMONIC": receiver_result.mnemonic,
        "sender": asdict(sender_result),
        "receiver": asdict(receiver_result),
    }

    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"export SENDER_SPARK_MNEMONIC={shlex.quote(sender_result.mnemonic)}")
    print(f"export RECEIVER_SPARK_MNEMONIC={shlex.quote(receiver_result.mnemonic)}")
    print(f"export SENDER_SPARK_ADDRESS={shlex.quote(sender_result.spark_address or '')}")
    print(f"export RECEIVER_SPARK_ADDRESS={shlex.quote(receiver_result.spark_address or '')}")
    print(
        "export SENDER_SPARK_DEPOSIT_ADDRESS="
        f"{shlex.quote(sender_result.deposit_address or '')}"
    )
    print(
        "export RECEIVER_SPARK_DEPOSIT_ADDRESS="
        f"{shlex.quote(receiver_result.deposit_address or '')}"
    )
    print(f"export SENDER_TARGET_BALANCE_SATS={shlex.quote(str(args.sender_target_balance_sats))}")
    return 0


def main() -> int:
    try:
        return asyncio.run(main_async())
    except Exception as exc:  # noqa: BLE001
        _log(f"Wallet preparation failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
