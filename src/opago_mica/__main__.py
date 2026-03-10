"""
opago-MiCA-reference – Python Entry Point

MiCA-compliant Lightning Network VASP reference implementation using:
- Spark SDK for Lightning payments
- UMA (Universal Money Address) protocol for address resolution
- IVMS101 for travel rule data exchange (TRP / TRISA / TRUST / GTR / direct)
- eIDAS 2.0 Digital Identity Wallet for self-custodial identity proofs

Regulatory basis:
- EU Markets in Crypto-Assets Regulation (MiCA) – Regulation (EU) 2023/1114
- EU Transfer of Funds Regulation (TFR) – Regulation (EU) 2023/1113
- FATF Recommendation 16 (Travel Rule)
- eIDAS 2.0 – Regulation (EU) 2024/1183

Architecture Overview::

    Sender (port 3001)              Receiver (port 3002)
    ┌────────────────┐              ┌────────────────┐
    │  SendingVASP   │──UMA pay──▶  │ ReceivingVASP  │
    │                │◀─invoice──   │                │
    │  SparkWallet   │──Lightning─▶ │  SparkWallet   │
    │  Manager       │              │  Manager       │
    │                │              │                │
    │  UMAMiCA       │──IVMS101──▶  │  UMAMiCA       │
    │  Protocol      │  (encrypted) │  Protocol      │
    │                │              │                │
    │  EIDAS         │──VP Token──▶ │  Compliance    │
    │  WalletBridge  │              │  Engine        │
    └────────────────┘              └────────────────┘

Quick start::

    # Start both VASPs with demo payments
    python -m opago_mica

    # Or start individually
    python -m opago_mica sender
    python -m opago_mica receiver
"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import suppress

import uvicorn  # type: ignore[import-untyped]

from opago_mica.compliance.travel_rule_manager import TravelRuleManager
from opago_mica.core.compliance_engine import ComplianceEngine, ComplianceEngineConfig
from opago_mica.core.uma_mica import UMAMiCAProtocol
from opago_mica.eidas.eidas_wallet import EIDASWalletBridge
from opago_mica.receiving.receiver_server import (
    ReceiverServerConfig,
    create_receiver_server,
    start_receiver_server,
)
from opago_mica.sending.sender import SendingVASP, SendPaymentParams, SendPaymentResult
from opago_mica.sending.sender_server import (
    SenderServerConfig,
    create_sender_server,
    start_sender_server,
)
from opago_mica.types.uma_extended import UMAMiCAConfig
from opago_mica.utils.crypto import generate_key_pair
from opago_mica.utils.logger import create_logger
from opago_mica.wallet.spark_wallet import SparkWalletManager, wallet_config_from_env

logger = create_logger("main")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENDER_PORT: int = 3001
RECEIVER_PORT: int = 3002

# Demo signing/encryption keys (production: use env vars or HSM)
DEMO_SIGNING_KEY: str = generate_key_pair(use="sig").private_key_pem
DEMO_ENCRYPTION_KEY: str = generate_key_pair(use="enc").private_key_pem


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log_result(label: str, result: SendPaymentResult) -> None:
    """Log the outcome of a demo payment in a human-readable form.

    Args:
        label: Short label such as 'DEMO 1'.
        result: Payment result to log.
    """
    if result.success:
        logger.info(
            f"{label} ✓ Payment succeeded",
            payment_id=result.payment_id,
            travel_rule=result.travel_rule_transfer_id or "(not required)",
            eidas_signed=result.eidas_signed,
            compliance=result.compliance_status,
        )
    else:
        logger.warning(
            f"{label} ✗ Payment failed",
            payment_id=result.payment_id,
            compliance=result.compliance_status,
            error=result.error,
        )


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------


async def start_demo() -> None:
    """Run a full end-to-end demo of the MiCA-compliant payment flow.

    Starts both a sending and receiving VASP, then executes three simulated
    payments demonstrating:

    1. Small payment below the EUR 1,000 travel rule threshold
    2. Large payment above the threshold (travel rule required)
    3. Large payment with eIDAS qualified electronic signature

    Example::

        import asyncio
        from opago_mica.__main__ import start_demo
        asyncio.run(start_demo())
    """
    logger.info("═══════════════════════════════════════════════════════")
    logger.info(" opago MiCA Reference Implementation — Demo Start      ")
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("Regulatory basis: MiCA Art. 83 / EU TFR 2023/1113 / FATF R.16")
    logger.info("")

    sender_domain = f"localhost:{SENDER_PORT}"
    receiver_domain = f"localhost:{RECEIVER_PORT}"
    travel_rule_threshold_eur = float(
        os.environ.get("TRAVEL_RULE_THRESHOLD_EUR", "1000")
    )

    # ---------------------------------------------------------------------------
    # 1. Start the receiving VASP server
    # ---------------------------------------------------------------------------
    logger.info("Starting Receiving VASP server…")

    receiver_cfg = ReceiverServerConfig(
        host="0.0.0.0",
        port=RECEIVER_PORT,
        domain=receiver_domain,
        vasp_name="Demo Receiver VASP (DE)",
        eidas_enabled=True,
        mica_license_number="EU-MICA-2024-DEMO-RECV-001",
        uma_config={
            "signingKey": DEMO_SIGNING_KEY,
            "encryptionKey": DEMO_ENCRYPTION_KEY,
            "eidasEnabled": True,
            "travelRuleThresholdEur": travel_rule_threshold_eur,
        },
    )
    receiver_app = create_receiver_server(receiver_cfg)

    receiver_uvicorn_config = uvicorn.Config(
        receiver_app,
        host="0.0.0.0",
        port=RECEIVER_PORT,
        log_level="warning",
    )
    receiver_server = uvicorn.Server(receiver_uvicorn_config)
    receiver_task = asyncio.create_task(receiver_server.serve())

    # Give the server a moment to bind the port
    await asyncio.sleep(0.5)
    logger.info(
        "Receiving VASP listening",
        port=RECEIVER_PORT,
        domain=receiver_domain,
    )

    # ---------------------------------------------------------------------------
    # 2. Start the sending VASP server
    # ---------------------------------------------------------------------------
    logger.info("Starting Sending VASP server…")

    sender_cfg = SenderServerConfig(
        host="0.0.0.0",
        port=SENDER_PORT,
        domain=sender_domain,
        vasp_name="Demo Sender VASP (DE)",
        mica_license_number="EU-MICA-2024-DEMO-SEND-001",
        uma_config={
            "signingKey": DEMO_SIGNING_KEY,
            "encryptionKey": DEMO_ENCRYPTION_KEY,
            "eidasEnabled": True,
            "travelRuleThresholdEur": travel_rule_threshold_eur,
        },
    )
    sender_app = create_sender_server(sender_cfg)

    sender_uvicorn_config = uvicorn.Config(
        sender_app,
        host="0.0.0.0",
        port=SENDER_PORT,
        log_level="warning",
    )
    sender_server = uvicorn.Server(sender_uvicorn_config)
    sender_task = asyncio.create_task(sender_server.serve())

    await asyncio.sleep(0.5)
    logger.info(
        "Sending VASP listening",
        port=SENDER_PORT,
        domain=sender_domain,
    )

    await asyncio.sleep(0.3)

    # ---------------------------------------------------------------------------
    # 3. Build demo components for direct payment simulation
    # ---------------------------------------------------------------------------
    wallet_cfg = wallet_config_from_env(default_network="regtest", prefix="SENDER")
    wallet = SparkWalletManager(wallet_cfg)
    await wallet.initialize()

    uma_protocol = UMAMiCAProtocol(
        UMAMiCAConfig(
            vasp_domain=sender_domain,
            signing_key=DEMO_SIGNING_KEY,
            encryption_key=DEMO_ENCRYPTION_KEY,
            travel_rule_threshold_eur=travel_rule_threshold_eur,
            eidas_enabled=True,
        )
    )

    travel_rule = TravelRuleManager()

    eidas_bridge = EIDASWalletBridge(
        enabled=True,
        issuer_url=f"https://issuer.{sender_domain}",
    )

    compliance = ComplianceEngine(
        ComplianceEngineConfig(
            vasp_domain=sender_domain,
            travel_rule_threshold_eur=travel_rule_threshold_eur,
        )
    )

    sending_vasp = SendingVASP(
        wallet=wallet,
        uma_protocol=uma_protocol,
        travel_rule=travel_rule,
        eidas_bridge=eidas_bridge,
        compliance=compliance,
        vasp_domain=sender_domain,
        vasp_name="Demo Sender VASP (DE)",
    )

    # ---------------------------------------------------------------------------
    # 4. Execute demo payments
    # ---------------------------------------------------------------------------
    logger.info("")
    logger.info("─── Demo Payment Flow ──────────────────────────────────────")
    logger.info("")

    # Demo 1: Small payment (below EUR 1,000 threshold → no travel rule)
    logger.info("DEMO 1: Small payment (below EUR ~1,000 travel rule threshold)")
    demo1 = await sending_vasp.send_payment(
        SendPaymentParams(
            receiver_uma=f"$alice@{receiver_domain}",
            amount_sats=2_100,
            sender_name="Charlie Demo",
            sender_account=f"$charlie@{sender_domain}",
            memo="Coffee ☕",
            use_eidas=False,
        )
    )
    log_result("DEMO 1", demo1)
    await asyncio.sleep(0.2)

    # Demo 2: Large payment (above threshold → travel rule required)
    logger.info("")
    logger.info("DEMO 2: Large payment (above threshold → travel rule required)")
    demo2 = await sending_vasp.send_payment(
        SendPaymentParams(
            receiver_uma=f"$alice@{receiver_domain}",
            amount_sats=50_000,
            sender_name="Dave Mustermann",
            sender_account=f"$dave@{sender_domain}",
            memo="Invoice #2024-001",
            use_eidas=False,
        )
    )
    log_result("DEMO 2", demo2)
    await asyncio.sleep(0.2)

    # Demo 3: Large payment + eIDAS qualified signature
    logger.info("")
    logger.info("DEMO 3: Large payment with eIDAS wallet qualified signature")
    logger.info("         User approves identity sharing from EU Digital Identity Wallet")
    demo3 = await sending_vasp.send_payment(
        SendPaymentParams(
            receiver_uma=f"$alice@{receiver_domain}",
            amount_sats=100_000,
            sender_name="Alice Musterfrau",
            sender_account=f"$alice@{sender_domain}",
            memo="Rent payment",
            use_eidas=True,  # enables eIDAS wallet consent flow
        )
    )
    log_result("DEMO 3", demo3)

    # ---------------------------------------------------------------------------
    # 5. Summary
    # ---------------------------------------------------------------------------
    logger.info("")
    logger.info("─── Demo Complete ────────────────────────────────────────")
    logger.info("")
    logger.info("Both servers are still running. Available endpoints:")
    logger.info("")
    logger.info(f"Sending VASP  → http://localhost:{SENDER_PORT}")
    logger.info("  POST /api/send                     Initiate a payment")
    logger.info("  GET  /api/balance                  Wallet balance")
    logger.info("  GET  /api/audit                    Compliance audit log")
    logger.info("  GET  /api/health                   Health check")
    logger.info("  GET  /.well-known/uma-configuration UMA configuration")
    logger.info("")
    logger.info(f"Receiving VASP → http://localhost:{RECEIVER_PORT}")
    logger.info("  GET  /.well-known/lnurlp/alice     LNURL-pay discovery")
    logger.info("  POST /api/uma/payreq/alice         Handle pay request")
    logger.info("  GET  /api/compliance/requirements  Compliance requirements")
    logger.info("  POST /api/travel-rule/trp          TRP protocol endpoint")
    logger.info("  POST /api/travel-rule/trisa        TRISA protocol endpoint")
    logger.info("")
    logger.info("Press Ctrl+C to stop.")

    # Keep both servers running until interrupted
    with suppress(asyncio.CancelledError):
        await asyncio.gather(receiver_task, sender_task)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point for ``python -m opago_mica`` and the installed script."""
    command = sys.argv[1] if len(sys.argv) > 1 else "demo"

    if command == "sender":
        asyncio.run(start_sender_server())
    elif command == "receiver":
        asyncio.run(start_receiver_server())
    elif command in ("demo", ""):
        try:
            asyncio.run(start_demo())
        except (KeyboardInterrupt, SystemExit):
            logger.info("Demo stopped.")
    else:
        print(f"Unknown command: {command!r}")
        print("Usage: python -m opago_mica [demo|sender|receiver]")
        sys.exit(1)


if __name__ == "__main__":
    main()
