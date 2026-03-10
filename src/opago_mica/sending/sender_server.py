"""
Sending VASP HTTP Server

FastAPI application serving the originator-side VASP API endpoints.
Provides a REST API for initiating MiCA-compliant payments and
querying compliance state.

Endpoints:
  POST /api/send                      – Initiate a payment
  GET  /api/balance                   – Wallet balance
  GET  /api/transactions              – Transaction history
  GET  /api/compliance/transfers      – Travel rule transfer log
  GET  /api/audit                     – Compliance audit log
  GET  /api/health                    – Health check
  POST /api/travel-rule/callback      – Callback for async travel rule responses
  GET  /.well-known/uma-configuration – UMA VASP discovery
  GET  /.well-known/lnurlp/{username} – LNURL pay endpoint
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from opago_mica.compliance.travel_rule_manager import TravelRuleManager
from opago_mica.compliance.trisa_adapter import TRISAAdapter, TRISAConfig
from opago_mica.core.compliance_engine import ComplianceEngine
from opago_mica.core.uma_mica import UMAMiCAProtocol
from opago_mica.eidas.eidas_wallet import EIDASWalletBridge
from opago_mica.sending.sender import SendingVASP, SendPaymentParams
from opago_mica.types.common import HealthCheckResponse
from opago_mica.types.uma_extended import UMAMiCAConfig
from opago_mica.utils.logger import create_logger
from opago_mica.utils.uma_keys import resolve_uma_runtime_keys
from opago_mica.utils.url import build_service_url
from opago_mica.wallet.spark_wallet import SparkWalletManager, wallet_config_from_env

logger = create_logger("SenderServer")

# ---------------------------------------------------------------------------
# Config model
# ---------------------------------------------------------------------------


class SenderServerConfig(BaseModel):
    """Configuration for the sending VASP HTTP server."""

    model_config = ConfigDict(populate_by_name=True)

    #: Hostname or IP to listen on.
    host: str = "0.0.0.0"
    #: TCP port.
    port: int = 3001
    #: Public domain (used in LNURL and UMA URLs).
    domain: str
    #: VASP display name.
    vasp_name: str
    #: Whether eIDAS is enabled for this VASP.
    eidas_enabled: bool = True
    #: MiCA license number to include in UMA configuration.
    mica_license_number: str | None = None
    #: UMA/MiCA protocol configuration (optional overrides).
    uma_config: dict[str, Any] | None = None


class _SendRequest(BaseModel):
    """Request body for POST /api/send."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    receiver_uma: str
    amount_sats: int
    sender_name: str
    sender_account: str
    currency: str | None = None
    memo: str | None = None
    use_eidas: bool | None = None


class _TravelRuleCallback(BaseModel):
    """Request body for POST /api/travel-rule/callback."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    transfer_id: str | None = None
    status: str | None = None
    protocol: str | None = None


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_sender_server(config: SenderServerConfig) -> FastAPI:
    """
    Create and configure the sending VASP FastAPI application.

    All dependencies are instantiated with sensible defaults if not provided.

    Args:
        config: Server configuration.

    Returns:
        Configured :class:`FastAPI` application (not yet listening).

    Example::

        app = create_sender_server(SenderServerConfig(
            host='0.0.0.0', port=3001,
            domain='sender.vasp.local',
            vasp_name='Demo Sender VASP',
        ))
        uvicorn.run(app, host='0.0.0.0', port=3001)
    """
    uma_cfg = config.uma_config or {}
    signing_key, encryption_key = resolve_uma_runtime_keys(uma_cfg)
    travel_rule_threshold_eur = float(
        uma_cfg.get("travelRuleThresholdEur")
        or os.environ.get("TRAVEL_RULE_THRESHOLD_EUR", "1000")
    )

    wallet_cfg = wallet_config_from_env(default_network="regtest", prefix="SENDER")
    wallet = SparkWalletManager(wallet_cfg)

    uma_protocol = UMAMiCAProtocol(UMAMiCAConfig(
        vasp_domain=config.domain,
        signing_key=signing_key,
        encryption_key=encryption_key,
        travel_rule_threshold_eur=travel_rule_threshold_eur,
        eidas_enabled=config.eidas_enabled,
    ))

    travel_rule = TravelRuleManager()

    # Register TRISA adapter when credentials are available (env or test scripts)
    trisa_cert = os.environ.get("TRISA_CERTIFICATE_PATH")
    trisa_key = os.environ.get("TRISA_PRIVATE_KEY_PATH")
    trisa_dir = os.environ.get("TRISA_DIRECTORY_ENDPOINT")
    trisa_vasp = os.environ.get("TRISA_VASP_ID")
    if all((trisa_cert, trisa_key, trisa_dir, trisa_vasp)):
        trisa_adapter = TRISAAdapter(
            TRISAConfig(
                certificate_path=trisa_cert,
                private_key_path=trisa_key,
                directory_endpoint=trisa_dir,
                vasp_id=trisa_vasp,
            )
        )
        travel_rule.register_provider(trisa_adapter)
        logger.info("TRISA adapter registered", vasp_id=trisa_vasp)

    eidas_bridge = EIDASWalletBridge(
        enabled=config.eidas_enabled,
        issuer_url=f"https://issuer.{config.domain}",
    )

    from opago_mica.core.compliance_engine import ComplianceEngineConfig
    compliance = ComplianceEngine(
        ComplianceEngineConfig(
            vasp_domain=config.domain,
            travel_rule_threshold_eur=travel_rule_threshold_eur,
        )
    )

    sending_vasp = SendingVASP(
        wallet=wallet,
        uma_protocol=uma_protocol,
        travel_rule=travel_rule,
        eidas_bridge=eidas_bridge,
        compliance=compliance,
        vasp_domain=config.domain,
        vasp_name=config.vasp_name,
    )

    # Initialize wallet and travel-rule providers before serving requests.
    async def _init_wallet() -> None:
        await wallet.initialize()
        logger.info("Sender wallet initialized")

    async def _init_travel_rule() -> None:
        await travel_rule.initialize_all()
        logger.info("Travel rule providers initialized")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> Any:
        await _init_wallet()
        await _init_travel_rule()
        yield

    # ---------------------------------------------------------------------------
    # FastAPI app
    # ---------------------------------------------------------------------------

    allowed_origins = [
        origin.strip()
        for origin in os.environ.get(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:3080,http://127.0.0.1:3080",
        ).split(",")
        if origin.strip()
    ]

    app = FastAPI(title="Sending VASP", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    router = APIRouter()

    @app.middleware("http")
    async def _log_requests(request: Request, call_next: Any) -> Any:
        logger.info(
            f"{request.method} {request.url.path}",
            ip=request.client.host if request.client else "unknown",
        )
        return await call_next(request)

    # ---------------------------------------------------------------------------
    # Health check
    # ---------------------------------------------------------------------------

    @router.get("/api/health", response_model=HealthCheckResponse, summary="Health check")
    async def health_check() -> HealthCheckResponse:
        """
        GET /api/health

        Returns server health status.
        Response: HealthCheckResponse
        """
        from datetime import UTC, datetime

        return HealthCheckResponse(
            status="ok",
            version="0.1.0",
            timestamp=datetime.now(UTC).isoformat(),
            services={
                "wallet": "ok",
                "compliance": "ok",
                "travelRule": "ok",
                "eidas": "ok" if eidas_bridge.is_available() else "degraded",
            },
        )

    # ---------------------------------------------------------------------------
    # UMA discovery
    # ---------------------------------------------------------------------------

    @router.get(
        "/.well-known/uma-configuration",
        summary="UMA VASP configuration document",
    )
    async def uma_configuration() -> dict[str, Any]:
        """
        GET /.well-known/uma-configuration

        UMA VASP configuration document for discovery by other VASPs.
        Advertises supported protocols, encryption keys, and MiCA compliance info.

        See: https://github.com/uma-universal-money-address/uma-spec#uma-vasp-configuration
        """
        return {
            "umaVersion": "1.0",
            "encryptionPubKey": uma_protocol.get_encryption_public_key_pem(),
            "signingPubKey": uma_protocol.get_signing_public_key_pem(),
            "encryptionAlgo": "ECDH-ES+A256KW",
            "complianceFeatures": {
                "travelRuleProtocols": travel_rule.get_registered_protocols(),
                "eidasSupported": config.eidas_enabled,
                "micaRegulated": True,
                "micaLicense": config.mica_license_number,
            },
            "vaspInfo": {
                "name": config.vasp_name,
                "domain": config.domain,
                "jurisdiction": "DE",
            },
        }

    @router.get(
        "/.well-known/lnurlp/{username}",
        summary="LNURL-pay metadata endpoint",
    )
    async def lnurlp(username: str) -> dict[str, Any]:
        """
        GET /.well-known/lnurlp/{username}

        LNURL-pay metadata endpoint. Allows this VASP to also receive payments
        at UMA addresses on its domain (sending VASPs can also receive).

        Response: LnurlpResponse
        """
        logger.info("LNURL-pay request on sender VASP", username=username)

        return {
            "tag": "payRequest",
            "callback": build_service_url(config.domain, f"/api/uma/payreq/{username}"),
            "minSendable": 1_000,
            "maxSendable": 100_000_000_000,
            "metadata": str([
                ["text/plain", f"Pay {username} at {config.vasp_name}"],
                ["text/identifier", f"${username}@{config.domain}"],
            ]),
            "travelRuleRequired": True,
            "eidasSignatureAccepted": config.eidas_enabled,
            "umaVersion": "1.0",
            "compliance": {
                "isMiCARegulated": True,
                "travelRuleProtocols": travel_rule.get_registered_protocols(),
                "micaLicenseNumber": config.mica_license_number,
                "jurisdiction": "DE",
            },
        }

    # ---------------------------------------------------------------------------
    # Payment initiation
    # ---------------------------------------------------------------------------

    @router.post("/api/send", summary="Initiate a MiCA-compliant payment")
    async def send_payment(body: _SendRequest) -> JSONResponse:
        """
        POST /api/send

        Initiate a MiCA-compliant payment.

        Request body: SendPaymentParams (JSON)
        Response: SendPaymentResult
        """
        if body.amount_sats <= 0:
            raise HTTPException(status_code=400, detail="amount_sats must be greater than 0")

        logger.info(
            "Payment request received",
            receiver_uma=body.receiver_uma,
            amount_sats=body.amount_sats,
        )

        try:
            params = SendPaymentParams(
                receiver_uma=body.receiver_uma,
                amount_sats=body.amount_sats,
                sender_name=body.sender_name,
                sender_account=body.sender_account,
                currency=body.currency,
                memo=body.memo,
                use_eidas=body.use_eidas,
            )
            result = await sending_vasp.send_payment(params)
            status_code = 200 if result.success else 422
            return JSONResponse(content=result.model_dump(), status_code=status_code)
        except Exception as exc:
            logger.error("Unexpected error in /api/send", error=str(exc))
            return JSONResponse(
                content={"error": "Internal server error", "details": str(exc)},
                status_code=500,
            )

    # ---------------------------------------------------------------------------
    # Wallet endpoints
    # ---------------------------------------------------------------------------

    @router.get("/api/balance", summary="Get wallet balance")
    async def get_balance() -> Any:
        """
        GET /api/balance

        Get the current wallet balance.
        Response: WalletBalance
        """
        try:
            balance = await wallet.get_balance()
            return balance
        except Exception as exc:
            logger.error("Error fetching balance", error=str(exc))
            raise HTTPException(status_code=500, detail="Failed to fetch balance") from exc

    @router.get("/api/transactions", summary="Get transaction history")
    async def get_transactions() -> dict[str, Any]:
        """
        GET /api/transactions

        Get recent transaction history.
        Response: TransactionRecord[]
        """
        try:
            transactions = await wallet.get_transaction_history()
            return {
                "transactions": [t.model_dump() for t in transactions],
                "count": len(transactions),
            }
        except Exception as exc:
            logger.error("Error fetching transactions", error=str(exc))
            raise HTTPException(status_code=500, detail="Failed to fetch transactions") from exc

    # ---------------------------------------------------------------------------
    # Compliance endpoints
    # ---------------------------------------------------------------------------

    @router.get("/api/compliance/transfers", summary="List travel rule transfers")
    async def get_compliance_transfers() -> dict[str, Any]:
        """
        GET /api/compliance/transfers

        List all outgoing travel rule transfers.
        """
        transfers = travel_rule.get_transfers()
        return {
            "transfers": [
                t.model_dump() if hasattr(t, "model_dump") else t
                for t in transfers
            ],
            "count": len(transfers),
        }

    @router.get("/api/audit", summary="Get compliance audit log")
    async def get_audit() -> dict[str, Any]:
        """
        GET /api/audit

        Get the compliance audit log.
        Response: PaymentAuditRecord[]
        """
        records = sending_vasp.get_audit_log()
        return {"records": [r.model_dump() for r in records], "count": len(records)}

    # ---------------------------------------------------------------------------
    # Travel rule callback
    # ---------------------------------------------------------------------------

    @router.post("/api/travel-rule/callback", summary="Travel rule callback")
    async def travel_rule_callback(body: _TravelRuleCallback) -> dict[str, Any]:
        """
        POST /api/travel-rule/callback

        Receive asynchronous travel rule responses from beneficiary VASPs.

        Request body: { transferId, status, protocol }
        """
        logger.info("Travel rule callback received", transfer_id=body.transfer_id)

        if not body.transfer_id:
            raise HTTPException(status_code=400, detail="Missing transferId")

        transfer = travel_rule.get_transfer(body.transfer_id)
        if not transfer:
            raise HTTPException(
                status_code=404, detail=f"Transfer {body.transfer_id} not found"
            )

        return {
            "received": True,
            "transferId": body.transfer_id,
            "status": transfer.status if hasattr(transfer, "status") else "unknown",
        }

    # ---------------------------------------------------------------------------
    # Attach router & global exception handler
    # ---------------------------------------------------------------------------

    app.include_router(router)

    @app.exception_handler(Exception)
    async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled server error", error=str(exc))
        return JSONResponse(
            content={
                "error": "Internal server error",
                "details": str(exc),
            },
            status_code=500,
        )

    logger.info(
        "Sender VASP server configured",
        domain=config.domain,
        vasp_name=config.vasp_name,
        eidas_enabled=config.eidas_enabled,
    )

    return app


# ---------------------------------------------------------------------------
# Standalone startup helper
# ---------------------------------------------------------------------------


async def start_sender_server() -> None:
    """
    Start the sending VASP server.

    Environment variables:
    - ``SENDER_PORT`` (default: 3001)
    - ``SENDER_DOMAIN`` (default: ``localhost:<port>``)
    - ``SENDER_VASP_NAME`` (default: 'Demo Sender VASP')
    - ``UMA_SIGNING_KEY`` – PEM/hex signing key
    - ``UMA_ENCRYPTION_KEY`` – PEM/hex encryption key
    - ``SENDER_SPARK_MNEMONIC`` – optional sender wallet mnemonic
    - ``SENDER_SPARK_MASTER_KEY`` – optional sender raw seed/master key
    - ``SPARK_NETWORK`` – Spark network (`MAINNET`, `REGTEST`, `SIGNET`)
    """
    import uvicorn  # type: ignore[import-untyped]

    port = int(os.environ.get("SENDER_PORT", "3001"))
    domain = os.environ.get("SENDER_DOMAIN", f"localhost:{port}")
    vasp_name = os.environ.get("SENDER_VASP_NAME", "Demo Sender VASP")

    app = create_sender_server(
        SenderServerConfig(
            host="0.0.0.0",
            port=port,
            domain=domain,
            vasp_name=vasp_name,
        )
    )

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    logger.info("Sending VASP server listening", port=port, domain=domain, vasp_name=vasp_name)
    await server.serve()
