"""
Receiving VASP HTTP Server

FastAPI application serving the beneficiary-side VASP API endpoints.
Handles UMA address resolution, pay requests, and incoming travel rule data.

Endpoints:
  GET  /.well-known/lnurlp/{username}      – LNURL-pay discovery
  GET  /.well-known/uma-configuration      – UMA VASP configuration
  POST /api/uma/payreq/{username}          – Handle UMA pay request
  POST /api/travel-rule/incoming           – Receive generic travel rule data
  POST /api/travel-rule/trp               – TRP protocol endpoint
  POST /api/travel-rule/trisa             – TRISA protocol endpoint
  GET  /api/compliance/requirements       – Get compliance requirements
  GET  /api/compliance/transfers          – List incoming transfers
  GET  /api/audit                         – Compliance audit log
  GET  /api/health                        – Health check
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
from opago_mica.core.compliance_engine import ComplianceEngine, ComplianceEngineConfig
from opago_mica.core.uma_mica import UMAMiCAProtocol
from opago_mica.receiving.receiver import ReceivingVASP
from opago_mica.types.common import HealthCheckResponse
from opago_mica.types.uma_extended import UMAMiCAConfig
from opago_mica.utils.logger import create_logger
from opago_mica.utils.uma_keys import resolve_uma_runtime_keys
from opago_mica.wallet.spark_wallet import SparkWalletManager, wallet_config_from_env

logger = create_logger("ReceiverServer")

# ---------------------------------------------------------------------------
# Config model
# ---------------------------------------------------------------------------


class ReceiverServerConfig(BaseModel):
    """Configuration for the receiving VASP HTTP server."""

    model_config = ConfigDict(populate_by_name=True)

    #: Hostname or IP to listen on.
    host: str = "0.0.0.0"
    #: TCP port.
    port: int = 3002
    #: Public domain (used in LNURL and UMA URLs).
    domain: str
    #: VASP display name.
    vasp_name: str
    #: Whether to accept eIDAS signatures from senders.
    eidas_enabled: bool = True
    #: MiCA license number.
    mica_license_number: str | None = None
    #: UMA/MiCA protocol configuration (optional overrides).
    uma_config: dict[str, Any] | None = None


class _IncomingTravelRule(BaseModel):
    """Request body for POST /api/travel-rule/incoming."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    protocol: str | None = None
    sender_vasp: str | None = None
    payload: Any = None


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_receiver_server(config: ReceiverServerConfig) -> FastAPI:
    """
    Create and configure the receiving VASP FastAPI application.

    All dependencies are instantiated with sensible defaults if not provided.

    Args:
        config: Server configuration.

    Returns:
        Configured :class:`FastAPI` application (not yet listening).

    Example::

        app = create_receiver_server(ReceiverServerConfig(
            host='0.0.0.0', port=3002,
            domain='receiver.vasp.local',
            vasp_name='Demo Receiver VASP',
        ))
        uvicorn.run(app, host='0.0.0.0', port=3002)
    """
    uma_cfg = config.uma_config or {}
    signing_key, encryption_key = resolve_uma_runtime_keys(uma_cfg)
    travel_rule_threshold_eur = float(
        uma_cfg.get("travelRuleThresholdEur")
        or os.environ.get("TRAVEL_RULE_THRESHOLD_EUR", "1000")
    )

    wallet_cfg = wallet_config_from_env(default_network="regtest", prefix="RECEIVER")
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

    compliance = ComplianceEngine(
        ComplianceEngineConfig(
            vasp_domain=config.domain,
            travel_rule_threshold_eur=travel_rule_threshold_eur,
        )
    )

    receiving_vasp = ReceivingVASP(
        wallet=wallet,
        uma_protocol=uma_protocol,
        travel_rule=travel_rule,
        compliance=compliance,
        vasp_domain=config.domain,
        vasp_name=config.vasp_name,
        eidas_enabled=config.eidas_enabled,
        **({"mica_license_number": config.mica_license_number}
           if config.mica_license_number is not None else {}),
    )

    # Initialize wallet and travel-rule providers before serving requests.
    async def _init_wallet() -> None:
        await wallet.initialize()
        logger.info("Receiver wallet initialized")

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

    app = FastAPI(title="Receiving VASP", version="0.1.0", lifespan=lifespan)
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
                "eidas": "ok" if config.eidas_enabled else "degraded",
            },
        )

    # ---------------------------------------------------------------------------
    # UMA / LNURL discovery
    # ---------------------------------------------------------------------------

    @router.get(
        "/.well-known/lnurlp/{username}",
        summary="LNURL-pay discovery endpoint",
    )
    async def lnurlp_discovery(username: str) -> Any:
        """
        GET /.well-known/lnurlp/{username}

        LNURL-pay discovery endpoint. Resolves a UMA address to payment metadata
        including this VASP's compliance capabilities and requirements.

        This is the first step in the UMA payment flow.

        Response: LnurlpResponse

        See: https://github.com/uma-universal-money-address/uma-spec#step-1
        """
        logger.info("LNURL-pay discovery request", username=username)

        try:
            lnurlp_response = await receiving_vasp.handle_lnurlp_request(username)
            return lnurlp_response
        except ValueError as exc:
            message = str(exc)
            if "not found" in message.lower():
                raise HTTPException(status_code=404, detail=f"User {username} not found") from exc
            logger.error("Error handling LNURL-pay request", username=username, error=message)
            raise HTTPException(status_code=500, detail="Internal server error") from exc

    @router.get(
        "/.well-known/uma-configuration",
        summary="UMA VASP configuration document",
    )
    async def uma_configuration() -> dict[str, Any]:
        """
        GET /.well-known/uma-configuration

        UMA VASP configuration document for discovery by other VASPs.
        Advertises supported protocols, encryption key, and MiCA compliance info.

        Response: UMAConfiguration
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
                "licenseNumber": config.mica_license_number,
            },
        }

    # ---------------------------------------------------------------------------
    # UMA pay request
    # ---------------------------------------------------------------------------

    @router.post("/api/uma/payreq/{username}", summary="Handle UMA pay request")
    async def uma_pay_request(username: str, request: Request) -> Any:
        """
        POST /api/uma/payreq/{username}

        Handle a UMA pay request from the originating VASP.

        This is the second step in the UMA payment flow: the sending VASP
        submits the payment intent including encrypted travel rule data. This
        endpoint returns a BOLT11 Lightning invoice.

        Request body: UMAPayRequest (raw JSON)
        Response: UMAPayResponse (includes BOLT11 invoice)

        See: https://github.com/uma-universal-money-address/uma-spec#step-3
        """
        body = await request.json()

        logger.info(
            "UMA pay request received",
            username=username,
            amount=body.get("amount"),
        )

        user = receiving_vasp.get_user(username)
        if not user:
            raise HTTPException(status_code=404, detail=f"User {username} not found")

        try:
            pay_response = await receiving_vasp.handle_pay_request(body, username)
            return pay_response
        except Exception as exc:
            message = str(exc)
            logger.error("Error handling pay request", username=username, error=message)

            if "blocked" in message.lower() or "rejected" in message.lower():
                return JSONResponse(
                    content={"error": message, "code": "COMPLIANCE_REJECTED"},
                    status_code=422,
                )
            return JSONResponse(
                content={"error": "Internal server error", "details": message},
                status_code=500,
            )

    # ---------------------------------------------------------------------------
    # Travel rule endpoints
    # ---------------------------------------------------------------------------

    @router.post("/api/travel-rule/incoming", summary="Receive generic travel rule data")
    async def travel_rule_incoming(body: _IncomingTravelRule) -> dict[str, Any]:
        """
        POST /api/travel-rule/incoming

        Generic endpoint to receive travel rule data from any VASP.

        Request body: { protocol, senderVASP, payload }
        """
        logger.info(
            "Incoming travel rule data",
            protocol=body.protocol,
            sender_vasp=body.sender_vasp,
        )

        if not body.sender_vasp or body.payload is None:
            raise HTTPException(status_code=400, detail="Missing senderVASP or payload")

        protocol_val: Any = body.protocol or "direct"

        try:
            transfer = await receiving_vasp.handle_travel_rule_data(
                protocol_val,
                body.payload,
                body.sender_vasp,
            )
            return {
                "received": True,
                "protocol": protocol_val,
                "transferId": transfer.transfer_id,
                "transferState": transfer.status.upper(),
            }
        except Exception as exc:
            logger.error("Error processing travel rule data", error=str(exc))
            raise HTTPException(
                status_code=500, detail="Failed to process travel rule data"
            ) from exc

    @router.post("/api/travel-rule/trp", summary="TRP protocol endpoint")
    async def travel_rule_trp(request: Request) -> dict[str, Any]:
        """
        POST /api/travel-rule/trp

        Travel Rule Protocol (TRP) endpoint.

        Receives IVMS101 data in TRP REST format.
        Headers:
          X-VASP-Domain: sender VASP domain

        Request body: IVMS101Payload

        See: https://trp.travel-rule.io/
        """
        sender_vasp = request.headers.get("x-vasp-domain", "unknown")
        logger.info("TRP travel rule data received", sender_vasp=sender_vasp)

        body = await request.json()
        if not body or not isinstance(body, dict):
            raise HTTPException(
                status_code=400, detail="Invalid request body – expected IVMS101 JSON"
            )

        try:
            transfer = await receiving_vasp.handle_travel_rule_data(
                "trp",
                body,
                sender_vasp,
            )
            return {
                "received": True,
                "protocol": "TRP",
                "senderVASP": sender_vasp,
                "transferId": transfer.transfer_id,
                "transferState": transfer.status.upper(),
            }
        except Exception as exc:
            logger.error("Error processing TRP data", error=str(exc))
            raise HTTPException(
                status_code=500, detail="Failed to process TRP data"
            ) from exc

    @router.post("/api/travel-rule/trisa", summary="TRISA protocol endpoint")
    async def travel_rule_trisa(request: Request) -> dict[str, Any]:
        """
        POST /api/travel-rule/trisa

        TRISA protocol endpoint.

        In production, TRISA uses mutual-TLS gRPC. This HTTP endpoint acts as
        a bridge for environments where gRPC is unavailable.

        Headers:
          X-TRISA-Sender: sender VASP TRISA address

        See: https://trisa.io/
        """
        sender_vasp = request.headers.get("x-trisa-sender", "unknown")
        logger.info("TRISA data received (HTTP bridge)", sender_vasp=sender_vasp)

        body = await request.json()
        if body is None:
            raise HTTPException(status_code=400, detail="Empty TRISA payload")

        try:
            transfer = await receiving_vasp.handle_travel_rule_data(
                "trisa",
                body,
                sender_vasp,
            )
            return {
                "received": True,
                "protocol": "TRISA",
                "senderVASP": sender_vasp,
                "transferId": transfer.transfer_id,
                "transferState": transfer.status.upper(),
            }
        except Exception as exc:
            logger.error("Error processing TRISA data", error=str(exc))
            raise HTTPException(
                status_code=500, detail="Failed to process TRISA data"
            ) from exc

    # ---------------------------------------------------------------------------
    # Compliance queries
    # ---------------------------------------------------------------------------

    @router.get("/api/compliance/requirements", summary="Get compliance requirements")
    async def compliance_requirements() -> dict[str, Any]:
        """
        GET /api/compliance/requirements

        Return this VASP's compliance requirements for senders.
        """
        requirements = uma_protocol.evaluate_compliance_requirements(1000)
        return {
            "travelRuleRequired": requirements.travel_rule_required,
            "travelRuleThresholdEur": requirements.travel_rule_threshold_eur,
            "eidasSignatureAccepted": requirements.eidas_signature_accepted,
            "supportedProtocols": travel_rule.get_registered_protocols(),
            "micaRegulated": True,
            "jurisdiction": "DE",
            "licenseNumber": config.mica_license_number,
        }

    @router.get("/api/compliance/transfers", summary="List incoming travel rule transfers")
    async def compliance_transfers() -> dict[str, Any]:
        """
        GET /api/compliance/transfers

        List all incoming travel rule transfers.
        """
        transfers = travel_rule.get_transfers()
        return {
            "transfers": [
                t.model_dump() if hasattr(t, "model_dump") else t for t in transfers
            ],
            "count": len(transfers),
        }

    @router.get("/api/audit", summary="Get compliance audit log")
    async def get_audit() -> dict[str, Any]:
        """
        GET /api/audit

        Get the compliance audit log.
        """
        records = receiving_vasp.get_audit_log()
        return {"records": [r.model_dump() for r in records], "count": len(records)}

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
        "Receiver VASP server configured",
        domain=config.domain,
        vasp_name=config.vasp_name,
        eidas_enabled=config.eidas_enabled,
    )

    return app


# ---------------------------------------------------------------------------
# Standalone startup helper
# ---------------------------------------------------------------------------


async def start_receiver_server() -> None:
    """
    Start the receiving VASP server.

    Environment variables:
    - ``RECEIVER_PORT`` (default: 3002)
    - ``RECEIVER_DOMAIN`` (default: ``localhost:<port>``)
    - ``RECEIVER_VASP_NAME`` (default: 'Demo Receiver VASP')
    - ``RECEIVER_EIDAS_ENABLED`` (default: 'true')
    - ``RECEIVER_MICA_LICENSE`` (optional)
    - ``UMA_SIGNING_KEY`` – PEM/hex signing key
    - ``UMA_ENCRYPTION_KEY`` – PEM/hex encryption key
    """
    import uvicorn  # type: ignore[import-untyped]

    port = int(os.environ.get("RECEIVER_PORT", "3002"))
    domain = os.environ.get("RECEIVER_DOMAIN", f"localhost:{port}")
    vasp_name = os.environ.get("RECEIVER_VASP_NAME", "Demo Receiver VASP")
    eidas_enabled = os.environ.get("RECEIVER_EIDAS_ENABLED", "true").lower() != "false"
    mica_license_number = os.environ.get("RECEIVER_MICA_LICENSE")

    cfg = ReceiverServerConfig(
        host="0.0.0.0",
        port=port,
        domain=domain,
        vasp_name=vasp_name,
        eidas_enabled=eidas_enabled,
        **({"mica_license_number": mica_license_number} if mica_license_number else {}),
    )
    app = create_receiver_server(cfg)

    uvicorn_config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(uvicorn_config)
    logger.info(
        "Receiving VASP server listening",
        port=port,
        domain=domain,
        vasp_name=vasp_name,
    )
    await server.serve()
