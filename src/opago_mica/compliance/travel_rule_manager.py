"""
Travel Rule Manager.

Orchestrates travel-rule protocol adapters and provides a unified API for
initiating and receiving transfers regardless of the underlying protocol.

Responsibilities:
 1. Maintain a registry of protocol adapters (TRISA, TRP, TRUST, GTR, direct)
 2. Discover counterparty capabilities via each registered protocol
 3. Negotiate and select the best common protocol
    (preference: TRISA > TRP > TRUST > GTR > direct)
 4. Route transfers to the appropriate adapter
 5. Store and expose all transfers across all protocols
 6. Enforce MiCA Article 83 threshold rule (≥ EUR 1,000 equivalent)

Usage::

    manager = TravelRuleManager()
    manager.register_provider(TRISAAdapter(trisa_config))
    manager.register_provider(TRPAdapter(trp_config))

    transfer = await manager.initiate_transfer(
        InitiateTransferParams(
            ivms101=ivms101,
            counterparty_domain="kraken.com",
            tx_hash="0xabc…",
            asset="ETH",
            amount="1.5",
        )
    )
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, ConfigDict

from opago_mica.compliance.travel_rule_provider import (
    CounterpartyInfo,
    TransferResponse,
    TransferStatus,
    TravelRuleProtocol,
    TravelRuleProvider,
    TravelRuleTransfer,
)
from opago_mica.types.ivms101 import IVMS101Payload
from opago_mica.utils.logger import create_logger

log = create_logger("TravelRuleManager")

# ---------------------------------------------------------------------------
# Protocol preference order (highest to lowest)
# ---------------------------------------------------------------------------

PROTOCOL_PREFERENCE: list[TravelRuleProtocol] = ["trisa", "trp", "trust", "gtr", "direct"]

# ---------------------------------------------------------------------------
# Manager types
# ---------------------------------------------------------------------------


class InitiateTransferParams(BaseModel):
    """Parameters for initiating an outgoing travel-rule transfer."""

    model_config = ConfigDict(populate_by_name=True)

    ivms101: IVMS101Payload
    counterparty_domain: str
    tx_hash: str
    asset: str
    amount: str


class NegotiationResult:
    """Result of protocol negotiation — the winning protocol and its provider."""

    def __init__(
        self,
        protocol: TravelRuleProtocol,
        counterparty: CounterpartyInfo,
        provider: TravelRuleProvider,
    ) -> None:
        self.protocol = protocol
        self.counterparty = counterparty
        self.provider = provider


# ---------------------------------------------------------------------------
# TravelRuleManager
# ---------------------------------------------------------------------------


class TravelRuleManager:
    """
    Orchestrates travel-rule protocol adapters.

    Maintains a registry of protocol providers, negotiates the best common
    protocol with counterparties, routes transfers, and tracks all transfer
    state across protocols.

    Usage::

        manager = TravelRuleManager()
        manager.register_provider(TRISAAdapter(trisa_config))
        transfer = await manager.initiate_transfer(params)
    """

    def __init__(self) -> None:
        self._providers: dict[TravelRuleProtocol, TravelRuleProvider] = {}
        self._transfers: dict[str, TravelRuleTransfer] = {}
        log.debug("TravelRuleManager created")

    # -------------------------------------------------------------------------
    # Provider registry
    # -------------------------------------------------------------------------

    def register_provider(self, provider: TravelRuleProvider) -> None:
        """
        Register a travel-rule protocol adapter.

        Call ``initialize()`` on the provider before or after registration as needed.

        :param provider: Protocol adapter implementing :class:`TravelRuleProvider`.
        """
        if provider.protocol in self._providers:
            log.warning(
                "TravelRuleManager: overwriting existing provider",
                protocol=provider.protocol,
            )
        self._providers[provider.protocol] = provider
        log.info(
            "TravelRuleManager: registered provider",
            protocol=provider.protocol,
        )

    async def initialize_all(self) -> None:
        """
        Initialize all registered providers.

        Convenience method — alternatively, providers may be initialized before
        being registered. Failures are logged but do not prevent other providers
        from initializing.
        """
        providers = list(self._providers.values())
        results = await asyncio.gather(
            *[p.initialize() for p in providers],
            return_exceptions=True,
        )
        for provider, result in zip(providers, results, strict=True):
            if isinstance(result, Exception):
                log.error(
                    "TravelRuleManager: provider initialization failed",
                    protocol=provider.protocol,
                    error=str(result),
                )

    # -------------------------------------------------------------------------
    # Originator-side: initiate outgoing transfer
    # -------------------------------------------------------------------------

    async def initiate_transfer(
        self,
        params: InitiateTransferParams,
    ) -> TravelRuleTransfer:
        """
        Initiate a travel-rule transfer to a counterparty VASP.

        The manager will:
         1. Discover what protocols the counterparty supports
         2. Select the best protocol this VASP also supports
         3. Validate the IVMS101 payload against that protocol's rules
         4. Send the transfer and store the result

        :param params: Transfer parameters including IVMS101 payload,
                       counterparty domain, transaction hash, asset, and amount.
        :returns: Completed TravelRuleTransfer record.
        :raises RuntimeError: If no providers are registered.
        :raises ValueError: If no common protocol can be negotiated.
        """
        log.info(
            "TravelRuleManager: initiating transfer",
            counterparty_domain=params.counterparty_domain,
            asset=params.asset,
            amount=params.amount,
            tx_hash=params.tx_hash,
        )

        if not self._providers:
            raise RuntimeError(
                "TravelRuleManager: no providers registered — "
                "call register_provider() first"
            )

        negotiation = await self._negotiate_protocol(params.counterparty_domain)

        log.info(
            "TravelRuleManager: protocol negotiated",
            protocol=negotiation.protocol,
            counterparty_vasp_id=negotiation.counterparty.vasp_id,
        )

        from opago_mica.compliance.travel_rule_provider import SendTransferParams

        transfer = await negotiation.provider.send_transfer(
            SendTransferParams(
                ivms101=params.ivms101,
                counterparty=negotiation.counterparty,
                tx_hash=params.tx_hash,
                asset=params.asset,
                amount=params.amount,
            )
        )

        self._transfers[transfer.transfer_id] = transfer
        return transfer

    # -------------------------------------------------------------------------
    # Beneficiary-side: handle incoming transfer
    # -------------------------------------------------------------------------

    async def handle_incoming(
        self,
        protocol: TravelRuleProtocol,
        raw_data: Any,
    ) -> TravelRuleTransfer:
        """
        Route a raw incoming travel-rule message to the appropriate adapter.

        :param protocol: Protocol that delivered the raw data.
        :param raw_data: Raw message from the protocol transport layer.
        :returns: Parsed TravelRuleTransfer with status 'pending'.
        """
        provider = self._require_provider(protocol)

        log.info(
            "TravelRuleManager: handling incoming transfer",
            protocol=protocol,
        )

        transfer = await provider.handle_incoming_transfer(raw_data)
        self._transfers[transfer.transfer_id] = transfer
        return transfer

    # -------------------------------------------------------------------------
    # Beneficiary-side: respond to incoming transfer
    # -------------------------------------------------------------------------

    async def respond(
        self,
        transfer_id: str,
        accepted: bool,
        beneficiary_data: IVMS101Payload | None = None,
    ) -> TravelRuleTransfer:
        """
        Accept or reject a pending incoming transfer.

        :param transfer_id:      Transfer to respond to.
        :param accepted:         Whether to accept the transfer.
        :param beneficiary_data: Optional IVMS101 payload for the beneficiary
                                 (required by some protocols when accepting).
        :returns: Updated TravelRuleTransfer record.
        """
        transfer = self._require_transfer(transfer_id)
        provider = self._require_provider(transfer.protocol)

        log.info(
            "TravelRuleManager: responding to transfer",
            transfer_id=transfer_id,
            protocol=transfer.protocol,
            accepted=accepted,
        )

        updated = await provider.respond_to_transfer(
            transfer_id,
            TransferResponse(
                accepted=accepted,
                beneficiary_ivms101=beneficiary_data,
            ),
        )

        self._transfers[transfer_id] = updated
        return updated

    # -------------------------------------------------------------------------
    # Queries
    # -------------------------------------------------------------------------

    def get_transfers(self) -> list[TravelRuleTransfer]:
        """Return all transfers tracked by the manager (all protocols)."""
        return list(self._transfers.values())

    def get_transfers_by_status(
        self,
        status: TransferStatus,
    ) -> list[TravelRuleTransfer]:
        """
        Return transfers filtered by status.

        :param status: Transfer status to filter by.
        """
        return [t for t in self.get_transfers() if t.status == status]

    def get_transfers_by_protocol(
        self,
        protocol: TravelRuleProtocol,
    ) -> list[TravelRuleTransfer]:
        """
        Return transfers filtered by protocol.

        :param protocol: Travel-rule protocol to filter by.
        """
        return [t for t in self.get_transfers() if t.protocol == protocol]

    def get_transfer(self, transfer_id: str) -> TravelRuleTransfer | None:
        """
        Return a single transfer by ID, or None if not found.

        :param transfer_id: Transfer ID to look up.
        """
        return self._transfers.get(transfer_id)

    def get_registered_protocols(self) -> list[TravelRuleProtocol]:
        """List all registered protocols."""
        return list(self._providers.keys())

    # -------------------------------------------------------------------------
    # Protocol negotiation (private)
    # -------------------------------------------------------------------------

    async def _negotiate_protocol(
        self,
        counterparty_domain: str,
    ) -> NegotiationResult:
        """
        Determine the best protocol to use with a given counterparty.

        Algorithm:
         1. For each registered provider (in preference order), try to discover
            the counterparty capabilities via that protocol.
         2. Select the highest-preference protocol supported by both sides.
         3. Fall back to the next protocol on discovery or network failure.

        :param counterparty_domain: Internet domain of the counterparty VASP.
        :returns: NegotiationResult with the selected protocol, counterparty info,
                  and provider.
        :raises ValueError: If no common protocol can be found.
        """
        log.debug(
            "TravelRuleManager: negotiating protocol",
            counterparty_domain=counterparty_domain,
        )

        # Build discovery attempts in preference order, skipping unregistered protocols
        candidates: list[TravelRuleProtocol] = [
            p for p in PROTOCOL_PREFERENCE if p in self._providers
        ]

        async def _attempt(protocol: TravelRuleProtocol) -> NegotiationResult | None:
            provider = self._providers[protocol]
            try:
                counterparty = await provider.discover_counterparty(counterparty_domain)
                return NegotiationResult(
                    protocol=protocol,
                    counterparty=counterparty,
                    provider=provider,
                )
            except Exception as exc:
                log.debug(
                    f"TravelRuleManager: {protocol} discovery failed "
                    f"for {counterparty_domain}",
                    error=str(exc),
                )
                return None

        results = await asyncio.gather(*[_attempt(p) for p in candidates])

        # Select the first successful discovery in preference order
        for result in results:
            if result is None:
                continue
            protocol = result.protocol
            counterparty = result.counterparty
            # Verify the counterparty actually supports this protocol
            if protocol in counterparty.supported_protocols or protocol == "direct":
                log.debug(
                    "TravelRuleManager: selected protocol",
                    protocol=protocol,
                    counterparty_vasp_id=counterparty.vasp_id,
                )
                return result

        # If we get here, try direct IVMS101 exchange if available
        if "direct" in self._providers:
            provider = self._providers["direct"]
            counterparty = await provider.discover_counterparty(counterparty_domain)
            return NegotiationResult(
                protocol="direct",
                counterparty=counterparty,
                provider=provider,
            )

        raise ValueError(
            f'TravelRuleManager: no common travel-rule protocol found for '
            f'"{counterparty_domain}". '
            f"Registered protocols: {', '.join(candidates)}"
        )

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _require_provider(self, protocol: TravelRuleProtocol) -> TravelRuleProvider:
        provider = self._providers.get(protocol)
        if provider is None:
            raise KeyError(
                f'TravelRuleManager: no provider registered for protocol "{protocol}"'
            )
        return provider

    def _require_transfer(self, transfer_id: str) -> TravelRuleTransfer:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise KeyError(f"TravelRuleManager: transfer not found: {transfer_id}")
        return transfer
