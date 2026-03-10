"""URL helpers for local/demo and production VASP domains."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def infer_scheme_for_domain(domain: str) -> str:
    """Use HTTP for localhost-style domains and HTTPS otherwise."""
    candidate = domain if "://" in domain else f"//{domain}"
    hostname = (urlsplit(candidate).hostname or "").lower()

    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or (parsed_ip is not None and (parsed_ip.is_loopback or parsed_ip.is_unspecified))
    ):
        return "http"
    return "https"


def build_service_url(domain: str, path: str) -> str:
    """Build an absolute URL with the appropriate scheme for the domain."""
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{infer_scheme_for_domain(domain)}://{domain}{normalized_path}"
