"""Helpers for resolving UMA runtime key material."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any


def resolve_uma_runtime_keys(uma_config: Mapping[str, Any] | None) -> tuple[str, str]:
    """Return UMA signing and encryption keys or fail closed.

    Args:
        uma_config: Optional config overrides passed into the server factory.

    Returns:
        A tuple of ``(signing_key, encryption_key)``.

    Raises:
        RuntimeError: If either key is missing from both the config overrides
            and the environment.
    """
    overrides = uma_config or {}
    signing_key = (
        overrides.get("signingKey")
        or os.environ.get("UMA_SIGNING_KEY")
        or os.environ.get("VASP_SIGNING_KEY_PEM")
    )
    encryption_key = (
        overrides.get("encryptionKey")
        or os.environ.get("UMA_ENCRYPTION_KEY")
        or os.environ.get("VASP_ENCRYPTION_KEY_PEM")
    )

    missing: list[str] = []
    if not signing_key:
        missing.append("UMA_SIGNING_KEY / uma_config.signingKey")
    if not encryption_key:
        missing.append("UMA_ENCRYPTION_KEY / uma_config.encryptionKey")

    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(
            "Missing UMA runtime key configuration: "
            f"{joined}. Refusing to start with placeholder keys."
        )

    return signing_key, encryption_key
