"""Helpers for resolving the current application environment."""

from __future__ import annotations

import os


def current_app_env(default: str = "development") -> str:
    """Return the active application environment.

    ``APP_ENV`` is the canonical variable. ``NODE_ENV`` remains as a fallback
    so existing local scripts continue to work while callers migrate.
    """
    return os.environ.get("APP_ENV") or os.environ.get("NODE_ENV", default)
