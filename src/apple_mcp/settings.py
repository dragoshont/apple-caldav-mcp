"""Configuration for brokered and guarded direct Apple DAV modes."""
from __future__ import annotations

import os


class ConfigurationError(RuntimeError):
    """Raised when a required env var is missing or unparseable."""


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes")


def tessera_egress_url() -> str:
    """Base URL of the Tessera broker. The MCP POSTs each CalDAV hop to
    ``{url}/v1/egress/{target}``. Required — the MCP has no Apple egress of its
    own; app.py fails fast at client build with a clear message."""
    return os.environ.get("TESSERA_EGRESS_URL", "").rstrip("/")


def tessera_target() -> str:
    """The Tessera proxy target name (matches the recipe/binding/grant)."""
    return os.environ.get("TESSERA_TARGET", "apple-caldav")


def direct_mode() -> bool:
    """Use the temporary direct CalDAV transport instead of legacy Tessera egress."""
    return env_flag("APPLE_MCP_DIRECT", default=False)


def apple_id() -> str:
    """Apple Account identifier used only by the guarded direct transport."""
    return os.environ.get("APPLE_ID", "")


def apple_app_password() -> str:
    """Apple app-specific password used only by the guarded direct transport."""
    return os.environ.get("APPLE_APP_PASSWORD", "")


def authentik_token_url() -> str:
    """Client-credentials token endpoint (Authentik) that mints the MCP's caller
    token. Required."""
    return os.environ.get("TESSERA_TOKEN_URL", "")


def tessera_caller_client_id() -> str:
    """The MCP's own client id at the token endpoint (client-credentials). Required.

    Note: if Tessera validates a SINGLE issuer + audience, mint this caller token
    via a shared Authentik M2M client (e.g. your chat app's) so it passes that
    validation. The grant's ``caller`` is this id (the token's ``azp``)."""
    return os.environ.get("TESSERA_CALLER_CLIENT_ID", "")


def tessera_caller_client_secret() -> str:
    """The MCP's own client secret (client-credentials grant). Required.

    Injected from Key Vault via ESO (never baked into the image or argv)."""
    return os.environ.get("TESSERA_CALLER_CLIENT_SECRET", "")


def tessera_caller_scope() -> str:
    """OAuth scope requested for the caller token. The ``tessera_caller`` scope
    marks the token app-only (``idtyp=app``) so Tessera's caller plane accepts it."""
    return os.environ.get("TESSERA_CALLER_SCOPE", "openid tessera_caller")


def request_timeout() -> float:
    """Per-hop HTTP timeout (seconds) for the brokered CalDAV calls."""
    try:
        return float(os.environ.get("APPLE_MCP_HTTP_TIMEOUT", "30"))
    except ValueError:
        return 30.0


def max_redirects() -> int:
    """Max RFC 6764 partition redirects the MCP follows per request."""
    try:
        return int(os.environ.get("APPLE_MCP_MAX_REDIRECTS", "5"))
    except ValueError:
        return 5


def http_port() -> int:
    return int(os.environ.get("APPLE_MCP_HTTP_PORT", "8080"))


def writes_enabled() -> bool:
    """Expose brokered calendar writes only; direct mode is always read-only.

    Brokered writes stay invisible until an operator sets
    ``APPLE_MCP_ENABLE_WRITES`` and a Tessera ``manage:dav`` grant exists.
    """
    return not direct_mode() and env_flag("APPLE_MCP_ENABLE_WRITES", default=False)


def debug() -> bool:
    return env_flag("APPLE_MCP_DEBUG", default=False)


def diag() -> bool:
    """Operator diagnostic mode (default OFF). When on, list_reminders logs a
    per-list accessibility dump (component-set + VTODO counts) and the MCP captures
    the request's short-lived on-behalf-of token to a pod-local file so tool calls
    can be REPLAYED without a chat round-trip. For a testing session only."""
    return env_flag("APPLE_MCP_DIAG", default=False)
