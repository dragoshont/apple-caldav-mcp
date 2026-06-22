"""Request-scoped on-behalf-of token.

LibreChat forwards the signed-in person's OIDC token to this MCP as
``Authorization: Bearer <token>`` on each inbound MCP request. The ASGI layer
(:mod:`apple_mcp.app`) captures it into this contextvar; the MCP call handler
reads it in the async request context (before threading the synchronous tool
call) and passes it EXPLICITLY down to the Tessera transport as
``X-Tessera-On-Behalf-Of``.

Kept in its own module so the ASGI layer (setter) and the MCP server (getter)
share it without an import cycle, and the value is request-scoped, never global —
one user's token can never bleed into another user's call (HL-17: the MCP is
identity-agnostic; per-user routing is the chat's signed token + Tessera's
binding, never a decision this process makes).
"""
from __future__ import annotations

import contextvars

_obo_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    "apple_mcp_obo_token", default=""
)


def set_obo_token(token: str) -> None:
    _obo_token.set(token or "")


def get_obo_token() -> str:
    return _obo_token.get()


def bearer_from_asgi_headers(headers: list[tuple[bytes, bytes]]) -> str:
    """Extract the bearer value from raw ASGI ``Authorization`` headers, or ''."""
    for key, value in headers or []:
        if key.lower() == b"authorization":
            text = value.decode("latin-1").strip()
            if text.lower().startswith("bearer "):
                return text[7:].strip()
    return ""
