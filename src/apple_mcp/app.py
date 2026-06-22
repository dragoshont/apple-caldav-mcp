"""FastAPI app: native Streamable HTTP MCP (/mcp) + OpenAPI tool routes + /healthz.

Credential-free: this process holds no Apple secret. It authenticates to Tessera
with its OWN app-only caller token (client-credentials) and forwards the
signed-in person's OIDC token (captured per request) as ``X-Tessera-On-Behalf-Of``;
Tessera owns the Apple credential and returns only results.

A fresh :class:`AppleCalendarService` is built per tool call with the
request-scoped on-behalf-of token, so one user's call can never reuse another
user's session.
"""
from __future__ import annotations

import logging
import os
import re

from fastapi import FastAPI, HTTPException, Request

from .context import bearer_from_asgi_headers, get_obo_token, set_obo_token
from .mcp_streamable import _tool_schema, build_session_manager
from .service import AppleCalendarService
from .settings import (
    authentik_token_url,
    diag,
    http_port,
    max_redirects,
    request_timeout,
    tessera_caller_client_id,
    tessera_caller_client_secret,
    tessera_caller_scope,
    tessera_egress_url,
    tessera_target,
)
from .tessera_caldav import AppleEgressError, _CallerToken
from .tools import TOOLS

log = logging.getLogger("apple_mcp.app")

_applog = logging.getLogger("apple_mcp")
_applog.setLevel(logging.INFO)
if not any(isinstance(h, logging.StreamHandler) for h in _applog.handlers):
    _stream = logging.StreamHandler()
    _stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    _applog.addHandler(_stream)


# ── secret-free audit + scrub (the MCP holds no secret; defence in depth) ────
# Strips credential-shaped substrings before an error/log line can carry them.
# Two families: prefix-keyed (Bearer / Basic / the on-behalf-of header) and
# prefix-free forms a credential takes if it leaks into a body — a `client_secret`
# assignment, and a bare JWT (the caller/OBO token always starts `eyJ`, the
# base64url of `{"`). Over-redaction here is safe (fail closed).
_SECRET_RE = re.compile(
    r"(?i)"
    r"bearer\s+[A-Za-z0-9._\-]+"
    r"|basic\s+[A-Za-z0-9+/=]+"
    r"|x-tessera-on-behalf-of:\s*\S+"
    r"|client_secret[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9._+/=\-]+"
    r"|eyJ[A-Za-z0-9._\-]+"
)


def _scrub(text: str) -> str:
    """Strip credential-shaped substrings from an error before it can reach the model."""
    return _SECRET_RE.sub("[redacted]", text or "")


def _audit(name: str, params: dict, outcome: str) -> None:
    """Secret-free call audit on stdout (the args here are non-sensitive ranges)."""
    log.info("tool=%s outcome=%s args=%s", name, outcome, sorted((params or {}).keys()))


def _safe_detail(exc: Exception) -> str:
    return _scrub(str(exc))


# ── caller token (shared, cached) — minted via the librechat M2M client ──────
_caller: _CallerToken | None = None


def _get_caller() -> _CallerToken:
    global _caller
    if _caller is None:
        token_url = authentik_token_url()
        client_id = tessera_caller_client_id()
        client_secret = tessera_caller_client_secret()
        egress = tessera_egress_url()
        missing = [
            name
            for name, value in (
                ("TESSERA_EGRESS_URL", egress),
                ("TESSERA_TOKEN_URL", token_url),
                ("TESSERA_CALLER_CLIENT_ID", client_id),
                ("TESSERA_CALLER_CLIENT_SECRET", client_secret),
            )
            if not value
        ]
        if missing:
            raise AppleEgressError(
                f"Tessera broker not configured: missing env {', '.join(missing)}"
            )
        _caller = _CallerToken(token_url, client_id, client_secret, tessera_caller_scope())
    return _caller


def _build_service(obo_token: str) -> AppleCalendarService:
    """Build a per-call service bound to the request's on-behalf-of token."""
    return AppleCalendarService(
        egress_url=tessera_egress_url(),
        target=tessera_target(),
        caller=_get_caller(),
        on_behalf_of=obo_token,
        timeout=request_timeout(),
        max_redirects=max_redirects(),
    )


def _invoke_tool(name: str, params: dict, obo_token: str):
    """Single choke point shared by the OpenAPI routes and the MCP transport:
    build the request-scoped service and run the tool. The MCP is
    identity-agnostic — it forwards ``obo_token`` to Tessera, which enforces the
    per-user binding; this process makes no identity decision (HL-17)."""
    if name not in TOOLS:
        raise AppleEgressError(f"unknown tool '{name}'")
    service = _build_service(obo_token)
    return TOOLS[name](service, **params)


_session_manager = build_session_manager(
    invoke_tool=_invoke_tool,
    scrub_error=_safe_detail,
    audit=_audit,
)


from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def _lifespan(app: FastAPI):
    log.info("apple-mcp ready (credential-free; iCloud CalDAV via Tessera egress proxy)")
    async with _session_manager.run():
        yield


app = FastAPI(
    title="apple-caldav-mcp",
    description=(
        "MCP for Apple iCloud Calendar, Reminders + Contacts (CalDAV + CardDAV). "
        "Unofficial; not affiliated with Apple. Credential-free: holds no Apple "
        "secret — every request is brokered through Tessera, which injects the "
        "app-specific password. Reads (list_calendars, list_events, list_reminders, "
        "find_contacts) plus an opt-in write (create_event) that requires an "
        "out-of-band human approval. Tools are exposed both as OpenAPI POST "
        "routes and over native Streamable HTTP MCP at /mcp."
    ),
    version="0.1.7",
    lifespan=_lifespan,
)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "credential_free": True}


def _register_openapi_route(name: str, fn) -> None:
    """Expose each tool as POST /<name> for OpenWebUI / mcpo consumers."""

    def _handler(request: Request, payload: dict | None = None):
        params = payload or {}
        obo = bearer_from_asgi_headers(request.scope.get("headers", []))
        try:
            return _invoke_tool(name, params, obo)
        except AppleEgressError as exc:
            _audit(name, params, f"upstream_error:{type(exc).__name__}")
            raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
        except Exception as exc:
            _audit(name, params, f"error:{type(exc).__name__}")
            raise HTTPException(status_code=500, detail=_safe_detail(exc)) from exc

    body_schema = _tool_schema(fn)
    app.add_api_route(
        f"/{name}",
        _handler,
        methods=["POST"],
        name=name,
        operation_id=name,
        openapi_extra={
            "requestBody": {
                "required": bool(body_schema.get("required")),
                "content": {"application/json": {"schema": body_schema}},
            }
        },
    )


for _tool_name, _tool_fn in TOOLS.items():
    _register_openapi_route(_tool_name, _tool_fn)


# Native Streamable HTTP MCP endpoint. The session manager IS the ASGI app for
# this transport. We capture the inbound Authorization bearer (the signed-in
# person's forwarded OIDC token) into the request-scoped contextvar BEFORE
# handing off, so the tool call can forward it to Tessera as the on-behalf-of.
_DIAG_OBO_PATH = "/tmp/apple-mcp-diag-obo"  # noqa: S108 — operator replay aid (diag only)


def _maybe_capture_obo(token: str | None) -> None:
    """When APPLE_MCP_DIAG is set, persist the request's on-behalf-of token to a
    pod-local file so an operator can REPLAY tool calls (curl the OpenAPI routes)
    without a chat round-trip. Off by default; the token is short-lived and never
    logged. Delete the file + unset the flag after a testing session."""
    if not token or not diag():
        return
    try:
        fd = os.open(_DIAG_OBO_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token)
        log.info("diag: captured on-behalf-of token for replay (%s)", _DIAG_OBO_PATH)
    except Exception:  # noqa: BLE001
        pass


async def _mcp_asgi(scope, receive, send) -> None:
    if scope.get("type") == "http":
        token = bearer_from_asgi_headers(scope.get("headers", []))
        set_obo_token(token)
        _maybe_capture_obo(token)
    await _session_manager.handle_request(scope, receive, send)


app.mount("/mcp", _mcp_asgi)


# Keep get_obo_token imported (used by the MCP server build) — referenced here so
# linters don't flag the context module as unused at the app boundary.
_ = get_obo_token


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=http_port())
