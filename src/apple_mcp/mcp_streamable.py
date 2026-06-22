"""Native **Streamable HTTP** MCP transport for apple-mcp.

Exposes the SAME ``TOOLS`` as the OpenAPI surface over the MCP Streamable HTTP
transport (mounted at /mcp), so MCP-native clients consume Apple Calendar the
standard, declarative way:

  * LibreChat -> ``mcpServers: { apple: { type: streamable-http, url } }``
  * OpenWebUI -> native MCP tool server
  * Claude/IDEs -> any MCP client

A stateless + json_response transport with schemas derived
from the real tool signatures (single source of truth), decoupled from app.py via
the injected ``invoke_tool`` callable. ``invoke_tool`` is given the request-scoped
on-behalf-of token (read here, in the async request context, BEFORE the sync tool
call is threaded) so the Tessera transport can forward it.
"""
from __future__ import annotations

import inspect
import json
import os
import types as _pytypes
import typing
from collections.abc import Callable
from typing import Any

import anyio
import mcp.types as mcp_types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

from .context import get_obo_token
from .tools import TOOLS

MCP_SERVER_NAME = "apple"


def _map_type(hint: Any) -> tuple[dict, bool]:
    """Map a Python type hint to a JSON-schema fragment (optional for X | None)."""
    optional = False
    origin = typing.get_origin(hint)
    if origin in (typing.Union, getattr(_pytypes, "UnionType", ())):
        args = [a for a in typing.get_args(hint) if a is not type(None)]
        optional = len(args) != len(typing.get_args(hint))
        hint = args[0] if args else str
        origin = typing.get_origin(hint)

    if hint is str:
        return {"type": "string"}, optional
    if hint is bool:
        return {"type": "boolean"}, optional
    if hint is int:
        return {"type": "integer"}, optional
    if hint is float:
        return {"type": "number"}, optional
    if origin in (list, set, tuple):
        item_args = typing.get_args(hint)
        item_schema, _ = _map_type(item_args[0]) if item_args else ({"type": "string"}, False)
        return {"type": "array", "items": item_schema}, optional
    return {}, optional  # unknown -> accept anything


def _tool_schema(fn: Callable) -> dict:
    """Build a JSON-schema ``inputSchema`` from a tool's real signature.

    ``service`` is dropped (injected server-side). Params with no default are
    required; keyword params with defaults are optional (default advertised)."""
    try:
        hints = typing.get_type_hints(fn)
    except Exception:
        hints = {}
    props: dict[str, Any] = {}
    required: list[str] = []
    for pname, param in inspect.signature(fn).parameters.items():
        if pname == "service":
            continue
        schema, _optional = _map_type(hints.get(pname, str))
        if param.default is inspect.Parameter.empty:
            required.append(pname)
        elif param.default is not None:
            schema = {**schema, "default": param.default}
        props[pname] = schema
    out: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        out["required"] = required
    return out


def _dns_rebinding_enabled() -> bool:
    # Off by default: reached in-cluster behind a NetworkPolicy where the Host
    # header is the service DNS the default empty allow-list would reject.
    return os.environ.get("APPLE_MCP_DNS_REBINDING_PROTECTION", "false").lower() == "true"


def _render_result(result: Any) -> str:
    """Render a tool result as plain, model-readable TEXT.

    MCP clients vary in how (and whether) they feed a tool's ``structuredContent``
    to the model; a single human-readable text block is the one representation
    every client reliably surfaces. So the MCP surface returns ONLY text — no
    ``structuredContent``/``outputSchema`` (the OpenAPI surface still returns raw
    JSON for programmatic callers). An unknown shape falls back to compact JSON.
    """
    if not isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False, default=str)

    if "events" in result:
        events = result.get("events") or []
        rng = result.get("range") or {}
        head = f"{len(events)} event(s)"
        if rng.get("start") and rng.get("end"):
            head += f" between {rng['start']} and {rng['end']}"
        if not events:
            return head + " — none found."
        lines = [head + ":"]
        for ev in events:
            when = ev.get("start") or "?"
            if ev.get("end") and ev.get("end") != ev.get("start"):
                when += f"–{ev['end']}"
            if ev.get("all_day"):
                when += " (all day)"
            seg = f"- {when} — {ev.get('summary') or '(no title)'}"
            if ev.get("calendar"):
                seg += f" [{ev['calendar']}]"
            if ev.get("location"):
                seg += f" @ {ev['location']}"
            lines.append(seg)
        return "\n".join(lines)

    if "reminders" in result:
        rems = result.get("reminders") or []
        lines = [f"{len(rems)} reminder(s)" + (":" if rems else " — none found.")]
        for rm in rems:
            seg = f"- {rm.get('summary') or '(no title)'}"
            if rm.get("due"):
                seg += f" (due {rm['due']})"
            if rm.get("calendar"):
                seg += f" [{rm['calendar']}]"
            if rm.get("completed"):
                seg += " ✓"
            lines.append(seg)
        out = "\n".join(lines)
        if result.get("note"):
            out += f"\n\nNote: {result['note']}"
        return out

    if "contacts" in result:
        cs = result.get("contacts") or []
        head = f"{len(cs)} contact(s) matching '{result.get('query') or ''}'"
        if not cs:
            return head + " — none found."
        lines = [head + ":"]
        for c in cs:
            seg = f"- {c.get('name') or '(no name)'}"
            if c.get("emails"):
                seg += " — " + ", ".join(c["emails"])
            if c.get("phones"):
                seg += " — " + ", ".join(c["phones"])
            if c.get("org"):
                seg += f" ({c['org']})"
            lines.append(seg)
        return "\n".join(lines)

    if "calendars" in result:
        cals = result.get("calendars") or []
        if not cals:
            return "0 calendar(s) — none found."
        lines = [f"{len(cals)} calendar(s):"]
        for c in cals:
            lines.append(f"- {c.get('name') or '(unnamed)'}")
        return "\n".join(lines)

    return json.dumps(result, ensure_ascii=False, default=str)


def build_session_manager(
    invoke_tool: Callable[[str, dict, str], Any],
    scrub_error: Callable[[Exception], str],
    audit: Callable[..., None],
) -> StreamableHTTPSessionManager:
    """Build the Streamable HTTP session manager exposing ``TOOLS``."""
    server = build_server(invoke_tool, scrub_error, audit)
    return StreamableHTTPSessionManager(
        app=server,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=_dns_rebinding_enabled(),
            allowed_hosts=[
                h for h in os.environ.get("APPLE_MCP_ALLOWED_HOSTS", "").split(",") if h
            ],
            allowed_origins=[
                o for o in os.environ.get("APPLE_MCP_ALLOWED_ORIGINS", "").split(",") if o
            ],
        ),
    )


def build_server(
    invoke_tool: Callable[[str, dict, str], Any],
    scrub_error: Callable[[Exception], str],
    audit: Callable[..., None],
) -> Server:
    """The low-level MCP ``Server`` exposing ``TOOLS`` (transport-agnostic)."""
    server: Server = Server(MCP_SERVER_NAME)

    @server.list_tools()
    async def _list_tools() -> list[mcp_types.Tool]:
        return [
            mcp_types.Tool(
                name=name,
                description=(fn.__doc__ or name).strip(),
                inputSchema=_tool_schema(fn),
            )
            for name, fn in TOOLS.items()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict | None):
        args = arguments or {}
        # Read the request-scoped on-behalf-of token in the ASYNC request context
        # (set by the ASGI layer), then pass it EXPLICITLY into the threaded sync
        # call — contextvars do not reliably propagate across the thread boundary.
        obo = get_obo_token()
        try:
            result = await anyio.to_thread.run_sync(lambda: invoke_tool(name, args, obo))
        except Exception as exc:  # noqa: BLE001 — scrub + re-raise so the SDK marks isError
            audit(name, args, f"mcp_error:{type(exc).__name__}")
            raise RuntimeError(scrub_error(exc)) from None
        # Plain text ONLY (see _render_result): the model reliably reads a text
        # block; structuredContent is delivered inconsistently across clients.
        return [mcp_types.TextContent(type="text", text=_render_result(result))]

    return server
