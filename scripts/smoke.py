#!/usr/bin/env python3
"""In-cluster smoke test for apple-caldav-mcp — drives the SAME streamable-HTTP
MCP transport LibreChat uses, against the live server, using the diag-captured
on-behalf-of token.

Why this exists
---------------
The calendar "the model says it can't see my events" bug was never a format bug:
the MCP + transport always delivered a correct result. The liability was LATENCY
(a sequential per-calendar fan-out took ~10s and raced the chat). This harness
turns verification into a fast, repeatable command so a single real chat message
(which refreshes ``/tmp/apple-mcp-diag-obo`` when ``APPLE_MCP_DIAG=1``) can gate
MANY automated checks — no more manual chat testing per iteration.

For every tool it asserts, over the real Tessera->iCloud path:
  * the call does not error (``isError`` is false),
  * the model-facing text content is non-empty,
  * the round-trip stays under a latency budget (the thing that regressed).

Usage (inside the pod; requires APPLE_MCP_DIAG=1 and one prior real chat):
    kubectl -n default exec -i deploy/apple-caldav-mcp -- python3 - < scripts/smoke.py
or copy it in and run ``python3 /tmp/smoke.py``. Exit code 0 = all green.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ.get("SMOKE_URL", "http://localhost:8080/mcp/")
OBO_PATH = os.environ.get("SMOKE_OBO", "/tmp/apple-mcp-diag-obo")
# Per-tool wall-clock budget. Post-parallelization a cold call is ~3-4s (principal
# discovery + one parallel REPORT wave); 7s catches a regression toward the old
# ~10s without being flaky on a slow iCloud round trip.
BUDGET_S = float(os.environ.get("SMOKE_BUDGET_S", "7.0"))

# (tool, args). Read-only probes only. find_contacts needs >=2 chars; "zq" is a
# cheap, least-disclosure query (exercises the CardDAV round trip, matches ~nothing).
CASES: list[tuple[str, dict]] = [
    ("list_calendars", {}),
    ("list_events", {}),
    ("list_reminders", {}),
    ("find_contacts", {"query": "zq"}),
]


def _load_obo() -> str | None:
    try:
        tok = Path(OBO_PATH).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return tok or None


async def _run() -> int:
    tok = _load_obo()
    if not tok:
        print(
            f"FAIL: no OBO token at {OBO_PATH}. Set APPLE_MCP_DIAG=1 and send one "
            "real apple chat message to capture a fresh token, then re-run.",
            file=sys.stderr,
        )
        return 2

    headers = {"Authorization": f"Bearer {tok}"}
    failures = 0
    results: list[tuple[str, float, bool, str]] = []

    try:
        async with streamablehttp_client(URL, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for name, args in CASES:
                    t0 = time.time()
                    try:
                        res = await session.call_tool(name, args)
                    except Exception as exc:  # noqa: BLE001 — report, don't abort the suite
                        msg = f"EXC {type(exc).__name__}: {exc}"
                        results.append((name, time.time() - t0, False, msg))
                        failures += 1
                        continue
                    dt = time.time() - t0
                    text = res.content[0].text if res.content else ""
                    ok = (not res.isError) and bool(text) and dt <= BUDGET_S
                    if not ok:
                        failures += 1
                    flags = []
                    if res.isError:
                        flags.append("isError")
                    if not text:
                        flags.append("empty")
                    if dt > BUDGET_S:
                        flags.append(f">{BUDGET_S:g}s")
                    note = " ".join(flags) or repr(text[:60])
                    results.append((name, dt, ok, note))
    except Exception as exc:  # noqa: BLE001 — connection/handshake failure is a suite failure
        print(f"FAIL: transport/handshake error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    width = max(len(n) for n, *_ in results)
    for name, dt, ok, note in results:
        print(f"{'OK  ' if ok else 'FAIL'} {name:<{width}}  {dt:5.1f}s  {note}")
    total = len(results)
    print(f"\n{'PASS' if failures == 0 else 'FAIL'}: {total - failures}/{total} tools ok "
          f"(budget {BUDGET_S:g}s)")
    return 0 if failures == 0 else 1


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())
