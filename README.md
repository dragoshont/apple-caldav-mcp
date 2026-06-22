# apple-caldav-mcp

A **credential-free** MCP server for **Apple iCloud Calendar, Reminders + Contacts** (CalDAV + CardDAV).
It holds **no** Apple secret. Every iCloud request is brokered through
[Tessera](https://github.com/dragoshont/tessera), which injects the
Apple ID + app-specific password (HTTP Basic) and returns only the result — the
credential never reaches this process.

> Unofficial; not affiliated with Apple. Read-first — calendar writes are opt-in (off by default).

## What it does

Four **read** tools plus one **opt-in write** tool, exposed over the native
**MCP Streamable HTTP** transport (`/mcp`) and as OpenAPI `POST` routes:

| Tool | Args | Returns |
|------|------|---------|
| `list_calendars` | — | the signed-in person's iCloud calendars (name + id) |
| `list_events` | `start?`, `end?` (ISO date/datetime; default today..+7d) | event metadata (summary, start, end, location, calendar, uid) |
| `list_reminders` | `include_completed?` (default false) | reminder (VTODO) metadata (summary, due, status, completed, priority, calendar, uid) — never notes |
| `find_contacts` | `query` (≥2 chars), `limit?` (default 10, max 25) | **search** of the address book (CardDAV): matched contacts' name, a few emails/phones, org — never photos, notes or postal addresses |
| `create_event` | `summary`, `start`, `end`, `location?`, `calendar?` | writes a calendar event (returns `status="created"`); **only exposed when `APPLE_MCP_ENABLE_WRITES` is set** — see **Writes** below |

### Writes (opt-in, off by default)

`create_event` is the only mutation, and it is **absent from the surface unless
`APPLE_MCP_ENABLE_WRITES` is set** — so by default this is a read-only server and a
prompt-injected model cannot reach a write at all. Even when enabled the write is
authorized **server-side by Tessera, never here**: the `manage:dav` plane is denied
without a write grant for the `(caller, on-behalf-of)` pair, and if the grant maps the
write to step-up, Tessera **holds it for the person's out-of-band approval** (ADR 0023) —
returning `status="pending_approval"` until they approve in the Tessera portal, then
completing the identical request. With a straight-through grant it returns
`status="created"`. The MCP only builds a deterministic VEVENT and forwards; it makes no
authorization decision.

> **iCloud Reminders limitation.** Apple does not expose *upgraded* Reminders
> lists over CalDAV. Once a list is upgraded to the new Reminders format it stops
> syncing over CalDAV (you trade open-protocol access for new app features), so
> `list_reminders` can only read *non-upgraded* lists and reports any upgraded
> ones via a `note`. Reading upgraded reminders requires a native Apple (EventKit)
> path. See [python-caldav#3](https://github.com/python-caldav/caldav/issues/3).

## Use it

**Prerequisite — a running [Tessera](https://github.com/dragoshont/tessera)** that, for this
target, has: an `apple-caldav` egress recipe, a grant `(caller, on-behalf-of) → read:dav`
(add `manage:dav` to allow writes), and a binding `(apple-caldav, on-behalf-of) → <KV secret>`
whose bundle is `{"access_token": "<app-specific password>", "extra": {"username": "<Apple ID>"}}`.
This MCP holds none of that — it only forwards.

**Run it** (the image is published to GHCR by CI):

```bash
docker run --rm -p 8080:8080 \
  -e TESSERA_EGRESS_URL=http://tessera:8080 \
  -e TESSERA_TOKEN_URL=https://<your-idp>/application/o/token/ \
  -e TESSERA_CALLER_CLIENT_ID=<shared M2M client id> \
  -e TESSERA_CALLER_CLIENT_SECRET=<from your secret store> \
  ghcr.io/dragoshont/apple-caldav-mcp
# append  -e APPLE_MCP_ENABLE_WRITES=1  to expose create_event
```

**Wire it into an MCP client** (e.g. LibreChat `librechat.yaml`) at the **canonical
`/mcp/` URL — keep the trailing slash** (a bare `/mcp` 307-redirects and destabilises the
transport):

```yaml
mcpServers:
  apple:
    type: streamable-http
    url: http://apple-caldav-mcp:8080/mcp/
    headers:
      Authorization: "Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}"
```

Then ask in plain language — *"what's on my calendar this week?"* or (writes enabled)
*"add 'Dentist' tomorrow 9–10"*. The model picks the tool; Tessera resolves **whose**
calendar from the forwarded identity.

## How the brokering works

```
LibreChat ──Bearer <user OIDC token>──▶ apple-caldav-mcp ──┐  (holds NO Apple secret)
                                                     │  mints its OWN app-only
                                                     │  caller token; forwards
                                                     ▼  the user token
                          Tessera  ANY /v1/egress/apple-caldav
                            • authenticates caller + on-behalf-of (verified token)
                            • PDP: read:dav (reads) / manage:dav (writes) grant for (caller, onBehalfOf)
                            • resolves binding (apple-caldav, onBehalfOf) → KV bundle
                            • injects HTTP Basic (Apple ID + app-specific password)
                            • strips identity headers, IP-pins, allow-lists the host
                            ▼
                          iCloud  caldav.icloud.com → pNN-caldav.icloud.com
```

`caldav` (RFC 4791) builds the requests; the transport
([`tessera_caldav.py`](src/apple_mcp/tessera_caldav.py)) reroutes every hop to
Tessera and **follows the RFC 6764 partition redirect itself** (Tessera keeps
`AllowAutoRedirect=false`), re-targeting Tessera per hop and validating the
redirect host against the Apple partition pattern first (defense in depth with
Tessera's own SSRF allow-list). caldav's own RFC 6764 SRV/DNS bootstrap is
**disabled** so no egress bypasses the broker.

Per hop the transport attaches exactly three non-credential headers:
`Authorization: Bearer <caller token>`, `X-Tessera-On-Behalf-Of: <user token>`,
`X-Tessera-Upstream: <iCloud URL>`.

## Configuration (env)

| Var | Meaning |
|-----|---------|
| `TESSERA_EGRESS_URL` | Tessera base URL; the MCP POSTs to `{url}/v1/egress/{target}` |
| `TESSERA_TARGET` | proxy target name (default `apple-caldav`) |
| `TESSERA_TOKEN_URL` | Authentik client-credentials token endpoint |
| `TESSERA_CALLER_CLIENT_ID` | the MCP's caller client id (the grant's `caller`/`azp`) |
| `TESSERA_CALLER_CLIENT_SECRET` | the caller client secret (from Key Vault via ESO) |
| `TESSERA_CALLER_SCOPE` | OAuth scope (default `openid tessera_caller` → `idtyp=app`) |
| `APPLE_MCP_HTTP_PORT` | listen port (default 8080) |
| `APPLE_MCP_ENABLE_WRITES` | set to expose the `create_event` write tool (default off → read-only surface) |

Tessera validates a **single** issuer + audience, so the
caller token is minted via a shared Authentik M2M client (e.g. your chat app's —
the only token that passes), the same caller every brokered MCP uses. The MCP is
**identity-agnostic**: it forwards the user token; Tessera's per-user
binding decides whose calendar is read. Per-user exposure is gated by LibreChat's
`MCP_USER_GATE`.

## Develop / test

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q          # offline: no network, no Apple call, no secrets
ruff check src tests
```

The tests cover the security-relevant **request construction**: the egress URL +
the three identity headers, the partition-redirect following + host validation,
the redirect cap, and the caller-token mint/cache — all mockable, no live Apple
call. The end-to-end "what's on my calendar?" proof is the operator-gated egress
flip (real iCloud), not an offline test.
