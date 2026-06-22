"""Tessera-brokered CalDAV transport — apple-mcp's ONLY egress path to iCloud.

The MCP holds **no** Apple secret. Every CalDAV request the ``caldav`` library
builds is rerouted to Tessera's raw egress proxy (``ANY /v1/egress/{target}``,
ADR 0022): Tessera authenticates the caller + the forwarded end-user, injects the
Apple ID + app-specific password as HTTP Basic, strips the caller's identity, and
reverse-proxies the request to an allow-listed, IP-pinned iCloud host. The
app-specific password never reaches this process; the user's token never reaches
Apple.

Per hop this transport attaches three headers and nothing credential-bearing:

  * ``Authorization: Bearer <caller token>`` — the MCP's OWN app-only token
    (Authentik ``client_credentials``; minted + cached by :class:`_CallerToken`).
    Per HL-13 it is minted via the shared librechat M2M client, the only token
    that passes Tessera's single issuer + audience check.
  * ``X-Tessera-On-Behalf-Of: <user token>`` — the signed-in person's forwarded
    OIDC token (from the inbound MCP request). Tessera derives ``onBehalfOf`` ONLY
    from this verified token; the binding ``(apple-caldav, onBehalfOf)`` is the
    sole selector of whose password is injected (confused-deputy defense, HL-2/3).
  * ``X-Tessera-Upstream: <absolute iCloud URL>`` — the destination for this hop,
    re-validated against Tessera's SSRF allow-list before injection.

Tessera keeps ``AllowAutoRedirect=false``; **this transport follows the RFC 6764
partition redirect** (``caldav.icloud.com`` → ``pNN-caldav.icloud.com``) itself
and re-targets Tessera per hop, validating the redirect host against the Apple
partition pattern first (defense in depth with Tessera's own allow-list, HL-4).
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from caldav.davclient import DAVClient, DAVResponse

try:  # caldav's body normaliser; fall back to identity if the internal moves.
    from caldav.lib.utils import to_wire
except Exception:  # pragma: no cover - defensive

    def to_wire(body: Any) -> Any:
        if body is None:
            return b""
        return body.encode("utf-8") if isinstance(body, str) else body


# The iCloud CalDAV/CardDAV root the library discovers from (RFC 6764). The
# request never actually goes here — it is rerouted to Tessera — but it is the
# logical base ``caldav`` uses for URL bookkeeping.
ICLOUD_CALDAV_ROOT = "https://caldav.icloud.com/"

# HTTP redirect status codes the MCP follows itself (Tessera returns the 3xx).
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

# Apple CalDAV/CardDAV hosts the MCP will follow a redirect to. Exact roots plus
# the runtime-discovered partition pattern (RFC 6764). Anchored + case-insensitive
# so ``icloud.com.evil.net`` and ``xpNN-caldav.icloud.com`` are rejected. This
# MIRRORS Tessera's SSRF allow-list entry; Tessera re-validates each hop, so this
# is defense in depth, not the only gate.
_APPLE_EXACT_HOSTS = frozenset({"caldav.icloud.com", "contacts.icloud.com"})
_APPLE_PARTITION_RE = re.compile(r"^p[0-9]{1,3}-(?:caldav|contacts)\.icloud\.com$", re.IGNORECASE)

# The only scheme/port a brokered hop may use. Tessera independently enforces
# https + default-port + the SSRF allow-list (it is the authoritative gate); we
# also pin them here so the FIRST hop is held to the same bar this module's
# docstring promises (defense in depth, not the gate).
_DEFAULT_HTTPS_PORT = 443


class AppleEgressError(Exception):
    """An Apple CalDAV operation could not be brokered.

    Carries a secret-free detail. The app layer is credential-free (Tessera owns
    the Apple password and the caller token is never placed in an error), but
    callers still treat the message as model-facing and keep it terse.
    """


def is_allowed_apple_host(host: str | None) -> bool:
    """True iff ``host`` is an iCloud CalDAV/CardDAV root or partition host.

    Used to validate a redirect ``Location`` before the MCP follows it. The match
    is exact for the roots and anchored for the ``pNN-`` partition pattern.
    """
    if not host:
        return False
    host = host.strip().lower()
    return host in _APPLE_EXACT_HOSTS or bool(_APPLE_PARTITION_RE.match(host))


def _require_brokerable_apple_url(upstream_url: str) -> None:
    """Fail closed unless ``upstream_url`` is https, an allow-listed Apple host, and
    on the scheme's default port.

    Tessera re-validates every hop authoritatively (https + default-port + SSRF
    allow-list); this enforces the same bar on the FIRST hop inside the transport,
    which caldav builds from the base URL and which would otherwise reach Tessera
    unchecked here. Redirect hops are validated separately (``is_allowed_apple_host``
    on each ``Location``). Raises :class:`AppleEgressError` (secret-free) on any miss.
    """
    parts = urllib.parse.urlsplit(upstream_url)
    if parts.scheme != "https":
        raise AppleEgressError(f"refusing non-https upstream scheme '{parts.scheme}'")
    if not is_allowed_apple_host(parts.hostname):
        raise AppleEgressError(f"refusing non-Apple upstream host '{parts.hostname}'")
    try:
        port = parts.port
    except ValueError:
        raise AppleEgressError("refusing upstream with a malformed port") from None
    if port is not None and port != _DEFAULT_HTTPS_PORT:
        raise AppleEgressError(f"refusing non-default upstream port '{port}'")


class _CallerToken:
    """Client-credentials caller token, cached until ~60s before expiry.

    ``POST {token_url}`` form-encoded
    ``grant_type=client_credentials&client_id=..&client_secret=..&scope=..`` ->
    JSON ``{access_token, expires_in}``. The HTTP layer is injectable (``opener``)
    so token minting is exercised offline. The secret + minted token live only on
    the instance and are never logged or placed in an exception.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ):
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._opener = opener
        self._tok = ""
        self._exp = 0.0

    def get(self) -> str:
        """Return a valid caller token, minting a fresh one when near expiry."""
        if self._tok and time.time() < self._exp - 60:
            return self._tok

        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": self._scope,
            }
        ).encode()
        req = urllib.request.Request(
            self._token_url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with self._opener(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:  # pragma: no cover - network
            # Never echo the body: the caller secret was just POSTed; minimise blast radius.
            raise AppleEgressError(f"caller token endpoint HTTP {e.code}") from None
        except urllib.error.URLError as e:  # pragma: no cover - network
            raise AppleEgressError(f"caller token endpoint unreachable: {e.reason}") from None

        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise AppleEgressError("caller token endpoint returned no access_token")
        self._tok = token
        self._exp = time.time() + float(data.get("expires_in", 3600))
        return self._tok


class TesseraCalDAVClient(DAVClient):
    """A ``caldav.DAVClient`` whose every HTTP hop is brokered through Tessera.

    Built with **no** Apple credentials — Tessera injects them. ``caller`` mints
    the MCP's own app-only token; ``on_behalf_of`` is the signed-in person's
    forwarded OIDC token for THIS request (a fresh client is built per tool call,
    so the token is request-scoped and never shared between users).
    """

    def __init__(
        self,
        *,
        egress_url: str,
        target: str,
        caller: _CallerToken,
        on_behalf_of: str,
        timeout: float = 30.0,
        max_redirects: int = 5,
        headers: Mapping[str, str] | None = None,
    ):
        # Base = the logical iCloud root; no username/password/auth (Tessera owns
        # the credential). enable_rfc6764=False is SECURITY-RELEVANT: caldav's
        # RFC 6764 SRV/well-known bootstrap resolves DNS itself (dnspython),
        # bypassing our overridden request() — i.e. egress that does NOT go through
        # Tessera. We disable it and instead point at the iCloud root and follow the
        # partition redirect through Tessera ourselves, so EVERY hop is brokered.
        super().__init__(
            url=ICLOUD_CALDAV_ROOT,
            headers=dict(headers or {}),
            timeout=timeout,
            enable_rfc6764=False,
        )
        self._egress_endpoint = f"{egress_url.rstrip('/')}/v1/egress/{target}"
        self._caller = caller
        self._obo = on_behalf_of
        self._max_redirects = max(0, int(max_redirects))

    # -- the single brokered hop (pure; unit-tested) --------------------------
    def _tessera_request(
        self, upstream_url: str, method: str, body: Any, headers: Mapping[str, str]
    ):
        """Issue ONE brokered hop to Tessera (no redirect following).

        Sends ``method`` + ``body`` to Tessera's egress endpoint with the caller
        token, the forwarded end-user token, and the real iCloud destination in
        ``X-Tessera-Upstream``. Redirects are disabled so the caller can inspect a
        3xx and re-target. Returns the raw HTTP response.
        """
        out = dict(headers or {})
        out["Authorization"] = f"Bearer {self._caller.get()}"
        out["X-Tessera-On-Behalf-Of"] = self._obo
        out["X-Tessera-Upstream"] = upstream_url
        return self.session.request(
            method,
            self._egress_endpoint,
            data=to_wire(body),
            headers=out,
            allow_redirects=False,
            timeout=self.timeout,
        )

    # -- follow Apple partition redirects ourselves (pure; unit-tested) -------
    def _brokered(self, upstream_url: str, method: str, body: Any, headers: Mapping[str, str]):
        """Broker the hop, following RFC 6764 partition redirects with host checks.

        Returns ``(response, final_upstream_url)``. A redirect to a non-Apple host
        is refused (defense in depth with Tessera's own SSRF allow-list).
        """
        # Validate the FIRST hop (https + Apple host + default port) before we
        # broker it. Redirect targets are validated inside the loop, as before.
        _require_brokerable_apple_url(upstream_url)
        for _ in range(self._max_redirects + 1):
            resp = self._tessera_request(upstream_url, method, body, headers)
            if resp.status_code in _REDIRECT_CODES:
                location = resp.headers.get("Location")
                if not location:
                    return resp, upstream_url
                target = urllib.parse.urljoin(upstream_url, location)
                host = urllib.parse.urlsplit(target).hostname
                if not is_allowed_apple_host(host):
                    raise AppleEgressError(
                        f"refusing redirect to non-Apple host '{host}' (RFC 6764 discovery)"
                    )
                upstream_url = target
                continue
            return resp, upstream_url
        raise AppleEgressError("too many CalDAV partition redirects")

    # -- raw brokered DAV (for CardDAV, which caldav doesn't model) ------------
    def brokered_dav(
        self,
        url: str,
        method: str,
        body: str = "",
        headers: Mapping[str, str] | None = None,
    ):
        """Issue a raw brokered DAV hop to an ABSOLUTE iCloud URL; return the raw
        HTTP response. The ``caldav`` library models CalDAV only, so CardDAV
        (Contacts) drives this directly — same Tessera brokering, partition-
        redirect following, and Apple-host validation as every other hop.
        """
        resp, _final = self._brokered(url, method, body, dict(headers or {}))
        return resp

    # -- caldav's single HTTP choke point -------------------------------------
    def request(
        self,
        url: str,
        method: str = "GET",
        body: str = "",
        headers: Mapping[str, str] | None = None,
        rate_limit_time_slept: int = 0,
    ) -> DAVResponse:
        """Reroute caldav's request through Tessera and wrap the response.

        ``caldav`` resolves ``url`` against the iCloud base + merges headers via
        ``_prepare_request``; we then broker the resulting absolute iCloud URL
        through Tessera (following partition redirects), label the response with
        the final iCloud URL so caldav resolves hrefs correctly, and hand it back
        as a normal :class:`DAVResponse`.
        """
        url_obj, combined_headers = self._prepare_request(url, method, body, headers)
        # Tessera requires an ABSOLUTE X-Tessera-Upstream. caldav may hand us a
        # base-relative path (e.g. "/123/calendars/"), so resolve it against the
        # iCloud root; an already-absolute URL (incl. a pNN partition host the
        # client learned from a prior hop's labelled response) passes through.
        upstream = urllib.parse.urljoin(ICLOUD_CALDAV_ROOT, str(url_obj))
        resp, final_url = self._brokered(upstream, method, body, combined_headers)
        try:
            resp.url = final_url  # so caldav resolves relative hrefs against iCloud, not Tessera
        except Exception:  # pragma: no cover - some HTTP libs make .url read-only
            pass
        return DAVResponse(resp, self)
