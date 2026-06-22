"""Offline tests for the Tessera-brokered CalDAV transport (no network, no secrets).

Recording fakes stand in for the HTTP session and the token endpoint, so the
request construction (the right egress URL + the three identity headers), the
RFC 6764 partition-redirect following with host validation, the redirect cap, and
the caller-token mint/cache are verified WITHOUT touching Tessera, Authentik, or
Apple — exactly the unit the prompt asks for ("CalDAV request construction,
mockable, no live Apple call").
"""
from __future__ import annotations

import io
import json

import pytest

from apple_mcp.tessera_caldav import (
    AppleEgressError,
    TesseraCalDAVClient,
    _CallerToken,
    is_allowed_apple_host,
)


# ── fakes ────────────────────────────────────────────────────────────────────
class _FakeResp:
    """Minimal HTTP response: status + headers (.get) + a settable .url."""

    def __init__(self, status_code: int, headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}
        self.url = None


class _RecordingSession:
    """Stand-in for caldav's niquests session: records calls, serves canned responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


class _StubToken:
    """A caller-token stub returning a fixed value."""

    def __init__(self, value="caller-tok"):
        self.value = value

    def get(self) -> str:
        return self.value


def _client(
    session, *, obo="user-tok", caller="caller-tok", max_redirects=5
) -> TesseraCalDAVClient:
    c = TesseraCalDAVClient(
        egress_url="http://tessera.default.svc.cluster.local:8080",
        target="apple-caldav",
        caller=_StubToken(caller),
        on_behalf_of=obo,
        max_redirects=max_redirects,
    )
    c.session = session  # swap caldav's real niquests session for the recorder
    return c


class _Resp(io.BytesIO):
    """urlopen-style context manager carrying a ``.status`` (for the token opener)."""

    def __init__(self, body, status=200):
        super().__init__(body if isinstance(body, bytes) else body.encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _ok_opener(record, body):
    text = body if isinstance(body, str) else json.dumps(body)

    def opener(req, timeout=30):
        record.append(req)
        return _Resp(text, 200)

    return opener


# ── host allow-list (defense in depth with Tessera's SSRF guard) ─────────────
@pytest.mark.parametrize(
    "host,ok",
    [
        ("caldav.icloud.com", True),
        ("contacts.icloud.com", True),
        ("p52-caldav.icloud.com", True),
        ("p1-contacts.icloud.com", True),
        ("p999-caldav.icloud.com", True),
        ("P52-CALDAV.ICLOUD.COM", True),  # case-insensitive
        ("icloud.com", False),
        ("evil.icloud.com", False),
        ("caldav.icloud.com.evil.net", False),  # anchored: no suffix attack
        ("xp52-caldav.icloud.com", False),  # anchored: no prefix attack
        ("p52-mail.icloud.com", False),  # only caldav/contacts partitions
        ("p1234-caldav.icloud.com", False),  # \d{1,3} only
        ("", False),
        (None, False),
    ],
)
def test_is_allowed_apple_host(host, ok):
    assert is_allowed_apple_host(host) is ok


# ── the single brokered hop: URL + identity headers ──────────────────────────
def test_tessera_request_builds_egress_call_with_identity_headers():
    sess = _RecordingSession([_FakeResp(207)])
    c = _client(sess)
    c._tessera_request(
        "https://caldav.icloud.com/123/calendars/", "PROPFIND", "<propfind/>", {"Depth": "1"}
    )
    assert len(sess.calls) == 1
    call = sess.calls[0]
    assert call["url"] == "http://tessera.default.svc.cluster.local:8080/v1/egress/apple-caldav"
    assert call["method"] == "PROPFIND"
    h = call["headers"]
    assert h["Authorization"] == "Bearer caller-tok"
    assert h["X-Tessera-On-Behalf-Of"] == "user-tok"
    assert h["X-Tessera-Upstream"] == "https://caldav.icloud.com/123/calendars/"
    assert h["Depth"] == "1"  # caller (caldav) headers are preserved
    assert call["allow_redirects"] is False  # Tessera returns 3xx; the MCP follows


def test_tessera_request_never_sends_basic_or_cookie():
    # The MCP holds no Apple secret: it must not inject Basic/Cookie — Tessera does.
    sess = _RecordingSession([_FakeResp(207)])
    c = _client(sess)
    c._tessera_request("https://caldav.icloud.com/", "PROPFIND", "", {})
    h = sess.calls[0]["headers"]
    assert h["Authorization"].startswith("Bearer ")  # the caller token, not Basic
    assert "Cookie" not in h


# ── RFC 6764 partition-redirect following ────────────────────────────────────
def test_brokered_follows_apple_partition_redirect_and_retargets():
    sess = _RecordingSession(
        [
            _FakeResp(301, {"Location": "https://p52-caldav.icloud.com/123/principal/"}),
            _FakeResp(207),
        ]
    )
    c = _client(sess)
    resp, final = c._brokered("https://caldav.icloud.com/", "PROPFIND", "", {})
    assert resp.status_code == 207
    assert final == "https://p52-caldav.icloud.com/123/principal/"
    assert len(sess.calls) == 2
    # each hop is re-targeted through Tessera with the new upstream
    assert sess.calls[0]["headers"]["X-Tessera-Upstream"] == "https://caldav.icloud.com/"
    assert (
        sess.calls[1]["headers"]["X-Tessera-Upstream"]
        == "https://p52-caldav.icloud.com/123/principal/"
    )


def test_brokered_resolves_relative_redirect_location():
    sess = _RecordingSession(
        [
            _FakeResp(302, {"Location": "/456/principal/"}),  # relative
            _FakeResp(207),
        ]
    )
    c = _client(sess)
    _resp, final = c._brokered("https://caldav.icloud.com/", "PROPFIND", "", {})
    assert final == "https://caldav.icloud.com/456/principal/"


def test_brokered_refuses_redirect_off_apple():
    sess = _RecordingSession([_FakeResp(302, {"Location": "https://evil.example.com/x"})])
    c = _client(sess)
    with pytest.raises(AppleEgressError):
        c._brokered("https://caldav.icloud.com/", "PROPFIND", "", {})
    assert len(sess.calls) == 1  # the off-allow-list redirect was NOT followed


def test_brokered_caps_redirects():
    resps = [
        _FakeResp(301, {"Location": "https://p1-caldav.icloud.com/a/"}) for _ in range(10)
    ]
    c = _client(_RecordingSession(resps), max_redirects=2)
    with pytest.raises(AppleEgressError):
        c._brokered("https://caldav.icloud.com/", "PROPFIND", "", {})


def test_brokered_returns_non_redirect_directly():
    sess = _RecordingSession([_FakeResp(207)])
    c = _client(sess)
    resp, final = c._brokered("https://caldav.icloud.com/", "REPORT", "<x/>", {})
    assert resp.status_code == 207
    assert final == "https://caldav.icloud.com/"
    assert len(sess.calls) == 1


# ── caller token: mint + cache ───────────────────────────────────────────────
def test_caller_token_mints_and_caches():
    record = []
    tok = _CallerToken(
        "https://auth.example/token",
        "test-caller-id",
        "secret",
        "openid tessera_caller",
        opener=_ok_opener(record, {"access_token": "tok-1", "expires_in": 3600}),
    )
    assert tok.get() == "tok-1"
    assert tok.get() == "tok-1"  # cached -> one mint
    assert len(record) == 1
    body = record[0].data.decode()
    assert "grant_type=client_credentials" in body
    assert "client_id=test-caller-id" in body
    assert "client_secret=secret" in body
    assert "scope=openid+tessera_caller" in body  # urlencoded space


def test_caller_token_missing_access_token_raises():
    tok = _CallerToken(
        "https://auth.example/token",
        "c",
        "s",
        "sc",
        opener=_ok_opener([], {"error": "invalid_client"}),
    )
    with pytest.raises(AppleEgressError):
        tok.get()


# ── request(): caldav's choke point composes prepare -> broker -> wrap ────────
def test_request_resolves_relative_url_brokers_and_labels_response(monkeypatch):
    import apple_mcp.tessera_caldav as tc

    captured: dict = {}

    class _StubDAVResponse:
        def __init__(self, response, client):
            captured["response"] = response
            captured["client"] = client

    # Stub caldav's DAVResponse so the test exercises OUR composition, not caldav's
    # XML parser (no live multistatus body needed).
    monkeypatch.setattr(tc, "DAVResponse", _StubDAVResponse)

    sess = _RecordingSession([_FakeResp(207)])
    c = _client(sess)
    out = c.request("/123/calendars/", "PROPFIND", "<propfind/>", {"Depth": "1"})

    # caldav resolved the relative path against the iCloud base; we brokered THAT.
    upstream = sess.calls[0]["headers"]["X-Tessera-Upstream"]
    assert upstream == "https://caldav.icloud.com/123/calendars/"
    assert isinstance(out, _StubDAVResponse)
    # the wrapped response is labelled with the final iCloud URL so caldav resolves
    # relative hrefs against iCloud, not Tessera.
    assert captured["response"].url == "https://caldav.icloud.com/123/calendars/"


# ── MINOR-3: the FIRST hop is validated (host + https + default port) ─────────
def test_brokered_validates_first_hop_not_just_redirects():
    """The first brokered hop must be https, an Apple host, and on the default port
    — not only redirects. Tessera re-checks authoritatively; this keeps the
    transport honest with its docstring (defense in depth)."""
    for bad in (
        "http://caldav.icloud.com/",          # non-https downgrade
        "https://evil.example.com/",          # non-Apple host
        "https://caldav.icloud.com:8443/",    # non-default port
    ):
        sess = _RecordingSession([_FakeResp(207)])
        c = _client(sess)
        with pytest.raises(AppleEgressError):
            c._brokered(bad, "PROPFIND", "", {})
        assert sess.calls == []  # nothing was brokered upstream


# ── MINOR-4 (1): the scrub strips a caller secret + an OBO token from errors ──
def test_error_scrub_removes_caller_secret_and_obo_token():
    """Defense in depth: even if a credential-shaped string reaches an error/log
    path, the scrub strips it, so it can never surface in an AppleEgressError
    detail or a log line. Covers the caller token (Bearer), the injected Basic, a
    bare on-behalf-of JWT, and a client_secret form."""
    from apple_mcp.app import _safe_detail, _scrub

    obo_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkcmFnb3MifQ.s3cr3t-signature_A1"
    leaky = (
        "broker said no -- Authorization: Bearer caller-tok-ABC123xyz "
        "Authorization: Basic dXNlcjphcHAtc3BlY2lmaWMtcHc= "
        f"X-Tessera-On-Behalf-Of: {obo_jwt} "
        "client_secret=s3cr3t-fake-value-XYZ"
    )
    scrubbed = _safe_detail(AppleEgressError(leaky))
    assert "caller-tok-ABC123xyz" not in scrubbed
    assert "dXNlcjphcHAtc3BlY2lmaWMtcHc=" not in scrubbed
    assert obo_jwt not in scrubbed
    assert "s3cr3t-fake-value-XYZ" not in scrubbed
    assert "[redacted]" in scrubbed
    # _scrub is the same guard the log path uses.
    assert "caller-tok-ABC123xyz" not in _scrub(leaky)
    assert obo_jwt not in _scrub(leaky)


# ── MINOR-4 (2): RFC 6764 auto-discovery is disabled (no direct-to-iCloud) ────
def test_caldav_client_disables_rfc6764_autodiscovery(monkeypatch):
    """enable_rfc6764=False is load-bearing: caldav's RFC 6764 SRV/well-known
    bootstrap resolves DNS itself and would egress to iCloud WITHOUT going through
    Tessera. Assert the client is always built with it disabled and pinned to the
    iCloud root (never auto-discovered)."""
    import apple_mcp.tessera_caldav as tc

    captured: dict = {}

    def _spy_init(self, *args, **kwargs):
        captured.update(kwargs)  # record only; don't run caldav's real init

    monkeypatch.setattr(tc.DAVClient, "__init__", _spy_init)
    tc.TesseraCalDAVClient(
        egress_url="http://tessera.default.svc.cluster.local:8080",
        target="apple-caldav",
        caller=_StubToken(),
        on_behalf_of="user-tok",
    )
    assert captured.get("enable_rfc6764") is False
    assert captured.get("url") == tc.ICLOUD_CALDAV_ROOT


# ── MINOR-4 (3): on-behalf-of is request-scoped — no cross-user bleed ─────────
def test_obo_is_request_scoped_no_cross_user_bleed(monkeypatch):
    """Each tool call builds a FRESH service bound to THAT request's on-behalf-of
    token (threaded explicitly, never via shared/contextvar state). Two users get
    their OWN X-Tessera-On-Behalf-Of; a missing OBO fails closed (empty, never
    another user's token)."""
    import apple_mcp.app as app_mod

    # Minimal env so _get_caller() can build the caller object (no network — the
    # probe tool below never mints a token).
    monkeypatch.setenv("TESSERA_EGRESS_URL", "http://tessera.default.svc.cluster.local:8080")
    monkeypatch.setenv("TESSERA_TOKEN_URL", "https://auth.example/token")
    monkeypatch.setenv("TESSERA_CALLER_CLIENT_ID", "test-caller-id")
    monkeypatch.setenv("TESSERA_CALLER_CLIENT_SECRET", "secret")
    monkeypatch.setattr(app_mod, "_caller", None)  # reset the cached caller

    # A probe tool that reports the OBO the per-request transport would forward.
    def _probe(service):
        return {"obo": service._client._obo}

    monkeypatch.setattr(app_mod, "TOOLS", {"probe": _probe})

    assert app_mod._invoke_tool("probe", {}, "tok-alice")["obo"] == "tok-alice"
    assert app_mod._invoke_tool("probe", {}, "tok-bob")["obo"] == "tok-bob"
    # interleave: a prior user's token must not carry over via any shared state.
    assert app_mod._invoke_tool("probe", {}, "tok-alice")["obo"] == "tok-alice"
    # missing OBO fails closed: empty, NEVER another user's token.
    assert app_mod._invoke_tool("probe", {}, "")["obo"] == ""

