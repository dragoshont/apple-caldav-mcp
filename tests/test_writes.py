"""Tests for the gated calendar WRITE tool (create_event) and its out-of-band approval flow.

create_event is exposed only when APPLE_MCP_ENABLE_WRITES is set, and a write is HELD by
Tessera for the person's out-of-band approval (ADR 0023). The MCP's job is to build a
DETERMINISTIC request so the held attempt and the post-approval re-request are byte-identical
(the body Tessera's approval is bound to), and to map the brokered response honestly.
"""
from __future__ import annotations

import datetime as _dt
import importlib

import pytest

from apple_mcp.service import AppleCalendarService, _build_vevent, _deterministic_uid
from apple_mcp.tessera_caldav import AppleEgressError, _CallerToken


class _FakeResp:
    def __init__(self, status: int, payload: dict | None = None):
        self.status_code = status
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class _FakeCal:
    url = "https://p99-caldav.icloud.com/123/calendars/home/"

    def get_display_name(self) -> str:
        return "Hont"


def _service() -> AppleCalendarService:
    return AppleCalendarService(
        egress_url="http://t",
        target="apple-caldav",
        caller=_CallerToken("http://t/token", "id", "sec", "scope"),
        on_behalf_of="tok",
    )


def test_writes_disabled_by_default(monkeypatch):
    monkeypatch.delenv("APPLE_MCP_ENABLE_WRITES", raising=False)
    from apple_mcp.settings import writes_enabled

    assert writes_enabled() is False


def test_writes_enabled_flag(monkeypatch):
    monkeypatch.setenv("APPLE_MCP_ENABLE_WRITES", "true")
    from apple_mcp.settings import writes_enabled

    assert writes_enabled() is True


def test_create_event_tool_is_gated_by_the_flag(monkeypatch):
    from apple_mcp import tools

    monkeypatch.delenv("APPLE_MCP_ENABLE_WRITES", raising=False)
    importlib.reload(tools)
    assert "create_event" not in tools.TOOLS  # invisible by default

    monkeypatch.setenv("APPLE_MCP_ENABLE_WRITES", "1")
    importlib.reload(tools)
    assert "create_event" in tools.TOOLS  # exposed only when enabled

    monkeypatch.delenv("APPLE_MCP_ENABLE_WRITES", raising=False)
    importlib.reload(tools)  # restore the default surface for other tests


def test_vevent_and_uid_are_deterministic():
    s = _dt.datetime(2026, 6, 25, 15, 0, tzinfo=_dt.UTC)
    e = _dt.datetime(2026, 6, 25, 16, 0, tzinfo=_dt.UTC)
    uid = _deterministic_uid("Hont", "Dentist", s, e)
    a = _build_vevent(uid, "Dentist", s, e, None)
    b = _build_vevent(uid, "Dentist", s, e, None)
    assert a == b  # byte-identical (no wall-clock fields)
    assert uid.encode() in a
    assert b"Dentist" in a
    assert _deterministic_uid("Hont", "Dentist", s, e) == uid  # stable for the same content


def test_create_event_held_then_created_is_deterministic(monkeypatch):
    svc = _service()
    monkeypatch.setattr(svc, "_calendars", lambda: [_FakeCal()])
    captured: dict = {}

    def held(url, method, body, headers):
        captured.update(url=url, method=method, body=body, headers=headers)
        return _FakeResp(
            409,
            {"challenge": "abc123", "approveAt": "/portal", "expiresAt": "2026-06-21T20:00:00Z"},
        )

    monkeypatch.setattr(svc._client, "brokered_dav", held)
    out = svc.create_event(
        summary="Dentist",
        start="2026-06-25T15:00:00+03:00",
        end="2026-06-25T16:00:00+03:00",
        calendar="Hont",
    )
    assert out["status"] == "pending_approval"
    assert out["challenge"] == "abc123"
    assert out["approve_at"] == "/portal"
    assert captured["method"] == "PUT"
    assert captured["url"].startswith("https://p99-caldav.icloud.com/123/calendars/home/")
    assert captured["url"].endswith(".ics")
    assert captured["headers"]["X-Tessera-Write-Summary"].startswith("Create event 'Dentist'")

    def created(url, method, body, headers):
        captured["body2"] = body
        return _FakeResp(201)

    monkeypatch.setattr(svc._client, "brokered_dav", created)
    out2 = svc.create_event(
        summary="Dentist",
        start="2026-06-25T15:00:00+03:00",
        end="2026-06-25T16:00:00+03:00",
        calendar="Hont",
    )
    assert out2["status"] == "created"
    assert out2["uid"] == out["uid"]  # deterministic UID across attempts
    assert captured["body2"] == captured["body"]  # byte-identical body -> same Tessera content hash


def test_create_event_without_grant_reports_writes_not_enabled(monkeypatch):
    svc = _service()
    monkeypatch.setattr(svc, "_calendars", lambda: [_FakeCal()])

    def denied(*args, **kwargs):
        return _FakeResp(403, {"error": "denied"})

    monkeypatch.setattr(svc._client, "brokered_dav", denied)
    out = svc.create_event(summary="X", start="2026-06-25", end="2026-06-26")
    assert out["status"] == "writes_not_enabled"


def test_create_event_rejects_unknown_calendar(monkeypatch):
    svc = _service()
    monkeypatch.setattr(svc, "_calendars", lambda: [_FakeCal()])
    with pytest.raises(AppleEgressError):
        svc.create_event(summary="X", start="2026-06-25", end="2026-06-26", calendar="Nope")


def test_create_event_rejects_end_before_start(monkeypatch):
    svc = _service()
    monkeypatch.setattr(svc, "_calendars", lambda: [_FakeCal()])
    with pytest.raises(AppleEgressError):
        svc.create_event(summary="X", start="2026-06-26", end="2026-06-25")
