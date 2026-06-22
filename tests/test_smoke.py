"""Smoke tests: the tool surface is read-only and the schemas are clean."""
from __future__ import annotations

from apple_mcp.mcp_streamable import _render_result, _tool_schema
from apple_mcp.tools import TOOLS


def test_read_only_tool_surface():
    assert set(TOOLS) == {"list_calendars", "list_events", "list_reminders", "find_contacts"}


def test_no_write_tools_by_construction():
    # Read-only by construction: no mutation tool exists in the surface at all.
    forbidden = ("create", "update", "delete", "complete", "remove", "move")
    for name in TOOLS:
        assert not any(w in name for w in forbidden)


def test_list_events_schema_drops_injected_service_and_advertises_range():
    schema = _tool_schema(TOOLS["list_events"])
    assert "service" not in schema["properties"]
    assert set(schema["properties"]) == {"start", "end"}
    assert schema["additionalProperties"] is False


def test_list_calendars_takes_no_user_args():
    schema = _tool_schema(TOOLS["list_calendars"])
    assert schema["properties"] == {}


def test_find_contacts_requires_a_query_arg():
    schema = _tool_schema(TOOLS["find_contacts"])
    assert "service" not in schema["properties"]
    assert set(schema["properties"]) == {"query", "limit"}
    assert schema.get("required") == ["query"]


def test_healthz_reports_credential_free():
    from apple_mcp.app import healthz

    body = healthz()
    assert body["ok"] is True
    assert body["credential_free"] is True


def test_render_events_is_readable_prose_not_json():
    # The MCP returns plain text (not structuredContent); the model must be able to
    # read the events directly. Prose, never a raw JSON blob.
    out = _render_result(
        {
            "range": {"start": "2026-06-21T00:00:00", "end": "2026-06-28T00:00:00"},
            "events": [
                {
                    "summary": "Meditatie ROMANA", "start": "2026-06-23T15:00:00+03:00",
                    "end": "2026-06-23T17:00:00+03:00", "all_day": False,
                    "location": "200RON", "calendar": "Family", "uid": "x",
                }
            ],
            "count": 1,
        }
    )
    assert "1 event(s)" in out
    assert "Meditatie ROMANA" in out and "Family" in out and "200RON" in out
    assert not out.lstrip().startswith("{")  # prose, not a JSON blob


def test_render_empty_events_says_none():
    out = _render_result({"range": {"start": "a", "end": "b"}, "events": [], "count": 0})
    assert "none found" in out


def test_render_reminders_includes_note():
    out = _render_result({"reminders": [], "count": 0, "note": "upgraded lists ⚠️ unreadable"})
    assert "none found" in out
    assert "Note:" in out and "⚠" in out


def test_render_contacts_is_prose():
    out = _render_result(
        {
            "query": "hont",
            "contacts": [
                {"name": "Maria Hont", "emails": ["m@x.com"], "phones": ["+40"], "org": "Acme"}
            ],
            "count": 1,
        }
    )
    assert "Maria Hont" in out and "m@x.com" in out and "hont" in out


def test_list_reminders_skips_upgraded_tombstone_lists(monkeypatch):
    # Upgraded (⚠️) Reminders lists hold only iCloud tombstones and are unreadable
    # via CalDAV; they must be skipped + reported via `note`, not surfaced.
    from apple_mcp.service import AppleCalendarService
    from apple_mcp.tessera_caldav import _CallerToken

    svc = AppleCalendarService(
        egress_url="http://t",
        target="apple-caldav",
        caller=_CallerToken("http://t/token", "id", "sec", "scope"),
        on_behalf_of="tok",
    )

    class _Cal:
        def __init__(self, name):
            self._n = name

        def get_display_name(self):
            return self._n

    monkeypatch.setattr(svc, "_calendars", lambda: [_Cal("Mementouri ⚠️"), _Cal("Work")])
    monkeypatch.setattr(svc, "_search_todos", lambda cal, name, inc: [])

    out = svc.list_reminders()
    assert out["count"] == 0
    assert "note" in out and "⚠" in out["note"]


def test_is_tombstone_todo_matches_apple_placeholders():
    from apple_mcp.service import _is_tombstone_todo

    assert _is_tombstone_todo({"summary": "Where are my reminders?"}) is True
    assert _is_tombstone_todo({"summary": "The creator upgraded these reminders to iOS"}) is True
    assert _is_tombstone_todo({"summary": "Buy milk"}) is False
    assert _is_tombstone_todo({"summary": None}) is False
    assert _is_tombstone_todo({}) is False


def test_list_reminders_drops_unmarked_tombstones(monkeypatch):
    # A normal (non-⚠️) calendar like "Family" can retain stray "upgraded
    # reminders" tombstones; they carry no real reminder and must be dropped.
    import icalendar

    from apple_mcp.service import AppleCalendarService
    from apple_mcp.tessera_caldav import _CallerToken

    svc = AppleCalendarService(
        egress_url="http://t",
        target="apple-caldav",
        caller=_CallerToken("http://t/token", "id", "sec", "scope"),
        on_behalf_of="tok",
    )

    class _Cal:
        def __init__(self, name):
            self._n = name

        def get_display_name(self):
            return self._n

    def _td(summary):
        comp = icalendar.Todo()
        comp.add("summary", summary)
        obj = type("_Td", (), {})()
        obj.icalendar_component = comp
        return obj

    monkeypatch.setattr(svc, "_calendars", lambda: [_Cal("Family")])
    monkeypatch.setattr(
        svc,
        "_search_todos",
        lambda cal, name, inc: [_td("Where are my reminders?"), _td("Soccer practice")],
    )

    out = svc.list_reminders()
    assert out["count"] == 1
    assert out["reminders"][0]["summary"] == "Soccer practice"


def test_list_events_merges_calendars_sorted(monkeypatch):
    # Per-calendar searches run concurrently (_map_calendars); results across
    # calendars must be merged and sorted by start, independent of calendar order.
    import datetime as dt

    import icalendar

    from apple_mcp.service import AppleCalendarService
    from apple_mcp.tessera_caldav import _CallerToken

    svc = AppleCalendarService(
        egress_url="http://t",
        target="apple-caldav",
        caller=_CallerToken("http://t/token", "id", "sec", "scope"),
        on_behalf_of="tok",
    )

    class _Cal:
        def __init__(self, name):
            self._n = name

        def get_display_name(self):
            return self._n

    def _ev(summary, start):
        comp = icalendar.Event()
        comp.add("summary", summary)
        comp.add("dtstart", start)
        obj = type("_Ev", (), {})()
        obj.icalendar_component = comp
        return obj

    # "A" holds the later event, "B" the earlier — merged output must be sorted.
    mapping = {
        "A": [_ev("Late", dt.datetime(2026, 6, 25, 10, 0))],
        "B": [_ev("Early", dt.datetime(2026, 6, 22, 9, 0))],
    }
    monkeypatch.setattr(svc, "_calendars", lambda: [_Cal("A"), _Cal("B")])
    monkeypatch.setattr(svc, "_search_events", lambda cal, name, s, e: mapping[name])

    out = svc.list_events()
    assert out["count"] == 2
    assert [e["summary"] for e in out["events"]] == ["Early", "Late"]


def test_summarize_todo_is_least_disclosure_and_detects_completion():
    # A reminder's notes/description can hold sensitive free text; the summary
    # must NEVER include it. Also verify completion + field extraction.
    import icalendar

    from apple_mcp.service import _summarize_todo

    class _Td:
        def __init__(self, comp):
            self.icalendar_component = comp

    vtodo = icalendar.Todo()
    vtodo.add("summary", "Pay rent")
    vtodo.add("description", "IBAN RO49 0000 secret note")  # must not leak
    vtodo.add("status", "COMPLETED")
    vtodo.add("priority", 1)
    vtodo.add("uid", "abc")

    out = _summarize_todo(_Td(vtodo), "Reminders")
    assert out["summary"] == "Pay rent"
    assert out["status"] == "COMPLETED"
    assert out["completed"] is True
    assert out["priority"] == 1
    assert out["calendar"] == "Reminders"
    assert "description" not in out and "notes" not in out
    assert "secret note" not in str(out)
