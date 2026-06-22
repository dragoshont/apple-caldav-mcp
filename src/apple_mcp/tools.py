"""Tool implementations.

Read tools (``list_calendars``, ``list_events``, ``list_reminders``, ``find_contacts``)
match the ``read:dav`` grant. The WRITE tool (``create_event``) is exposed ONLY when
``APPLE_MCP_ENABLE_WRITES`` is set, and is doubly gated beyond that: Tessera's PDP denies
the ``manage:dav`` plane without a write grant, and Tessera policy MAY additionally hold a
write for OUT-OF-BAND human approval in the Tessera portal (ADR 0023 / HL-18) — a prompt-
injected model can neither enable the tool nor self-approve a mutation.

Each tool takes a bound :class:`AppleCalendarService` (built per call with the
request-scoped on-behalf-of token) as its first argument; ``mcp_streamable`` /
``app`` inject it.
"""
from __future__ import annotations

from typing import Any

from .service import AppleCalendarService
from .settings import writes_enabled


def list_calendars(service: AppleCalendarService) -> dict[str, Any]:
    """List the signed-in person's Apple iCloud calendars (name + id)."""
    return service.list_calendars()


def list_events(
    service: AppleCalendarService,
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    """List Apple iCloud calendar events in a date range.

    start/end are ISO dates (YYYY-MM-DD) or datetimes; both default to
    [today, +7 days]. Returns event metadata (summary, start, end, location,
    calendar, uid).
    """
    return service.list_events(start=start, end=end)


def list_reminders(
    service: AppleCalendarService,
    include_completed: bool = False,
) -> dict[str, Any]:
    """List Apple Reminders (tasks) across the person's reminder lists.

    Returns pending reminders by default (summary, due, status, priority,
    calendar, uid); set include_completed=true to also include finished ones.
    Notes/description are never returned (least-disclosure).
    """
    return service.list_reminders(include_completed=include_completed)


def find_contacts(
    service: AppleCalendarService,
    query: str,
    limit: int = 10,
) -> dict[str, Any]:
    """Search the person's Apple Contacts (iCloud) by name or email.

    Read-only SEARCH (there is no list-all): pass a name/email fragment of at
    least 2 characters. Returns up to `limit` (max 25) matches with least-
    disclosure fields (name, a few emails/phones, org) — never photos, notes or
    postal addresses.
    """
    return service.find_contacts(query=query, limit=limit)


# name -> callable. The first parameter (``service``) is injected (a service-
# injection pattern), so the MCP/OpenAPI schemas only advertise the user-facing args.
TOOLS = {
    "list_calendars": list_calendars,
    "list_events": list_events,
    "list_reminders": list_reminders,
    "find_contacts": find_contacts,
}


def create_event(
    service: AppleCalendarService,
    summary: str,
    start: str,
    end: str,
    location: str | None = None,
    calendar: str | None = None,
) -> dict[str, Any]:
    """Create an Apple iCloud calendar event (WRITE).

    summary is the title; start/end are ISO datetimes (YYYY-MM-DD or full ISO, e.g.
    2026-06-25T15:00:00+03:00). Optional location + calendar (name; defaults to your
    first calendar). The event is written to your calendar and the call returns
    status="created". (If Tessera policy holds writes for approval, it instead returns
    status="pending_approval" with where to approve; approve, then ask again with the
    SAME details to complete it.)
    """
    return service.create_event(
        summary=summary, start=start, end=end, location=location, calendar=calendar
    )


# The WRITE surface is exposed ONLY when explicitly enabled (default off), so the create
# tool is invisible + unreachable until an operator opts in (Tessera still gates the actual
# mutation via the manage:dav grant, and MAY hold it for out-of-band approval, ADR 0023).
if writes_enabled():
    TOOLS["create_event"] = create_event
