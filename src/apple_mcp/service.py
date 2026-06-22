"""Apple iCloud Calendar service — read-only Phase 1.

Drives the ``caldav`` library over the Tessera-brokered transport to implement
the two read-only tools: list the user's calendars and list events in a date
range. A fresh client is built per call with the request-scoped on-behalf-of
token, so one user's call can never reuse another user's session. The MCP holds
no Apple secret — Tessera injects it.

Least-disclosure: events are returned as metadata (summary, start, end, location,
calendar, uid), not raw VEVENT bodies, so a single call can't drain a calendar's
full contents into the model.
"""
from __future__ import annotations

import datetime as _dt
import logging
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import icalendar

from .contacts import find_contacts as _find_contacts
from .settings import diag
from .tessera_caldav import AppleEgressError, TesseraCalDAVClient, _CallerToken

log = logging.getLogger("apple_mcp.service")

# iCloud appends ⚠ to a Reminders list it has upgraded to the new (non-CalDAV)
# format; such a list returns only tombstone items over CalDAV. See list_reminders.
_UPGRADED_LIST_MARKER = "\u26a0"

# Per-calendar CalDAV REPORTs are independent and dominate list latency, so they
# are brokered concurrently (bounded). iCloud + Tessera handle a handful of
# parallel hops fine; the cap keeps brokered fan-out modest so a single list call
# never floods the shared Tessera path (which also fronts the medical RM broker).
_MAX_CALENDAR_WORKERS = 8

# When iCloud upgrades a Reminders list it leaves tombstone VTODOs behind. Most
# such lists are ⚠-marked (skipped wholesale), but a few normal calendars retain
# stray tombstones with no marker (e.g. a shared "Family" calendar). These match a
# small set of Apple-authored summaries and are dropped so they never surface as
# fake reminders. Matched case-insensitively as substrings.
_TOMBSTONE_TODO_SUMMARIES = (
    "where are my reminders",
    "upgraded these reminders",
    "reminders were upgraded",
    "reminders have been upgraded",
)


def _iso(value: Any) -> str | None:
    """Render a date/datetime (or passthrough string) as ISO 8601, or None."""
    if value is None:
        return None
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    return str(value)


def _parse_range(
    start: str | None, end: str | None, *, default_days: int = 7
) -> tuple[_dt.datetime, _dt.datetime]:
    """Parse an ISO start/end into aware-naive datetimes.

    Defaults to ``[today 00:00, +default_days]`` when unset. Accepts ``YYYY-MM-DD``
    or full ISO datetimes. Raises :class:`AppleEgressError` on an unparseable value
    (secret-free message).
    """
    def _one(raw: str) -> _dt.datetime:
        raw = raw.strip()
        try:
            if len(raw) == 10:  # date only
                return _dt.datetime.fromisoformat(raw + "T00:00:00")
            return _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AppleEgressError(f"invalid date '{raw}' (use YYYY-MM-DD or ISO 8601)") from exc

    now = _dt.datetime.now()
    start_dt = _one(start) if start else _dt.datetime(now.year, now.month, now.day)
    end_dt = _one(end) if end else start_dt + _dt.timedelta(days=default_days)
    if end_dt < start_dt:
        raise AppleEgressError("end is before start")
    return start_dt, end_dt


def _parse_one_dt(raw: str) -> _dt.datetime:
    """Parse a single ISO date/datetime (``YYYY-MM-DD`` or full ISO 8601)."""
    raw = (raw or "").strip()
    try:
        if len(raw) == 10:
            return _dt.datetime.fromisoformat(raw + "T00:00:00")
        return _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AppleEgressError(f"invalid datetime '{raw}' (use YYYY-MM-DD or ISO 8601)") from exc


# A fixed namespace so a create is IDEMPOTENT by content: the UID is a deterministic
# function of (calendar, summary, start, end), so the first (held) attempt and the
# post-approval re-request build the SAME object — the byte-identical body Tessera's
# out-of-band approval is bound to (ADR 0023).
_UID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "apple-caldav-mcp/event")


def _deterministic_uid(
    calendar_name: str | None, summary: str, start: _dt.datetime, end: _dt.datetime
) -> str:
    key = f"{calendar_name or ''}|{summary}|{start.isoformat()}|{end.isoformat()}"
    return f"apple-mcp-{uuid.uuid5(_UID_NAMESPACE, key)}"


def _build_vevent(
    uid: str, summary: str, start: _dt.datetime, end: _dt.datetime, location: str | None
) -> bytes:
    """Serialize a DETERMINISTIC VEVENT (no wall-clock fields), so the held attempt and the
    approved completion are byte-identical — the exact body the out-of-band approval binds to."""
    # DTSTAMP is derived from the start (UTC-normalized), NOT the wall clock, so the body does
    # not change between the held attempt and the approved re-request.
    base_ts = start if start.tzinfo else start.replace(tzinfo=_dt.UTC)
    dtstamp = base_ts.astimezone(_dt.UTC)
    cal = icalendar.Calendar()
    cal.add("prodid", "-//apple-caldav-mcp//calendar write//EN")
    cal.add("version", "2.0")
    ev = icalendar.Event()
    ev.add("uid", uid)
    ev.add("summary", summary)
    ev.add("dtstart", start)
    ev.add("dtend", end)
    ev.add("dtstamp", dtstamp)
    if location:
        ev.add("location", location)
    cal.add_component(ev)
    return cal.to_ical()


def _safe_json(resp: Any) -> dict[str, Any]:
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001 — a non-JSON body just yields no fields
        return {}
    return data if isinstance(data, dict) else {}


def _interpret_write(resp: Any, *, uid: str, summary: str, calendar: str | None) -> dict[str, Any]:
    """Map a brokered write response to a least-disclosure tool result.

    2xx = created. 409 = HELD for the person's OUT-OF-BAND approval (ADR 0023): surface the
    challenge + where to approve, and tell the caller to retry the identical write afterwards.
    401/403 = the ``manage:dav`` grant is not in place (writes not enabled). 424 = no Apple
    credential bound. Anything else becomes a secret-free domain error.
    """
    status = getattr(resp, "status_code", 0)
    if status in (200, 201, 204):
        return {"status": "created", "uid": uid, "summary": summary, "calendar": calendar}
    if status == 409:
        data = _safe_json(resp)
        return {
            "status": "pending_approval",
            "summary": summary,
            "calendar": calendar,
            "uid": uid,
            "challenge": data.get("challenge"),
            "approve_at": data.get("approveAt") or "/portal",
            "expires_at": data.get("expiresAt"),
            "note": (
                "This change is held for YOUR approval. Open the Tessera portal, approve the "
                "pending write, then ask me to make the same change again to complete it."
            ),
        }
    if status in (401, 403):
        return {
            "status": "writes_not_enabled",
            "summary": summary,
            "note": "Writing is not enabled for your account yet (no manage grant).",
        }
    if status == 424:
        return {"status": "no_credential", "note": "No Apple credential is bound for your account."}
    raise AppleEgressError(f"create event failed: HTTP {status}")


class AppleCalendarService:
    """Apple Calendar operations over the Tessera-brokered transport (reads + gated writes)."""

    def __init__(
        self,
        *,
        egress_url: str,
        target: str,
        caller: _CallerToken,
        on_behalf_of: str,
        timeout: float = 30.0,
        max_redirects: int = 5,
    ):
        self._client = TesseraCalDAVClient(
            egress_url=egress_url,
            target=target,
            caller=caller,
            on_behalf_of=on_behalf_of,
            timeout=timeout,
            max_redirects=max_redirects,
        )

    def _calendars(self) -> list[Any]:
        try:
            principal = self._client.principal()
            return list(principal.calendars())
        except AppleEgressError:
            raise
        except Exception as exc:  # noqa: BLE001 — normalise to a secret-free domain error
            raise AppleEgressError(f"could not list calendars: {type(exc).__name__}") from exc

    def _map_calendars(self, cals: list[Any], fn: Callable[[Any], Any]) -> list[Any]:
        """Apply ``fn`` to each calendar concurrently (bounded), order preserved.

        The per-calendar CalDAV REPORT is the dominant cost of a list call and the
        calendars are independent, so they are brokered in parallel over the shared
        session (urllib3's connection pool is thread-safe; the caller token is
        already cached by the preceding principal discovery, so the threads only
        hit its read-only fast path). Serial for 0/1 calendars. ``fn``'s first
        raised error propagates on iteration (parity with the prior serial loop).
        """
        if not cals:
            return []
        workers = min(len(cals), _MAX_CALENDAR_WORKERS)
        if workers <= 1:
            return [fn(cals[0])]
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="caldav") as ex:
            return list(ex.map(fn, cals))

    def list_calendars(self) -> dict[str, Any]:
        """List the signed-in person's iCloud calendars (name + id)."""
        out = []
        for cal in self._calendars():
            try:
                name = cal.get_display_name()
            except Exception:  # noqa: BLE001
                name = None
            out.append({"name": name, "id": str(getattr(cal, "url", "")) or None})
        return {"calendars": out, "count": len(out)}

    def list_events(self, start: str | None = None, end: str | None = None) -> dict[str, Any]:
        """List events across the person's calendars in ``[start, end]``.

        ``start``/``end`` are ISO dates (``YYYY-MM-DD``) or datetimes; both default
        (today .. +7 days). Returns event metadata only (least-disclosure).
        """
        start_dt, end_dt = _parse_range(start, end)
        cals = self._calendars()
        log.info(
            "list_events range=[%s .. %s] across %d calendar(s): %s",
            start_dt.isoformat(), end_dt.isoformat(), len(cals),
            [str(getattr(c, "url", "?")).rstrip("/").rsplit("/", 1)[-1] for c in cals],
        )
        def _one(cal: Any) -> list[dict[str, Any]]:
            cal_name = _display_name(cal)
            found = self._search_events(cal, cal_name, start_dt, end_dt)
            log.info("calendar name=%r -> %d event(s) in range", cal_name, len(found))
            return [_summarize_event(ev, cal_name) for ev in found]

        events: list[dict[str, Any]] = []
        for sub in self._map_calendars(cals, _one):
            events.extend(sub)
        events.sort(key=lambda e: (e.get("start") or ""))
        log.info("list_events total=%d event(s)", len(events))
        return {
            "range": {"start": start_dt.isoformat(), "end": end_dt.isoformat()},
            "events": events,
            "count": len(events),
        }

    def _search_events(
        self, cal: Any, cal_name: str | None, start_dt: _dt.datetime, end_dt: _dt.datetime
    ) -> list[Any]:
        """Search one calendar for events in ``[start, end]``, robust to iCloud's
        recurrence-expansion quirk.

        iCloud's CalDAV can return **nothing** for a ``calendar-query`` REPORT that
        asks for server-side recurrence ``<C:expand>`` — a long-standing
        incompatibility. So try ``expand=True`` first (per-instance dates), and if
        it yields nothing (or errors), fall back to ``expand=False`` (the recurring
        master is returned instead, so the event still appears). A one-off event is
        returned by both paths; only the recurring case depends on this fallback.
        """
        try:
            found = list(cal.search(start=start_dt, end=end_dt, event=True, expand=True))
        except Exception as exc:  # noqa: BLE001 — expand is the fragile path; fall back
            log.warning(
                "expand search failed on %r: %s; retrying without expand",
                cal_name, type(exc).__name__,
            )
            found = []
        if not found:
            try:
                found = list(cal.search(start=start_dt, end=end_dt, event=True, expand=False))
            except Exception as exc:  # noqa: BLE001 — normalise to a secret-free domain error
                raise AppleEgressError(
                    f"could not search events: {type(exc).__name__}"
                ) from exc
            if found:
                log.info(
                    "calendar %r: expand returned 0 but no-expand returned %d "
                    "(iCloud expand quirk)",
                    cal_name, len(found),
                )
        return found

    def list_reminders(self, include_completed: bool = False) -> dict[str, Any]:
        """List the person's Apple Reminders (CalDAV VTODOs) across their lists.

        Pending only by default (``include_completed=False``). Returns least-
        disclosure metadata (summary, due, status, completed, priority, calendar,
        uid) — never the reminder's notes/description.

        iCloud marks a Reminders list it has upgraded to the new (non-CalDAV)
        format with a ``⚠️`` in the name and leaves only tombstone items behind
        ("Where are my reminders?"). Such lists CANNOT be read over CalDAV, so they
        are skipped and reported via ``note`` rather than surfaced as fake reminders.
        """
        cals = self._calendars()
        if diag():
            self._log_diagnostics(cals)
        log.info(
            "list_reminders include_completed=%s across %d calendar(s)",
            include_completed, len(cals),
        )
        def _one(cal: Any) -> tuple[bool, list[dict[str, Any]]]:
            cal_name = _display_name(cal)
            if cal_name and _UPGRADED_LIST_MARKER in cal_name:
                return True, []  # upgraded list — skip wholesale, count as inaccessible
            found = self._search_todos(cal, cal_name, include_completed)
            summaries = [_summarize_todo(td, cal_name) for td in found]
            summaries = [s for s in summaries if not _is_tombstone_todo(s)]
            if summaries:
                log.info("calendar name=%r -> %d reminder(s)", cal_name, len(summaries))
            return False, summaries

        reminders: list[dict[str, Any]] = []
        inaccessible = 0
        for upgraded, sub in self._map_calendars(cals, _one):
            if upgraded:
                inaccessible += 1
            reminders.extend(sub)
        # Due date ascending; undated reminders sort last ("~" > any ISO digit).
        reminders.sort(key=lambda r: (r.get("due") or "~"))
        log.info(
            "list_reminders total=%d reminder(s); %d upgraded list(s) skipped",
            len(reminders), inaccessible,
        )
        out: dict[str, Any] = {"reminders": reminders, "count": len(reminders)}
        if inaccessible:
            out["note"] = (
                f"{inaccessible} Reminders list(s) have been upgraded to iCloud's new "
                "format (marked ⚠️) and cannot be read over CalDAV; only legacy lists "
                "appear here. Those upgraded reminders are not retrievable by this tool."
            )
        return out

    def _search_todos(
        self, cal: Any, cal_name: str | None, include_completed: bool
    ) -> list[Any]:
        """Fetch a calendar's VTODOs, robust to iCloud.

        iCloud returns HTTP 500 for a calendar-query carrying the
        ``include_completed=False`` STATUS!=COMPLETED filter (python-caldav#3), so
        always issue the BARE ``VTODO`` query and drop completed items client-side.
        An event-only calendar simply matches nothing and returns an empty list.
        """
        try:
            found = list(cal.search(todo=True, include_completed=True))
        except Exception as exc:  # noqa: BLE001 — VTODO query unsupported on this list
            log.warning("todo search failed on %r: %s", cal_name, type(exc).__name__)
            return []
        if not include_completed:
            found = [td for td in found if not _todo_is_completed(td)]
        return found

    def _log_diagnostics(self, cals: list[Any]) -> None:
        """Dump per-calendar accessibility (component-set + VTODO count + a sample)
        when APPLE_MCP_DIAG is on — shows exactly what iCloud exposes for each list,
        so reminder accessibility can be diagnosed from a single call."""
        for cal in cals:
            name = _display_name(cal)
            try:
                comps = cal.get_supported_components()
            except Exception as exc:  # noqa: BLE001
                comps = f"ERR:{type(exc).__name__}"
            try:
                todos = list(cal.search(todo=True, include_completed=True))
                tinfo: Any = len(todos)
                sample = None
                if todos:
                    s = _summarize_todo(todos[0], name)
                    sample = {k: s.get(k) for k in ("summary", "status", "due", "completed")}
            except Exception as exc:  # noqa: BLE001
                tinfo, sample = f"ERR:{type(exc).__name__}", None
            log.info("DIAG list=%r components=%s vtodos=%s sample=%s", name, comps, tinfo, sample)

    def find_contacts(self, query: str, limit: int = 10) -> dict[str, Any]:
        """Search the person's iCloud Contacts (CardDAV) by name/email (read-only).

        Delegates to the CardDAV module, which drives raw CardDAV over this
        service's Tessera-brokered transport (``self._client``). Search-only +
        hard-capped + least-disclosure (see :mod:`apple_mcp.contacts`).
        """
        return _find_contacts(self._client, query=query, limit=limit)

    def create_event(
        self,
        summary: str,
        start: str,
        end: str,
        location: str | None = None,
        calendar: str | None = None,
    ) -> dict[str, Any]:
        """Create a calendar event via a brokered CalDAV PUT (manage:dav).

        On success the event is written and the call returns ``status="created"``. If Tessera
        policy HOLDS the write for the person's OUT-OF-BAND approval (ADR 0023), the first call
        returns ``status="pending_approval"`` (with the portal to approve in) and the IDENTICAL
        re-request completes it after approval. The VEVENT is deterministic so both calls hash
        identically (the held attempt and the approved re-request are byte-identical).
        """
        if not (summary or "").strip():
            raise AppleEgressError("summary is required")
        start_dt = _parse_one_dt(start)
        end_dt = _parse_one_dt(end)
        if end_dt < start_dt:
            raise AppleEgressError("end is before start")

        cal = self._resolve_calendar(self._calendars(), calendar)
        cal_name = _display_name(cal)
        uid = _deterministic_uid(cal_name, summary, start_dt, end_dt)
        body = _build_vevent(uid, summary, start_dt, end_dt, location)
        base = str(getattr(cal, "url", "")).rstrip("/")
        if not base:
            raise AppleEgressError("the target calendar has no URL")
        put_url = f"{base}/{uid}.ics"
        human = f"Create event '{summary}' starting {start_dt.isoformat()} in calendar '{cal_name}'"
        log.info("create_event uid=%s calendar=%r", uid, cal_name)
        try:
            resp = self._client.brokered_dav(
                put_url,
                "PUT",
                body,
                {"Content-Type": "text/calendar; charset=utf-8", "X-Tessera-Write-Summary": human},
            )
        except AppleEgressError:
            raise
        except Exception as exc:  # noqa: BLE001 — normalise to a secret-free domain error
            raise AppleEgressError(f"could not create event: {type(exc).__name__}") from exc

        return _interpret_write(resp, uid=uid, summary=summary, calendar=cal_name)

    def _resolve_calendar(self, cals: list[Any], name: str | None) -> Any:
        """Pick the target calendar: by display name (case-insensitive) when given, else the
        first calendar (a stable default so the deterministic UID is reproducible)."""
        if name and name.strip():
            wanted = name.strip().lower()
            for cal in cals:
                if (_display_name(cal) or "").strip().lower() == wanted:
                    return cal
            raise AppleEgressError(f"no calendar named '{name}'")
        if not cals:
            raise AppleEgressError("no calendars are available to write to")
        return cals[0]


def _display_name(cal: Any) -> str | None:
    """The calendar's display name, or None if it can't be read."""
    try:
        return cal.get_display_name()
    except Exception:  # noqa: BLE001
        return None


def _summarize_event(ev: Any, calendar_name: str | None) -> dict[str, Any]:
    """Extract least-disclosure metadata from a caldav Event (VEVENT)."""
    try:
        comp = ev.icalendar_component
    except Exception:  # noqa: BLE001 - tolerate a parse miss; return what we can
        comp = None
    if comp is None:
        return {"summary": None, "calendar": calendar_name}

    def _g(key: str) -> Any:
        try:
            v = comp.get(key)
        except Exception:  # noqa: BLE001
            return None
        return getattr(v, "dt", v) if v is not None else None

    start = _g("dtstart")
    return {
        "summary": str(comp.get("summary")) if comp.get("summary") is not None else None,
        "start": _iso(start),
        "end": _iso(_g("dtend")),
        "all_day": isinstance(start, _dt.date) and not isinstance(start, _dt.datetime),
        "location": str(comp.get("location")) if comp.get("location") is not None else None,
        "calendar": calendar_name,
        "uid": str(comp.get("uid")) if comp.get("uid") is not None else None,
    }


def _todo_is_completed(td: Any) -> bool:
    """True if a VTODO is finished (STATUS:COMPLETED or a COMPLETED timestamp)."""
    try:
        comp = td.icalendar_component
    except Exception:  # noqa: BLE001
        return False
    if comp is None:
        return False
    status = comp.get("status")
    if status is not None and str(status).upper() == "COMPLETED":
        return True
    return comp.get("completed") is not None


def _is_tombstone_todo(summary: dict[str, Any]) -> bool:
    """True if a summarized VTODO is an Apple "upgraded reminders" tombstone.

    When iCloud upgrades a Reminders list it can leave placeholder items behind
    ("Where are my reminders?", "… upgraded these reminders …"). They carry no
    real reminder, so they are dropped rather than surfaced. ⚠-marked lists are
    skipped wholesale by the caller; this catches strays left on otherwise-normal
    calendars (e.g. a shared "Family" calendar) that have no marker.
    """
    text = (summary.get("summary") or "").lower()
    return any(pat in text for pat in _TOMBSTONE_TODO_SUMMARIES)


def _summarize_todo(td: Any, calendar_name: str | None) -> dict[str, Any]:
    """Extract least-disclosure metadata from a caldav Todo (VTODO).

    Deliberately omits DESCRIPTION/notes — a reminder's body can hold sensitive
    free text, so a single call can't drain it into the model.
    """
    try:
        comp = td.icalendar_component
    except Exception:  # noqa: BLE001 — tolerate a parse miss; return what we can
        comp = None
    if comp is None:
        return {"summary": None, "calendar": calendar_name}

    def _g(key: str) -> Any:
        try:
            v = comp.get(key)
        except Exception:  # noqa: BLE001
            return None
        return getattr(v, "dt", v) if v is not None else None

    status = comp.get("status")
    priority = comp.get("priority")
    return {
        "summary": str(comp.get("summary")) if comp.get("summary") is not None else None,
        "due": _iso(_g("due")),
        "status": str(status) if status is not None else None,
        "completed": _todo_is_completed(td),
        "priority": int(priority) if isinstance(priority, int) else None,
        "calendar": calendar_name,
        "uid": str(comp.get("uid")) if comp.get("uid") is not None else None,
    }
