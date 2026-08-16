"""Apple iCloud Contacts (CardDAV) — read-only SEARCH, least-disclosure.

The ``caldav`` library models CalDAV only, so this drives raw CardDAV (RFC 6352)
over the same controlled transport used for Calendar/Reminders: a PROPFIND
discovery chain (current-user-principal -> addressbook-home-set -> address books)
then an ``addressbook-query`` REPORT with an ``FN`` text-match filter. The MCP
uses the credential custody of the configured brokered or guarded direct mode.

Privacy + context-size by design:
  * SEARCH only — there is deliberately no "list every contact" surface, so a
    single call (or a prompt-injected model) cannot drain the whole address book.
  * A query of >= 2 characters is required; the result set is HARD-capped.
  * Least-disclosure: only the name, a few emails/phones and org are returned —
    never photos, notes, postal addresses, birthdays, URLs or any other field.
  * The CardDAV XML is parsed with ``defusedxml`` (XXE / entity-expansion safe),
    because the response is network input even though Tessera brokers it.
"""
from __future__ import annotations

import urllib.parse
from typing import Any

from defusedxml.ElementTree import fromstring as _xml_fromstring

from .tessera_caldav import AppleEgressError

_DAV = "DAV:"
_CARD = "urn:ietf:params:xml:ns:carddav"
ICLOUD_CONTACTS_ROOT = "https://contacts.icloud.com/"

# Hard caps — context-size AND privacy. Never return more than this many
# contacts, nor more than a few contact methods each, whatever iCloud sends back.
_MAX_RESULTS = 25
_DEFAULT_RESULTS = 10
_MAX_METHODS_EACH = 4
# Defensive: if a server-side filter is ignored and iCloud returns the whole
# book, stop parsing after this many vCards (the result is capped regardless).
_MAX_SCAN = 1000

_PROPFIND_PRINCIPAL = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>'
)
_PROPFIND_HOMESET = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
    "<d:prop><c:addressbook-home-set/></d:prop></d:propfind>"
)
_PROPFIND_ADDRESSBOOKS = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>'
)
# Ask iCloud to project ONLY the fields we need (no PHOTO/NOTE/ADR), filter by an
# FN substring, and cap server-side. If iCloud ignores any of these, the client
# side still filters + caps.
_ADDRESSBOOK_QUERY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
    "<d:prop><c:address-data>"
    '<c:prop name="FN"/><c:prop name="N"/><c:prop name="EMAIL"/>'
    '<c:prop name="TEL"/><c:prop name="ORG"/>'
    "</c:address-data></d:prop>"
    '<c:filter test="anyof">'
    '<c:prop-filter name="FN">'
    '<c:text-match collation="i;unicode-casemap" match-type="contains">{q}</c:text-match>'
    "</c:prop-filter>"
    "</c:filter>"
    "<c:limit><c:nresults>{n}</c:nresults></c:limit>"
    "</c:addressbook-query>"
)


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _unfold(text: str) -> list[str]:
    """Unfold vCard logical lines (a continuation line starts with space/tab)."""
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "N": "\n", ",": ",", ";": ";", "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _name_from_n(value: str) -> str | None:
    # N = Family;Given;Additional;Prefix;Suffix
    parts = [p.strip() for p in value.split(";")]
    family = parts[0] if len(parts) > 0 else ""
    given = parts[1] if len(parts) > 1 else ""
    name = " ".join(p for p in (given, family) if p).strip()
    return name or None


def summarize_vcard(text: str, max_each: int = _MAX_METHODS_EACH) -> dict[str, Any] | None:
    """Least-disclosure parse of one vCard: name + a few emails/phones + org.

    Reads ONLY ``FN`` / ``N`` / ``EMAIL`` / ``TEL`` / ``ORG`` — never ``PHOTO``,
    ``NOTE``, ``ADR``, ``BDAY``, ``URL`` or any other property, so a contact's
    photo and free-text notes can never reach the model. Returns ``None`` for a
    vCard with no usable name or contact method.
    """
    fn: str | None = None
    n_name: str | None = None
    emails: list[str] = []
    phones: list[str] = []
    org: str | None = None
    for line in _unfold(text):
        name_part, sep, value = line.partition(":")
        if not sep:
            continue
        prop = name_part.split(";", 1)[0].strip().upper()
        value = _unescape(value.strip())
        if not value:
            continue
        if prop == "FN":
            fn = fn or value
        elif prop == "N":
            n_name = n_name or _name_from_n(value)
        elif prop == "EMAIL" and len(emails) < max_each:
            emails.append(value)
        elif prop == "TEL" and len(phones) < max_each:
            phones.append(value)
        elif prop == "ORG":
            org = org or (value.split(";")[0].strip() or None)
    name = fn or n_name
    if not name and not emails and not phones:
        return None
    return {"name": name, "emails": emails, "phones": phones, "org": org}


def _matches(summary: dict[str, Any], query: str) -> bool:
    """Client-side guard: keep only true hits even if iCloud ignored the filter
    and returned the whole book."""
    needle = query.lower()
    name = summary.get("name")
    if name and needle in name.lower():
        return True
    return any(needle in email.lower() for email in summary.get("emails", []))


def _parse(xml_bytes: bytes):
    try:
        return _xml_fromstring(xml_bytes)
    except Exception as exc:  # noqa: BLE001 — never echo the body (secret-free)
        raise AppleEgressError("CardDAV: unparseable response") from exc


def _first_href(tree, local: str, ns: str = _DAV) -> str | None:
    el = tree.find(f".//{{{ns}}}{local}/{{{_DAV}}}href")
    return el.text.strip() if el is not None and el.text else None


def _addressbook_hrefs(tree) -> list[str]:
    """Hrefs of collections whose resourcetype includes ``{carddav}addressbook``."""
    out: list[str] = []
    for resp in tree.iter(f"{{{_DAV}}}response"):
        rtype = resp.find(f".//{{{_DAV}}}resourcetype")
        if rtype is not None and rtype.find(f"{{{_CARD}}}addressbook") is not None:
            href = resp.find(f"{{{_DAV}}}href")
            if href is not None and href.text:
                out.append(href.text.strip())
    return out


def _vcard_texts(tree) -> list[str]:
    out: list[str] = []
    for addr in tree.iter(f"{{{_CARD}}}address-data"):
        if addr.text and "BEGIN:VCARD" in addr.text:
            out.append(addr.text)
    return out


def _dav(client: Any, url: str, method: str, body: str, depth: int) -> bytes:
    """One brokered CardDAV hop; returns the raw XML bytes (or raises secret-free)."""
    resp = client.brokered_dav(
        url,
        method,
        body,
        {"Depth": str(depth), "Content-Type": 'application/xml; charset="utf-8"'},
    )
    code = getattr(resp, "status_code", 0)
    if code >= 400:
        raise AppleEgressError(f"CardDAV {method} returned HTTP {code}")
    return getattr(resp, "content", b"") or b""


def _discover_addressbooks(client: Any) -> list[str]:
    """PROPFIND chain: current-user-principal -> addressbook-home-set -> books."""
    root = ICLOUD_CONTACTS_ROOT
    tree = _parse(_dav(client, root, "PROPFIND", _PROPFIND_PRINCIPAL, depth=0))
    principal = _first_href(tree, "current-user-principal")
    if not principal:
        raise AppleEgressError("CardDAV: no current-user-principal in discovery")
    principal_url = urllib.parse.urljoin(root, principal)

    tree = _parse(_dav(client, principal_url, "PROPFIND", _PROPFIND_HOMESET, depth=0))
    home = _first_href(tree, "addressbook-home-set", ns=_CARD)
    if not home:
        raise AppleEgressError("CardDAV: no addressbook-home-set in discovery")
    home_url = urllib.parse.urljoin(root, home)

    tree = _parse(_dav(client, home_url, "PROPFIND", _PROPFIND_ADDRESSBOOKS, depth=1))
    hrefs = _addressbook_hrefs(tree)
    if not hrefs:
        # Some accounts expose the address book at the home collection itself.
        return [home_url]
    return [urllib.parse.urljoin(root, h) for h in hrefs]


def find_contacts(client: Any, query: str, limit: int = _DEFAULT_RESULTS) -> dict[str, Any]:
    """Search the person's iCloud address books by name/email (read-only).

    ``client`` is the Tessera-brokered transport (its ``brokered_dav`` issues raw
    CardDAV hops). Returns at most ``limit`` (hard-capped at 25) least-disclosure
    contacts. Requires a query of >= 2 characters — there is no list-everything
    path by design.
    """
    query = (query or "").strip()
    if len(query) < 2:
        raise AppleEgressError("contact search needs a query of at least 2 characters")
    limit = max(1, min(int(limit or _DEFAULT_RESULTS), _MAX_RESULTS))

    contacts: list[dict[str, Any]] = []
    scanned = 0
    for ab_url in _discover_addressbooks(client):
        body = _ADDRESSBOOK_QUERY.format(q=_xml_escape(query), n=limit)
        tree = _parse(_dav(client, ab_url, "REPORT", body, depth=1))
        for vtext in _vcard_texts(tree):
            scanned += 1
            if scanned > _MAX_SCAN:
                break
            summary = summarize_vcard(vtext)
            if summary and _matches(summary, query):
                contacts.append(summary)
                if len(contacts) >= limit:
                    break
        if len(contacts) >= limit or scanned > _MAX_SCAN:
            break
    contacts.sort(key=lambda c: (c.get("name") or "~").lower())
    return {"query": query, "contacts": contacts, "count": len(contacts)}
