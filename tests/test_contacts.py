"""Offline CardDAV (Contacts) tests — discovery, search, caps, least-disclosure.

No network and no live Apple call: a fake brokered client returns canned DAV XML,
so the discovery chain + addressbook-query + vCard parsing are exercised end to
end. The security-critical property under test is least-disclosure — a contact's
PHOTO and NOTE must NEVER appear in the result.
"""
from __future__ import annotations

import pytest

from apple_mcp.contacts import (
    _addressbook_hrefs,
    _first_href,
    _parse,
    _vcard_texts,
    find_contacts,
    summarize_vcard,
)
from apple_mcp.tessera_caldav import AppleEgressError

_PRINCIPAL_XML = (
    b'<?xml version="1.0"?>'
    b'<d:multistatus xmlns:d="DAV:"><d:response><d:href>/</d:href>'
    b"<d:propstat><d:prop><d:current-user-principal>"
    b"<d:href>/123/principal/</d:href></d:current-user-principal>"
    b"</d:prop></d:propstat></d:response></d:multistatus>"
)
_HOMESET_XML = (
    b'<?xml version="1.0"?>'
    b'<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
    b"<d:response><d:href>/123/principal/</d:href><d:propstat><d:prop>"
    b"<c:addressbook-home-set><d:href>/123/carddavhome/</d:href></c:addressbook-home-set>"
    b"</d:prop></d:propstat></d:response></d:multistatus>"
)
_BOOKS_XML = (
    b'<?xml version="1.0"?>'
    b'<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
    b"<d:response><d:href>/123/carddavhome/card/</d:href><d:propstat><d:prop>"
    b"<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>"
    b"<d:displayname>Card</d:displayname></d:prop></d:propstat></d:response>"
    b"<d:response><d:href>/123/carddavhome/</d:href><d:propstat><d:prop>"
    b"<d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>"
    b"</d:multistatus>"
)
# Two vCards. The first matches "hont" and carries a PHOTO + NOTE that MUST be
# dropped; the second (John Smith) must not match.
_REPORT_XML = (
    b'<?xml version="1.0"?>'
    b'<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
    b"<d:response><d:href>/123/carddavhome/card/a.vcf</d:href><d:propstat><d:prop>"
    b"<c:address-data>BEGIN:VCARD\n"
    b"VERSION:3.0\n"
    b"FN:Maria Hont\n"
    b"N:Hont;Maria;;;\n"
    b"EMAIL;TYPE=HOME:maria@example.com\n"
    b"TEL;TYPE=CELL:+40 712 345 678\n"
    b"ORG:Acme;Engineering\n"
    b"PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZSECRETBASE64DATA\n"
    b"NOTE:private medical note - do not leak\n"
    b"END:VCARD</c:address-data></d:prop></d:propstat></d:response>"
    b"<d:response><d:href>/123/carddavhome/card/b.vcf</d:href><d:propstat><d:prop>"
    b"<c:address-data>BEGIN:VCARD\nVERSION:3.0\nFN:John Smith\n"
    b"EMAIL:john@example.com\nEND:VCARD</c:address-data></d:prop></d:propstat></d:response>"
    b"</d:multistatus>"
)


class _Resp:
    def __init__(self, content: bytes, status: int = 207):
        self.content = content
        self.status_code = status


class _FakeClient:
    """Stands in for TesseraCalDAVClient: routes brokered_dav() to canned XML."""

    def __init__(self, report_xml: bytes = _REPORT_XML):
        self.calls: list[tuple[str, str]] = []
        self._rules = [
            (lambda m, u: m == "PROPFIND" and u == "https://contacts.icloud.com/", _PRINCIPAL_XML),
            (lambda m, u: m == "PROPFIND" and "principal" in u, _HOMESET_XML),
            (lambda m, u: m == "PROPFIND" and "carddavhome/" in u, _BOOKS_XML),
            (lambda m, u: m == "REPORT", report_xml),
        ]
        self._report_xml = report_xml

    def brokered_dav(self, url, method, body="", headers=None):
        self.calls.append((method, url))
        for pred, xml in self._rules:
            if pred(method, url):
                return _Resp(xml)
        raise AssertionError(f"unexpected brokered hop: {method} {url}")


# ── least-disclosure (the security-critical property) ────────────────────────
def test_summarize_vcard_drops_photo_and_notes():
    vcard = (
        "BEGIN:VCARD\nVERSION:3.0\nFN:Maria Hont\nN:Hont;Maria;;;\n"
        "EMAIL;TYPE=HOME:maria@example.com\nTEL;TYPE=CELL:+40 712 345 678\n"
        "ORG:Acme;Engineering\nPHOTO;ENCODING=b:SECRETBASE64\n"
        "NOTE:private note do not leak\nADR:;;1 Secret St;City;;;\nEND:VCARD"
    )
    out = summarize_vcard(vcard)
    assert out == {
        "name": "Maria Hont",
        "emails": ["maria@example.com"],
        "phones": ["+40 712 345 678"],
        "org": "Acme",
    }
    blob = str(out)
    assert "SECRETBASE64" not in blob
    assert "private note" not in blob
    assert "Secret St" not in blob


def test_summarize_vcard_unfolds_and_unescapes_and_caps():
    vcard = (
        "BEGIN:VCARD\nVERSION:3.0\nFN:Ana-Maria O'Bri\n en\n"  # folded mid-value
        "ORG:Big\\, Corp\n"  # escaped comma
        "EMAIL:a@x.com\nEMAIL:b@x.com\nEMAIL:c@x.com\nEMAIL:d@x.com\nEMAIL:e@x.com\n"
        "END:VCARD"
    )
    out = summarize_vcard(vcard)
    assert out["name"] == "Ana-Maria O'Brien"  # unfolded continuation
    assert out["org"] == "Big, Corp"  # escaped comma unescaped
    assert len(out["emails"]) == 4  # capped at max_each


def test_summarize_vcard_none_when_empty():
    assert summarize_vcard("BEGIN:VCARD\nVERSION:3.0\nEND:VCARD") is None


# ── DAV XML parsing ──────────────────────────────────────────────────────────
def test_parse_helpers():
    assert _first_href(_parse(_PRINCIPAL_XML), "current-user-principal") == "/123/principal/"
    assert (
        _first_href(
            _parse(_HOMESET_XML), "addressbook-home-set", ns="urn:ietf:params:xml:ns:carddav"
        )
        == "/123/carddavhome/"
    )
    assert _addressbook_hrefs(_parse(_BOOKS_XML)) == ["/123/carddavhome/card/"]
    texts = _vcard_texts(_parse(_REPORT_XML))
    assert len(texts) == 2 and all("BEGIN:VCARD" in t for t in texts)


def test_parse_rejects_unparseable():
    with pytest.raises(AppleEgressError):
        _parse(b"<not-xml")


# ── find_contacts orchestration: discovery -> search -> filter + cap ─────────
def test_find_contacts_searches_filters_and_is_least_disclosure():
    client = _FakeClient()
    result = find_contacts(client, "hont", limit=10)

    assert result["query"] == "hont"
    assert result["count"] == 1  # only Maria Hont matches; John Smith filtered out
    contact = result["contacts"][0]
    assert contact["name"] == "Maria Hont"
    assert contact["emails"] == ["maria@example.com"]
    assert contact["phones"] == ["+40 712 345 678"]
    assert contact["org"] == "Acme"
    # the photo + note are nowhere in the serialized result
    blob = str(result)
    assert "SECRETBASE64" not in blob and "medical note" not in blob
    # the discovery chain ran (principal -> homeset -> books -> report)
    assert [m for m, _ in client.calls] == ["PROPFIND", "PROPFIND", "PROPFIND", "REPORT"]


def test_find_contacts_requires_min_query():
    client = _FakeClient()
    with pytest.raises(AppleEgressError):
        find_contacts(client, "a", limit=5)
    assert client.calls == []  # rejected before any egress


def test_find_contacts_hard_caps_limit():
    # A REPORT that returns 30 matching contacts must still cap at _MAX_RESULTS=25.
    rows = b"".join(
        b"<d:response><d:href>/123/carddavhome/card/%d.vcf</d:href><d:propstat><d:prop>"
        b"<c:address-data>BEGIN:VCARD\nVERSION:3.0\nFN:Hont Person %d\nEND:VCARD"
        b"</c:address-data></d:prop></d:propstat></d:response>" % (i, i)
        for i in range(30)
    )
    report = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
        + rows
        + b"</d:multistatus>"
    )
    result = find_contacts(_FakeClient(report_xml=report), "hont", limit=100)
    assert result["count"] == 25  # hard cap, regardless of the requested limit
