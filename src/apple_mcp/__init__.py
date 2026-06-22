"""apple-mcp — credential-free MCP for Apple iCloud Calendar (CalDAV), brokered
through Tessera.

The MCP holds NO Apple secret. Every iCloud request is forwarded to Tessera's
egress proxy (``ANY /v1/egress/apple-caldav``), which injects the Apple ID +
app-specific password (HTTP Basic) and returns only the result — the credential
never reaches this process. See README.md and ADR 0022 (tessera repo).
"""

__version__ = "0.1.0"
