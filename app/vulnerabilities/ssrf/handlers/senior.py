"""SSRF: Senior Tier (Code Reviewed)

OWASP: A01:2025 Broken Access Control
CWE: CWE-918 (Server-Side Request Forgery)
Difficulty: Senior

Vulnerability: Resolves DNS and checks if IP is private, but only checks
the initial resolution. Vulnerable to DNS rebinding: first resolution
returns a public IP (passes check), but the actual HTTP request resolves
to a different (internal) IP. Also allows file:// and other schemes.

Exploit: DNS rebinding attack or file:///etc/passwd
Fix: Check resolved IP at connection time (see tech_lead.py)
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx


async def handle_fetch(url: str) -> dict:
    """Fetch a URL with DNS resolution check (vulnerable to rebinding).

    Args:
        url: User-supplied URL with pre-flight DNS check.

    Returns:
        Dict with response body or error.
    """
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        return {"success": False, "error": "Only http/https schemes allowed"}

    hostname = parsed.hostname
    if not hostname:
        return {"success": False, "error": "Invalid URL"}

    # Pre-flight DNS resolution check
    try:
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {
                "success": False,
                "error": f"Blocked: {hostname} resolves to private IP {ip}",
            }
    except socket.gaierror:
        return {"success": False, "error": f"DNS resolution failed for {hostname}"}

    # Fetch (DNS may resolve differently now: rebinding window)
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.get(url)
            return {
                "success": True,
                "status_code": resp.status_code,
                "content": resp.text[:5000],
                "resolved_ip": ip,
                "method": "Pre-flight DNS check for private IPs. Vulnerable to DNS rebinding.",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}
