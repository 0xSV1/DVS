"""
Insecure Deserialization: Preferences Loader, Senior Tier

OWASP: A08:2025 Software and Data Integrity Failures
CWE: CWE-502 (Deserialization of Untrusted Data)
Difficulty: Senior

Vulnerability: Uses JSON instead of pickle (no RCE), but performs no
schema validation. An attacker can inject unexpected fields like "role"
or "is_admin" that the application may trust downstream.

Exploit: Submit JSON with extra keys like {"role": "admin", "is_admin": true}
         to escalate privileges if the app blindly trusts deserialized data.
Fix: Validate against an allowlist of expected keys and value types
     (see tech_lead.py).
"""

from __future__ import annotations

import base64
import json

DEFAULT_PREFS = {
    "theme": "dark",
    "language": "en",
    "notifications": True,
    "role": "user",
}


def get_default_prefs() -> tuple[str, str]:
    """Return base64-encoded default prefs and format name."""
    encoded = base64.b64encode(json.dumps(DEFAULT_PREFS).encode()).decode()
    return encoded, "JSON (base64)"


def handle_load(raw: bytes, unsafe_enabled: bool) -> dict:
    """Load preferences from JSON data without schema validation.

    No pickle, so no RCE risk. But any JSON keys are accepted,
    allowing mass assignment style attacks.

    Args:
        raw: Raw bytes after base64 decoding.
        unsafe_enabled: Unused at this tier (no dangerous operations).

    Returns:
        Result dict with success, prefs, and error.
    """
    result: dict = {"success": False, "prefs": None, "error": None}
    try:
        prefs = json.loads(raw)
        result = {"success": True, "prefs": prefs, "error": None}
    except ValueError as e:
        result["error"] = f"Invalid JSON: {e}"
    return result
