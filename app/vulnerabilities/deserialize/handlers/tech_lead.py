"""
Insecure Deserialization: Preferences Loader, Tech Lead Tier (Secure)

OWASP: A08:2025 Software and Data Integrity Failures
CWE: CWE-502 (Deserialization of Untrusted Data)
Difficulty: Tech Lead

Mitigation: Uses JSON (no code execution risk) with strict schema
validation. Only allowed keys are accepted; unexpected fields are
silently dropped. Value types are validated before acceptance.

This is the reference secure implementation.
"""

from __future__ import annotations

import base64
import json

ALLOWED_KEYS = {"theme", "language", "notifications"}

DEFAULT_PREFS = {"theme": "dark", "language": "en", "notifications": True}


def get_default_prefs() -> tuple[str, str]:
    """Return base64-encoded default prefs and format name."""
    encoded = base64.b64encode(json.dumps(DEFAULT_PREFS).encode()).decode()
    return encoded, "JSON (base64)"


def handle_load(raw: bytes, unsafe_enabled: bool) -> dict:
    """Load preferences from JSON with strict schema validation.

    Only keys in ALLOWED_KEYS are accepted. Extra keys (like "role"
    or "is_admin") are silently dropped.

    Args:
        raw: Raw bytes after base64 decoding.
        unsafe_enabled: Unused at this tier (no dangerous operations).

    Returns:
        Result dict with success, prefs, and error.
    """
    result: dict = {"success": False, "prefs": None, "error": None}
    try:
        prefs = json.loads(raw)
        if not isinstance(prefs, dict):
            result["error"] = "Expected a JSON object"
            return result
        filtered = {k: v for k, v in prefs.items() if k in ALLOWED_KEYS}
        result = {"success": True, "prefs": filtered, "error": None}
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
        # Raw pickle bytes (0x80 header) land here as UnicodeDecodeError since
        # json.loads tries to decode to str first; treat as invalid input.
        result["error"] = f"Invalid JSON: {e}"
    return result
