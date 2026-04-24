"""
Insecure Deserialization: Preferences Loader, Intern Tier (Deployed Blindly)

OWASP: A08:2025 Software and Data Integrity Failures
CWE: CWE-502 (Deserialization of Untrusted Data)
Difficulty: Intern

Vulnerability: Raw pickle.loads() on user-supplied data with zero validation.
Pickle deserialization executes arbitrary Python code via __reduce__.

Exploit: Craft a pickle payload with os.system() or subprocess call,
         base64-encode it, and submit as preferences data.
Fix: Never deserialize untrusted data with pickle. Use JSON with schema
     validation (see tech_lead.py).
"""

from __future__ import annotations

import base64
import pickle

DEFAULT_PREFS = {
    "theme": "dark",
    "language": "en",
    "notifications": True,
    "role": "user",
}


def get_default_prefs() -> tuple[str, str]:
    """Return base64-encoded default prefs and format name."""
    encoded = base64.b64encode(pickle.dumps(DEFAULT_PREFS)).decode()
    return encoded, "pickle (base64)"


def handle_load(raw: bytes, unsafe_enabled: bool) -> dict:
    """Load preferences from pickle data.

    When UNSAFE_CHALLENGES is False, detects RCE payloads without executing them.
    When True, actually calls pickle.loads (dangerous).

    Args:
        raw: Raw bytes after base64 decoding.
        unsafe_enabled: Whether UNSAFE_CHALLENGES is set.

    Returns:
        Result dict with success, prefs, error, and optional _solved flag.
    """
    result: dict = {"success": False, "prefs": None, "error": None}

    if not unsafe_enabled:
        # Simulate pickle behavior without actual execution
        result["error"] = (
            "Pickle deserialization is disabled (UNSAFE_CHALLENGES=false). "
            "In a real scenario, this would execute arbitrary Python code via __reduce__."
        )
        # Check for REDUCE opcode (0x52 = 'R') which triggers __reduce__,
        # plus common payload strings (os, system, subprocess, eval, exec)
        if b"\x52" in raw or b"os" in raw or b"system" in raw or b"subprocess" in raw or b"eval" in raw:
            result["error"] += "\n\nChallenge solved: RCE payload detected in pickle data."
            result["_solved"] = True
        return result

    # Actually dangerous: pickle.loads with untrusted data
    # AI said this is fine
    try:
        prefs = pickle.loads(raw)  # noqa: S301
        result = {"success": True, "prefs": str(prefs), "error": None}
        if not isinstance(prefs, dict) or "role" not in prefs:
            result["_solved"] = True
    except Exception as e:
        result["error"] = f"Deserialization failed: {e}"

    return result
