"""
Insecure Deserialization: Preferences Loader, Junior Tier

OWASP: A08:2025 Software and Data Integrity Failures
CWE: CWE-502 (Deserialization of Untrusted Data)
Difficulty: Junior

Vulnerability: Same as Intern tier. Still uses pickle.loads() with no
restrictions. A "junior developer" might add logging but not fix the
actual deserialization problem.

Exploit: Identical to Intern; craft a pickle RCE payload.
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

    Identical to intern tier. The junior developer added a comment
    saying "TODO: maybe don't use pickle?" but shipped it anyway.

    Args:
        raw: Raw bytes after base64 decoding.
        unsafe_enabled: Whether UNSAFE_CHALLENGES is set.

    Returns:
        Result dict with success, prefs, error, and optional _solved flag.
    """
    result: dict = {"success": False, "prefs": None, "error": None}

    if not unsafe_enabled:
        result["error"] = (
            "Pickle deserialization is disabled (UNSAFE_CHALLENGES=false). "
            "In a real scenario, this would execute arbitrary Python code via __reduce__."
        )
        if b"__reduce__" in raw or b"os" in raw or b"system" in raw or b"subprocess" in raw:
            result["error"] += "\n\nChallenge solved: RCE payload detected in pickle data."
            result["_solved"] = True
        return result

    # TODO: maybe don't use pickle? AI said it's fine for now
    try:
        prefs = pickle.loads(raw)  # noqa: S301
        result = {"success": True, "prefs": str(prefs), "error": None}
        if not isinstance(prefs, dict) or "role" not in prefs:
            result["_solved"] = True
    except Exception as e:
        result["error"] = f"Deserialization failed: {e}"

    return result
