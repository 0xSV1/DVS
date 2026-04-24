"""Crypto Hashes: Tech Lead Tier (Secure Implementation)

OWASP: A04:2025 Cryptographic Failures
CWE: CWE-328 (Use of Weak Hash)
Difficulty: Tech Lead

Mitigation: No password hashes are exposed. The crack endpoint is disabled
entirely. In a real application, passwords would be hashed with bcrypt or
argon2id with per-user salts, and hash values would never leave the server.

Exploit: None. This is the reference secure implementation.
"""

from __future__ import annotations

from sqlalchemy.orm import Session


def handle_get_hashes(db: Session) -> list[dict]:
    """Return an empty list; hashes are not exposed at this tier.

    Args:
        db: Database session (unused, kept for interface consistency).

    Returns:
        Empty list.
    """
    return []


def handle_crack(db: Session, username: str, password: str) -> dict:
    """Reject all crack attempts; hash exposure is disabled.

    Args:
        db: Database session (unused).
        username: Target username (unused).
        password: Candidate password (unused).

    Returns:
        Dict with error message.
    """
    return {
        "success": False,
        "message": "Hash exposure disabled at this security tier.",
    }


# -- Hardcoded Secrets Challenge ------------------------------------------


def handle_get_secrets() -> dict:
    """Return page context with no key material whatsoever.

    Key is stored server-side only. Test endpoint returns boolean status,
    no key material sent to the client.

    Returns:
        Dict with no key data.
    """
    return {
        "api_key_plaintext": None,
        "fragments": None,
        "decoy": None,
    }


def handle_verify_secret(submitted_key: str) -> dict:
    """Reject all key submissions. No key material is available to extract.

    Args:
        submitted_key: The key submitted by the player (unused).

    Returns:
        Dict with rejection message.
    """
    return {
        "success": False,
        "message": "API keys are managed server-side via a secrets vault. No key material is exposed.",
    }
