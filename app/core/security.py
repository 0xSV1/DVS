"""JWT encoding/decoding and password hashing helpers.

Deliberately supports insecure modes at lower difficulty tiers:
- Intern: accepts JWT 'none' algorithm, MD5 passwords
- Tech Lead: strict HS256 with strong secret, bcrypt passwords
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

from app.core.config import settings

# Bcrypt context for tech_lead tier
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Deliberately weak JWT secret for intern/junior tiers
WEAK_JWT_SECRET = "secret"

# Token expiry
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(
    data: dict[str, Any],
    difficulty: str = "intern",
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token.

    At intern tier, uses a weak secret that can be brute-forced.
    At tech_lead tier, uses the application SECRET_KEY.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})

    if difficulty in ("intern", "junior"):
        # Weak secret, easily brute-forced
        return jwt.encode(to_encode, WEAK_JWT_SECRET, algorithm="HS256")

    # Senior and tech_lead use the strong secret
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str, difficulty: str = "intern") -> dict[str, Any] | None:
    """Decode and verify a JWT access token.

    At intern tier, accepts the 'none' algorithm (CWE-345).
    At tech_lead tier, strictly enforces HS256 with the strong secret.
    """
    try:
        if difficulty == "intern":
            # Accept any algorithm, including 'none'
            return jwt.decode(
                token,
                WEAK_JWT_SECRET,
                algorithms=["HS256", "none"],
                options={"verify_signature": False},
            )

        if difficulty == "junior":
            # Weak secret but at least verifies signature
            return jwt.decode(token, WEAK_JWT_SECRET, algorithms=["HS256"])

        if difficulty == "senior":
            # Strong secret but still accepts HS256 (vulnerable to key confusion
            # if RSA keys are ever introduced)
            return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

        # tech_lead: strict verification
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

    except jwt.PyJWTError:
        return None


def hash_password(password: str, difficulty: str = "intern") -> str:
    """Hash a password using the appropriate method for the difficulty tier.

    Intern/junior: unsalted MD5 (CWE-328).
    Senior: salted SHA-256 (better but not ideal).
    Tech Lead: bcrypt via passlib.
    """
    if difficulty in ("intern", "junior"):
        return hashlib.md5(password.encode()).hexdigest()
    if difficulty == "senior":
        return hashlib.sha256(password.encode()).hexdigest()
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str, difficulty: str = "intern") -> bool:
    """Verify a password against its hash.

    Method depends on difficulty tier to match the hashing approach.
    """
    if difficulty in ("intern", "junior"):
        return hashlib.md5(plain_password.encode()).hexdigest() == hashed_password
    if difficulty == "senior":
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password
    # tech_lead: try bcrypt first, fall back to checking if it's a plain/md5 match
    # (seed data uses md5, so tech_lead login still needs to work with seeded users)
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Fallback for seed data that uses MD5
        return hashlib.md5(plain_password.encode()).hexdigest() == hashed_password
