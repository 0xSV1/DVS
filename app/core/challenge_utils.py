"""Challenge solve detection and flag generation.

Implements the Juice Shop-inspired solve_if() pattern:
- Check a condition function
- If met and challenge is unsolved, mark as solved
- Broadcast WebSocket notification
- Generate deterministic HMAC-SHA256 flag for CTF mode
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.services.websocket_manager import ConnectionManager

logger = logging.getLogger(__name__)


def generate_flag(challenge_key: str) -> str:
    """Generate a deterministic CTF flag using HMAC-SHA256.

    Same CTF_KEY + same challenge_key = same flag, enabling CTFd integration.
    """
    mac = hmac.new(
        settings.CTF_KEY.encode(),
        challenge_key.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"DVS{{{mac}}}"


async def solve_if(
    db: Session,
    challenge_key: str,
    condition: Callable[[], bool],
    ws_manager: ConnectionManager | None = None,
) -> str | None:
    """Check if a challenge solve condition is met and emit notification.

    Args:
        db: Database session.
        challenge_key: The challenge's unique key from challenges.yml.
        condition: A callable that returns True if the challenge is solved.
        ws_manager: Optional WebSocket manager for broadcasting notifications.

    Returns:
        The flag string if the challenge was just solved, None otherwise.
    """
    from app.models.challenge import Challenge

    challenge = db.query(Challenge).filter(Challenge.key == challenge_key).first()
    if not challenge:
        logger.warning("Challenge not found: %s", challenge_key)
        return None

    if challenge.solved:
        # Already solved, return flag if in CTF mode
        if settings.CTF_MODE:
            return generate_flag(challenge_key)
        return None

    try:
        if not condition():
            return None
    except Exception:
        logger.exception("Error evaluating solve condition for %s", challenge_key)
        return None

    # Mark as solved
    challenge.solved = True
    challenge.solved_at = datetime.now(timezone.utc)
    db.commit()

    flag = generate_flag(challenge_key) if settings.CTF_MODE else None

    logger.info("Challenge solved: %s (%s)", challenge.name, challenge_key)

    # Broadcast via WebSocket
    if ws_manager:
        try:
            await ws_manager.broadcast(
                json.dumps(
                    {
                        "type": "challenge_solved",
                        "key": challenge_key,
                        "name": challenge.name,
                        "flag": flag,
                    }
                )
            )
        except Exception:
            logger.exception("Failed to broadcast challenge solve for %s", challenge_key)

    return flag
