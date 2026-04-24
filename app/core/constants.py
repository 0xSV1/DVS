from __future__ import annotations

from enum import Enum


class Difficulty(str, Enum):
    """Four-tier difficulty system mirroring DVWA's model with deploy bro theme.

    Intern:    Zero security. Raw f-strings, no auth, hardcoded secrets.
    Junior:    Cosmetic security. Client-side validation, incomplete blacklists.
    Senior:    Real security with subtle flaws. ORM with raw fallbacks, CSP with unsafe-inline.
    Tech Lead: Actually secure. The reference implementation.
    """

    INTERN = "intern"
    JUNIOR = "junior"
    SENIOR = "senior"
    TECH_LEAD = "tech_lead"


# All valid difficulty values for validation
VALID_DIFFICULTIES = {d.value for d in Difficulty}

# Flag prefix for CTF mode
FLAG_PREFIX = "DVS"

# Scoring per difficulty tier
SCORING = {
    1: 100,  # Intern
    2: 250,  # Junior
    3: 500,  # Senior
    4: 1000,  # Tech Lead
}

# Difficulty tier to numeric mapping
DIFFICULTY_TO_INT = {
    "intern": 1,
    "junior": 2,
    "senior": 3,
    "tech_lead": 4,
}

# Display labels
DIFFICULTY_LABELS = {
    "intern": "Intern (Deployed Blindly)",
    "junior": "Junior Dev (Bropilot-Assisted)",
    "senior": "Senior Dev (Code-Reviewed)",
    "tech_lead": "Tech Lead (Actually Secure)",
}

DIFFICULTY_COLORS = {
    "intern": "#22c55e",
    "junior": "#eab308",
    "senior": "#f97316",
    "tech_lead": "#3b82f6",
}
