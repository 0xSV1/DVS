"""CTFd challenge export: generates a CSV file compatible with CTFd import.

Usage:
    python -m app.ctf_export --key my-secret-key --output dvs_ctfd.csv

The CSV format follows CTFd's challenge import specification:
    name, category, description, value, type, flag
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import sys

import yaml

from app.core.config import BASE_DIR
from app.core.constants import SCORING


def generate_flag(ctf_key: str, challenge_key: str) -> str:
    """Generate a deterministic CTF flag using HMAC-SHA256."""
    mac = hmac.new(
        ctf_key.encode(),
        challenge_key.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"DVS{{{mac}}}"


def load_challenges() -> list[dict]:
    """Load challenge definitions from challenges.yml."""
    challenges_file = BASE_DIR / "data" / "challenges.yml"
    if not challenges_file.exists():
        print(f"Error: challenges file not found at {challenges_file}", file=sys.stderr)
        sys.exit(1)

    data = yaml.safe_load(challenges_file.read_text(encoding="utf-8"))
    return data.get("challenges", [])


def export_ctfd(ctf_key: str, output_path: str) -> None:
    """Export challenges to CTFd-compatible CSV."""
    challenges = load_challenges()

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # CTFd CSV header
        writer.writerow(["name", "category", "description", "value", "type", "flags"])

        for ch in challenges:
            flag = generate_flag(ctf_key, ch["key"])
            points = SCORING.get(ch.get("difficulty", 1), 100)
            description = ch.get("description", "")
            hint = ch.get("hint", "")
            if hint:
                description += f"\n\nHint: {hint}"

            writer.writerow(
                [
                    ch["name"],
                    ch.get("category", "Uncategorized"),
                    description,
                    points,
                    "standard",
                    flag,
                ]
            )

    print(f"Exported {len(challenges)} challenges to {output_path}")
    print(f"CTF key: {ctf_key[:4]}{'*' * (len(ctf_key) - 4)}")
    print("Flag format: DVS{hmac_sha256_hex}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export DVS challenges to CTFd-compatible CSV",
        prog="python -m app.ctf_export",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="HMAC secret key for flag generation (must match CTF_KEY in deployment)",
    )
    parser.add_argument(
        "--output",
        default="dvs_ctfd.csv",
        help="Output CSV file path (default: dvs_ctfd.csv)",
    )

    args = parser.parse_args()
    export_ctfd(args.key, args.output)


if __name__ == "__main__":
    main()
