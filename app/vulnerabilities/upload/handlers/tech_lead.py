"""File Upload: Tech Lead Tier (Actually Secure)

OWASP: A01:2025 Broken Access Control
CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
Difficulty: Tech Lead

Security: Extension allowlist, magic byte validation (not Content-Type
header), UUID filename, size limit, and files stored outside the web-
accessible static directory. This is the reference implementation.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import UploadFile

from app.core.config import BASE_DIR

# Store outside webroot
UPLOAD_DIR = BASE_DIR / "data" / "uploads"
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}

# Magic byte signatures for validation
MAGIC_BYTES = {
    b"\xff\xd8\xff": ".jpg",
    b"\x89PNG": ".png",
    b"GIF87a": ".gif",
    b"GIF89a": ".gif",
    b"%PDF": ".pdf",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


async def handle_upload(file: UploadFile) -> dict:
    """Save uploaded file with comprehensive validation.

    Args:
        file: The uploaded file, validated by extension, magic bytes, and size.

    Returns:
        Dict with upload result or error.
    """
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    original_name = file.filename or "unnamed"
    ext = Path(original_name).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        return {"success": False, "error": f"Extension {ext} not allowed"}

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        return {
            "success": False,
            "error": f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)",
        }

    # Validate magic bytes (skip for .txt)
    if ext != ".txt":
        valid_magic = False
        for magic, expected_ext in MAGIC_BYTES.items():
            if content[: len(magic)] == magic:
                if ext in (".jpg", ".jpeg") and expected_ext == ".jpg":
                    valid_magic = True
                elif ext == expected_ext:
                    valid_magic = True
                break

        if not valid_magic:
            return {
                "success": False,
                "error": "File content does not match extension (magic byte check failed)",
            }

    # UUID filename, stored outside webroot
    safe_name = f"{uuid.uuid4().hex}{ext}"
    file_path = UPLOAD_DIR / safe_name
    file_path.write_bytes(content)

    return {
        "success": True,
        "filename": safe_name,
        "original_name": original_name,
        "size": len(content),
        "stored": "Outside webroot (not directly accessible)",
        "method": "Extension allowlist + magic byte validation + UUID name + outside webroot.",
    }
