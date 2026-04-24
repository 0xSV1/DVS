"""File Upload: Senior Tier (Code Reviewed)

OWASP: A01:2025 Broken Access Control
CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
Difficulty: Senior

Vulnerability: Extension allowlist and MIME type check, but MIME is
read from the Content-Type header (client-controlled). UUID filename
prevents path traversal but files are still in a web-accessible directory.

Exploit: Set Content-Type to image/jpeg while uploading an HTML file.
Fix: Check file magic bytes, store outside webroot (see tech_lead.py)
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import UploadFile

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "static" / "uploads"
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}
ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "application/pdf",
    "text/plain",
}


async def handle_upload(file: UploadFile) -> dict:
    """Save uploaded file with allowlist and MIME check (header-based).

    Args:
        file: The uploaded file, validated by extension and Content-Type header.

    Returns:
        Dict with upload result or error.
    """
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    original_name = file.filename or "unnamed"
    ext = Path(original_name).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        return {"success": False, "error": f"Extension {ext} not allowed"}

    # Check MIME type (from header, not from file content)
    if file.content_type not in ALLOWED_MIME_TYPES:
        return {"success": False, "error": f"MIME type {file.content_type} not allowed"}

    # UUID filename prevents path traversal
    safe_name = f"{uuid.uuid4().hex}{ext}"
    content = await file.read()

    # Size limit: 5MB
    if len(content) > 5 * 1024 * 1024:
        return {"success": False, "error": "File too large (max 5MB)"}

    file_path = UPLOAD_DIR / safe_name
    file_path.write_bytes(content)

    return {
        "success": True,
        "filename": safe_name,
        "original_name": original_name,
        "url": f"/static/uploads/{safe_name}",
        "size": len(content),
        "method": "Extension allowlist + MIME header check + UUID name. But MIME is client-controlled.",
    }
