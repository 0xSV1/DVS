"""File Upload: Intern Tier (Deployed Blindly)

OWASP: A01:2025 Broken Access Control
CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
Difficulty: Intern

Vulnerability: No file type validation, no size limit, original filename
used directly. Files stored in a web-accessible directory. Path traversal
possible via filename manipulation.

Exploit: Upload a .py/.php/.html file with malicious content.
Fix: Validate MIME type, generate UUID filenames, store outside webroot (see tech_lead.py)
"""

from __future__ import annotations

from pathlib import Path

from fastapi import UploadFile

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "static" / "uploads"


async def handle_upload(file: UploadFile) -> dict:
    """Save uploaded file with zero validation.

    Args:
        file: The uploaded file, saved as-is with original filename.

    Returns:
        Dict with upload result and file URL.
    """
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    # AI said using the original filename is fine
    filename = file.filename or "unnamed"
    file_path = UPLOAD_DIR / filename

    content = await file.read()
    file_path.write_bytes(content)

    return {
        "success": True,
        "filename": filename,
        "url": f"/static/uploads/{filename}",
        "size": len(content),
        "content_type": file.content_type,
        "method": "No validation. Original filename. Web-accessible directory.",
    }
