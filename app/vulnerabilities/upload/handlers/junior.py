"""File Upload: Junior Tier (Copilot Assisted)

OWASP: A01:2025 Broken Access Control
CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
Difficulty: Junior

Vulnerability: Extension blacklist that blocks .py, .php, .exe but
misses .html, .svg, .phtml, double extensions (.py.jpg), and null bytes.
Still uses original filename. Client-side size validation only.

Exploit: Upload file.html, file.phtml, or file.py.jpg
Fix: Use allowlist and UUID filenames (see tech_lead.py)
"""

from __future__ import annotations

from pathlib import Path

from fastapi import UploadFile

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "static" / "uploads"
BLOCKED_EXTENSIONS = {".py", ".php", ".exe", ".sh", ".bat", ".cmd", ".ps1"}


async def handle_upload(file: UploadFile) -> dict:
    """Save uploaded file with extension blacklist.

    Args:
        file: The uploaded file, checked against an incomplete blacklist.

    Returns:
        Dict with upload result or error.
    """
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    filename = file.filename or "unnamed"
    ext = Path(filename).suffix.lower()

    # "Security" check: block dangerous extensions
    if ext in BLOCKED_EXTENSIONS:
        return {
            "success": False,
            "error": f"File type {ext} is not allowed",
            "method": "Extension blacklist. Misses .html, .svg, double extensions.",
        }

    content = await file.read()
    file_path = UPLOAD_DIR / filename
    file_path.write_bytes(content)

    return {
        "success": True,
        "filename": filename,
        "url": f"/static/uploads/{filename}",
        "size": len(content),
        "content_type": file.content_type,
        "method": "Extension blacklist only. Original filename retained.",
    }
