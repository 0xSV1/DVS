# Security Misconfiguration

OWASP: https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
CWE: CWE-215, CWE-942, CWE-200, CWE-798

Security misconfiguration covers debug endpoints left enabled in production, overly permissive CORS policies, exposed sensitive files, and credentials left in accessible locations. These are configuration errors rather than code vulnerabilities, but they provide attackers with information and access that enables further exploitation.

---

## We'll Turn It Off Before Launch (`misconfig_debug`)

**Difficulty:** Intern
**CWE:** CWE-215
**Route:** `GET /challenges/misconfig/debug`

### Intern Tier

**Vulnerability:** The debug endpoint is enabled and returns a full environment dump including `SECRET_KEY`, `DATABASE_URL`, `CTF_KEY`, `JWT_SECRET`, and the complete contents of `os.environ`.

**Exploit:**

1. Navigate to:

```
GET /challenges/misconfig/debug
```

2. The response contains all application secrets in plaintext, including:
   - `SECRET_KEY` (session signing)
   - `DATABASE_URL` (database connection string)
   - `CTF_KEY` (flag generation key)
   - `JWT_SECRET` (token signing secret)

**Solve condition:** The challenge solves on any visit to the debug endpoint at intern, junior, or senior tiers.

**Why it works:** Debug endpoints are meant for local development. When left enabled in production, they expose internal application state that attackers use to forge sessions, access databases, and compromise other security controls.

### Junior Tier

**What changed:** Same as intern. Full environment dump exposed.

### Senior Tier

**What changed:** The debug endpoint returns only non-sensitive application configuration: version number, debug flag status, and database type. Secrets are excluded.

**Why the challenge still solves:** The endpoint should not exist in production at all. Even sanitized debug information (version, database type) aids reconnaissance.

### Tech Lead Tier

**Defense:** The debug endpoint returns 404 Not Found. No debug information is exposed regardless of request parameters.

**Why it works:** Debug endpoints are disabled entirely in production. CWE-215 is addressed by removing the information exposure vector.

---

## Access-Control-Allow-Yolo (`misconfig_cors`)

**Difficulty:** Junior
**CWE:** CWE-942
**Route:** `GET /challenges/misconfig/cors-test`

### Intern Tier

**Vulnerability:** The API returns wildcard CORS headers: `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. This combination tells browsers that any website can make credentialed cross-origin requests to this API.

**Exploit:**

1. Send any request to the CORS test endpoint:

```bash
curl -H "Origin: https://evil.com" http://localhost:8000/challenges/misconfig/cors-test
```

2. The response headers include:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

3. An attacker's JavaScript on `evil.com` can now make authenticated requests to the API and read the responses.

**Solve condition:** The challenge auto-solves on any visit at intern tier. At junior and senior tiers, the challenge solves when a cross-origin `Origin` header is present in the request.

**Why it works:** CORS headers control which origins can read API responses. A wildcard with credentials enabled means any website can impersonate the logged-in user, reading private data and performing actions on their behalf.

### Junior Tier

**What changed:** The server no longer returns a static wildcard. Instead, it reflects the `Origin` header directly in `Access-Control-Allow-Origin`. This looks more secure than `*` but trusts any origin that sends the header.

**Exploit:**

```bash
curl -H "Origin: https://evil.com" http://localhost:8000/challenges/misconfig/cors-test
```

Response:

```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
```

The server echoes back whatever origin is sent. An attacker's page at `evil.com` can make credentialed requests and read responses, because the browser sees its own origin in the `Access-Control-Allow-Origin` header.

### Senior Tier

**What changed:** The server still reflects the `Origin` header without validation, but the response is slightly different: no `Access-Control-Allow-Methods` header is set. The `.env` file is no longer served (returns 404). The debug endpoint returns partial config only (no secrets). However, the CORS misconfiguration remains exploitable.

**Exploit:**

```bash
curl -H "Origin: https://evil.com" http://localhost:8000/challenges/misconfig/cors-test
```

The origin is reflected in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, allowing any attacker-controlled origin to make credentialed cross-origin requests.

### Tech Lead Tier

**Defense:** Same-origin only. No CORS headers are set, meaning only pages served from the application's own origin can make API requests.

**Why it works:** By not sending CORS headers, the browser's same-origin policy blocks all cross-origin requests. CWE-942 is addressed by enforcing strict origin restrictions.

---

## Exposed Config Files (`info_disclosure`)

**Difficulty:** Intern
**CWE:** CWE-200
**Route:** `GET /challenges/misconfig/.env`

### Intern Tier

**Vulnerability:** The `.env` file is served directly via URL traversal. It contains all application secrets in plaintext: Stripe API keys, AWS credentials, database passwords, and other configuration values.

**Exploit:**

1. Navigate to:

```
GET /challenges/misconfig/.env
```

2. The response contains the full `.env` file with hardcoded secrets:

```
STRIPE_KEY=sk_live_...
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
DATABASE_PASSWORD=...
```

**Solve condition:** The challenge solves when the `.env` file is successfully returned (HTTP 200) at any tier except tech_lead.

**Why it works:** Dotfiles like `.env` contain configuration secrets that should never be served by the web server. Static file handlers that serve entire directories without exclusion patterns expose these files to anyone who knows the conventional filenames.

### Junior Tier

**What changed:** Same as intern. The `.env` file is served without restriction.

### Senior Tier

**What changed:** The `.env` file returns 404. The file is excluded from static file serving. However, other configuration files may still be accessible.

### Tech Lead Tier

**Defense:** All sensitive files return 404. Static file serving is restricted to an explicit allowlist of public assets.

**Why it works:** Sensitive configuration files are excluded from the web-accessible directory. CWE-200 is addressed by preventing unauthorized access to internal files.

---

## deploybro secrets --dump (`terminal_cred_leak`)

**Difficulty:** Intern
**CWE:** CWE-798
**Route:** Interactive terminal at `/challenges/terminal`

### Intern Tier

**Vulnerability:** The simulated filesystem contains credential files in standard locations. AWS credentials, API keys, database URLs, and admin passwords are stored in plaintext in the user's home directory.

**Exploit:**

1. Navigate to `/challenges/terminal`
2. Explore the home directory:

```
ls -la /home/deploybro/.deploybro/
```

3. Read the credentials file:

```
cat /home/deploybro/.deploybro/credentials.json
```

4. The file contains:

```json
{
  "aws_access_key_id": "AKIAIOSFODNN7DEPLOYBRO",
  "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEPLOYBRO",
  "stripe_key": "sk_live_51DeployBroFakeKeyDontUse",
  "admin_password": "deploybro_admin_2024"
}
```

5. Also check the application's `.env` file:

```
cat /home/deploybro/projects/deploybro-app/.env
```

**Solve condition:** The challenge solves when either sensitive file is read (`condition: lambda: True`).

**Why it works:** Credentials stored on the filesystem in plaintext are accessible to anyone with shell access. Real-world examples include AWS `~/.aws/credentials`, Docker configs, SSH keys, and application `.env` files. Discovery is straightforward through standard directory enumeration.

### Junior Tier

**What changed:** Same credential files, same plaintext content. No additional protection.

### Senior Tier

**What changed:** Credentials are partially redacted with a note: "Partially redacted. Full creds in vault." Key material is masked but the file structure reveals what secrets exist.

### Tech Lead Tier

**Defense:** All credential values are replaced with `[REDACTED by security team]`. A message indicates credentials have been rotated and moved to HashiCorp Vault. No recoverable secrets remain on the filesystem.

**Why it works:** Secrets management systems (Vault, AWS Secrets Manager) provide centralized, auditable, and rotatable credential storage. Removing plaintext credentials from the filesystem eliminates CWE-798 by ensuring secrets are never stored alongside code or configuration.
