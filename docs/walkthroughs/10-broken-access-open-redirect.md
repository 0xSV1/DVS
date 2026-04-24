# Open Redirect

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-601

Open redirect occurs when an application accepts a user-controlled URL and redirects the browser to it without validation. Attackers use this to craft phishing links that appear to come from the trusted domain but redirect victims to malicious sites.

---

## Redirect to My Portfolio (`open_redirect`)

**Difficulty:** Intern
**CWE:** CWE-601
**Route:** `GET /redirect?url=<target>`

### Intern Tier

**Vulnerability:** The redirect endpoint accepts any URL in the `url` parameter and issues an HTTP redirect with no validation.

**Exploit:**

1. Craft a link that uses the application's domain but redirects to an attacker-controlled site:

```
http://localhost:8000/redirect?url=https://evil.com/phishing-login
```

2. When a victim clicks the link, they see the trusted domain in the initial URL but are redirected to `evil.com`.

**Solve condition:** The challenge solves when the URL starts with `http` (indicating an external redirect). The `is_external` flag is set to `True`.

**Why it works:** Users trust the domain in the link they click. The redirect happens transparently, and the victim ends up on a phishing page that mimics the original application's login form. This is commonly chained with social engineering attacks.

### Junior Tier

**What changed:** No change from intern. Redirects to any URL are permitted.

**Exploit:** Same payload as intern tier.

### Senior Tier

**What changed:** The handler blocks URLs starting with `http://` and `https://`. However, protocol-relative URLs (`//`) are not blocked.

**Bypass:**

```
http://localhost:8000/redirect?url=//evil.com/phishing-login
```

Browsers resolve `//evil.com` using the current page's protocol (http or https), resulting in a redirect to the attacker's site.

Note: The handler may set `is_external = False` for protocol-relative URLs, which means the solve condition may not trigger via this path. The senior tier demonstrates the defense gap without triggering the flag.

### Tech Lead Tier

**Defense:** Only relative paths starting with a single `/` are allowed. Double slashes (`//`), all URL schemes, and absolute URLs are rejected. The redirect destination must be a path within the application.

**Why it works:** By restricting redirects to relative paths, the application ensures the browser stays on the same origin. No external domain can be reached through the redirect endpoint. This addresses CWE-601 through input validation that enforces local-only navigation.
