# Server-Side Request Forgery

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-918

Server-side request forgery (SSRF) occurs when an application fetches a URL supplied by the user without validating the destination. The attacker makes the server send requests to internal services, cloud metadata endpoints, or other resources that are not directly accessible from the internet.

---

## Microservice Mischief (`ssrf_internal`)

**Difficulty:** Senior
**CWE:** CWE-918
**Route:** `POST /challenges/ssrf` or `GET /challenges/ssrf?url=<target>`

### Intern Tier

**Vulnerability:** The URL preview feature accepts any user-supplied URL and fetches it server-side with no validation. Redirects are followed.

**Exploit:**

1. Navigate to `/challenges/ssrf`
2. Enter the following URL:

```
http://169.254.169.254/latest/meta-data/
```

3. The server fetches the AWS metadata endpoint and returns the response, exposing IAM credentials and instance information.

Alternative targets:

```
http://localhost:8000/api/setup/reset
http://127.0.0.1:8000/health
http://[::1]:8000/health
```

**Solve condition:** The challenge solves when the fetch succeeds and the URL contains any of: `localhost`, `127.`, `0.0.0.0`, `::1`, `169.254`, `metadata`, `internal`.

**Why it works:** The server has network access to internal services that the attacker cannot reach directly. By making the server fetch a URL, the attacker pivots through the server's network position to access cloud metadata, internal APIs, and other services behind the firewall.

### Junior Tier

**What changed:** A blacklist blocks the strings: `localhost`, `127.0.0.1`, `169.254.169.254`, `metadata.google.internal`.

**Bypass:** The blacklist is incomplete. Alternative representations of localhost and internal addresses are not blocked:

```
http://0.0.0.0:8000/health
http://[::1]:8000/health
http://127.1:8000/health
http://0x7f000001:8000/health
http://2130706433:8000/health
```

**Exploit:**

```
http://0.0.0.0:8000/health
```

`0.0.0.0` resolves to the local machine on most systems but is not in the blacklist. IPv6 localhost `[::1]` and decimal/hex IP representations also bypass the check.

### Senior Tier

**What changed:** DNS resolution check validates that the target IP is not private, loopback, or link-local. Redirects are disabled. However, the check is vulnerable to time-of-check-time-of-use (TOCTOU) via DNS rebinding, and the `file://` scheme is not blocked.

**Bypass option 1: DNS rebinding**

1. Set up a DNS server that alternates responses: first resolve to a public IP (passes the check), then resolve to `127.0.0.1` (actual fetch hits localhost)
2. Submit the rebinding domain as the URL
3. The initial DNS check sees a public IP and allows the request. The actual HTTP fetch resolves to localhost.

**Bypass option 2: File scheme**

```
file:///etc/passwd
```

The handler validates HTTP destinations but does not block the `file://` protocol, which reads local files.

### Tech Lead Tier

**Defense:** Strict URL allowlist: only `example.com`, `httpbin.org`, and `api.github.com` are permitted. Only `https` scheme allowed. No redirects followed. Response size capped at 10,000 bytes.

**Why it works:** An allowlist approach is the only reliable SSRF defense. Blacklists can always be bypassed through encoding tricks, DNS rebinding, or protocol variations. By restricting destinations to known-good hosts, the attack surface is eliminated. This addresses CWE-918 through positive validation.
