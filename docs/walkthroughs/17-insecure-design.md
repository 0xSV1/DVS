# Insecure Design

OWASP: https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
CWE: CWE-1059

Insecure design refers to weaknesses in the application's architecture and design decisions, rather than implementation bugs. This meta-challenge tests the ability to identify vulnerability classes by reviewing source code and understanding the difference between secure and insecure implementations.

---

## Read the Diff, Ship the Fix (`view_source_puzzle`)

**Difficulty:** Tech Lead
**CWE:** CWE-1059
**Route:** `GET /source/<module>` (view code), `POST /source/submit` (submit reports)

### How It Works

This challenge is unique: instead of exploiting a vulnerability, you must demonstrate security knowledge by correctly identifying vulnerability classes and their mitigations across multiple modules.

**Exploit:**

1. Navigate to the View Source feature at `/source/<module>` for at least 3 different vulnerability modules
2. Compare the intern tier handler (vulnerable) with the tech_lead tier handler (secure)
3. For each module, identify:
   - The CWE number of the vulnerability in the intern code
   - A description of the specific defensive technique used in the tech_lead code

4. Submit reports for 3 or more distinct modules:

```bash
curl -X POST http://localhost:8000/source/submit \
  -H "Content-Type: application/json" \
  -d '{
    "reports": [
      {"module": "sqli", "cwe": "89", "fix": "Use parameterized queries with bound parameters"},
      {"module": "xss", "cwe": "79", "fix": "Bleach allowlist sanitization with Content Security Policy"},
      {"module": "ssti", "cwe": "1336", "fix": "Never compile user input as template source"}
    ]
  }'
```

**Solve condition:** The challenge solves when correct reports are submitted for 3 or more distinct modules. Each report must contain the correct CWE number and a fix description matching the expected keyword pattern.

### Module Answer Reference

Each module has specific CWE numbers and fix keyword patterns:

| Module | CWE | Fix Keywords |
|--------|-----|-------------|
| sqli | 89 | parameterize, prepared statement, bound param, placeholder, bindparam |
| xss | 79 | bleach, allowlist, sanitize, CSP, content security policy, escape |
| idor | 639 | ownership check, authorization, access control |
| ssti | 1336 | sandbox, escape, no template compilation |
| upload | 434 | magic byte, content validation, allowlist, outside webroot |
| ssrf | 918 | allowlist, whitelist, URL validation |
| csrf | 352 | CSRF token, synchronizer, SameSite, origin validation |
| crypto | 328, 798 | bcrypt, scrypt, argon2, strong hash, key management |
| deserialize | 502 | JSON, safe format, schema validation, no pickle |
| misconfig | 215, 200 | disable debug, remove endpoint, deny by default |
| mass_assign | 915 | allowlist, field filter, explicit fields |
| open_redirect | 601 | relative path, URL validation, deny external |
| broken_logging | 532 | access control, sanitize, no sensitive data |
| log_injection | 117 | control character strip, integrity hash, session username |

**Why it works:** This challenge validates that learners understand not just how to exploit vulnerabilities, but how to identify and fix them. Code review skills are essential for security engineers: recognizing vulnerability patterns in source code and articulating specific defensive measures. Generic answers like "add security" will not pass; the fix description must reference the specific technique used.

### Tier Relevance

This is a tech_lead tier challenge because it requires security knowledge across multiple domains. There is no exploit to execute; the challenge tests analytical and defensive skills. The source code comparison between intern (maximally vulnerable) and tech_lead (reference implementation) provides a clear contrast for each vulnerability class.
