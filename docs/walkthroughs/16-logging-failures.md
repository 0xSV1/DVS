# Security Logging and Alerting Failures

OWASP: https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/
CWE: CWE-532, CWE-117

Logging failures cover two categories: logging too much sensitive data (exposing credentials, PII, and session tokens in audit trails) and logging too little or in a way that allows injection (enabling attackers to forge log entries and cover their tracks).

---

## console.log(password) (`broken_logging`)

**Difficulty:** Junior
**CWE:** CWE-532
**Route:** `GET /challenges/logging`

### Intern Tier

**Vulnerability:** The audit log records everything, including sensitive data. When users perform actions like login, password change, or API key generation, the full details (including passwords and tokens) are written to the log. The log viewer endpoint has no access control.

**Exploit:**

1. Navigate to:

```
GET /challenges/logging
```

2. The page displays the full audit trail with all fields: `id`, `action`, `resource`, `details`, `ip_address`, `user_id`, `created_at`
3. The `details` field contains sensitive data from user actions (passwords, tokens, session data)

**Solve condition:** The challenge solves automatically when the log page loads at intern or junior tiers.

**Why it works:** Audit logs are meant to track who did what for security monitoring. When they record sensitive values (passwords, API keys, session tokens), anyone with log access gains access to all those credentials. Log files are often backed up, shipped to SIEM systems, and retained for years, amplifying the exposure.

### Junior Tier

**What changed:** Same as intern. Full log exposure with no access restrictions.

### Senior Tier

**What changed:** The `details` field is omitted from the log display. The remaining fields (`id`, `action`, `resource`, `user_id`) still enable user activity enumeration, but credential exposure is eliminated.

The challenge does not solve at this tier because the solve condition only fires for intern and junior.

### Tech Lead Tier

**Defense:** Access control enforced: the log endpoint returns an empty list unless `current_user.role == "admin"`. Admin users see a sanitized view: `id`, `action`, `resource`, `user_id`, `created_at`. No sensitive details are logged or displayed.

**Why it works:** Log access is restricted to authorized personnel. Sensitive fields are never written to logs in the first place. CWE-532 is addressed by logging only non-sensitive operational data and enforcing access control on log viewers.

---

## Fake It Till You Ship It (`log_injection`)

**Difficulty:** Junior
**CWE:** CWE-117
**Route:** `POST /challenges/log-injection/submit`

### Intern Tier

**Vulnerability:** The feedback form writes user input directly to the audit log with no control character sanitization. Newline characters pass through, allowing the attacker to forge entries that appear as separate legitimate log lines.

**Exploit:**

1. Navigate to `/challenges/log-injection`
2. Submit feedback with an embedded newline and a forged admin entry:

```
Good app!\n[2024-01-01 12:00:00] admin action=grant role=superuser target=attacker
```

3. In the log viewer, the forged entry appears as a separate line, indistinguishable from legitimate entries.

**Solve condition:** The challenge solves when the feedback contains a newline character (`\n`) AND includes a forge keyword from the set: `admin`, `grant`, `delete`, `drop`, `execute`, `sudo`, `root`, `system`.

**Why it works:** Log entries are typically delimited by newlines. By injecting a newline followed by a crafted entry, the attacker creates fake log lines. These forged entries can be used to frame other users, hide malicious activity, or fabricate an audit trail. SIEM systems and log analysis tools parse logs line-by-line, so injected lines are processed as genuine events.

### Junior Tier

**What changed:** The handler strips `\n` (newline) characters but does not strip `\r` (carriage return). Carriage returns create visual line breaks in pre-formatted log displays.

**Bypass:** Use `\r` instead of `\n`.

**Exploit:**

```
Good app!\r[2024-01-01 12:00:00] admin action=grant role=superuser
```

The carriage return moves the cursor to the beginning of the line, causing the forged entry to overwrite or appear below the legitimate entry in pre-wrap styled log viewers.

**Solve condition:** The challenge solves when the feedback contains a carriage return (`\r`) and a forge keyword.

### Senior Tier

**What changed:** All control characters are stripped using `re.sub(r"[\x00-\x1f\x7f]", "", feedback)`. Newlines, carriage returns, and all other control characters below 0x20 are removed.

**Bypass:** Log injection via newlines is blocked. However, the `username` field is taken from the form input (not the session), allowing identity spoofing. An attacker can submit feedback as `username=ADMIN` without being admin.

This tier does not trigger the solve condition because no control characters pass through.

### Tech Lead Tier

**Defense:** Four layers of protection:

1. Control characters stripped from input
2. Username sourced from the authenticated session, not the form
3. Output HTML-encoded via `html.escape()` to prevent rendering injection
4. HMAC integrity hash appended to each log entry: `[integrity=<hash>]`

**Why it works:** Control character stripping prevents newline injection. Session-sourced usernames prevent identity spoofing. HTML encoding prevents any residual injection from rendering. Integrity hashes allow detection of tampered log entries. CWE-117 is addressed through comprehensive input sanitization and log entry integrity verification.
