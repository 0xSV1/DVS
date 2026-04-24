# Mass Assignment

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-915

Mass assignment occurs when an application binds client-supplied data directly to internal objects without filtering which fields the client is allowed to modify. An attacker includes additional fields in the request that the application was not designed to accept, modifying privileged attributes like role, permissions, or account status.

---

## Promote Yourself in JSON (`mass_assign`)

**Difficulty:** Junior
**CWE:** CWE-915
**Route:** `POST /api/users/me` or `PUT /api/users/me`

### Intern Tier

**Vulnerability:** The profile update endpoint applies all request body keys directly to the user model using `setattr()`, with the only exclusion being `id`. Fields like `role`, `is_active`, and `email` can be modified by any authenticated user.

**Exploit:**

1. Log in and obtain a JWT token
2. Send a profile update request with an extra `role` field:

```bash
curl -X POST http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

3. Your role is changed to admin in the database.

**Solve condition:** The challenge solves when `body.get("role") == "admin"` and `current_user.role == "admin"` (the role change was applied).

**Why it works:** `setattr()` applies every key from the request to the user object. The client controls which fields are set, including privileged ones the UI never displays. The API response may reveal additional fields (like `role`) that hint at exploitable attributes.

### Junior Tier

**What changed:** No change from intern. All fields are writable without restriction.

**Exploit:** Same payload as intern tier.

### Senior Tier

**What changed:** An allowlist restricts writable fields to `{"bio", "email", "avatar_url"}`. The `role` field cannot be modified.

**Bypass:** Direct role escalation is blocked. However, email modification opens an indirect attack: change the email to one you control, then use a password reset flow to take over the account.

**Exploit (partial):**

```bash
curl -X POST http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@evil.com"}'
```

This does not solve the challenge directly (role is not changed) but demonstrates that the allowlist is still too broad.

### Tech Lead Tier

**Defense:** Strict allowlist of `{"bio"}` only. Maximum length of 500 characters. All other fields in the request body are silently dropped.

**Why it works:** The allowlist ensures only the intended field can be modified. By explicitly enumerating writable fields rather than blacklisting dangerous ones, new fields added to the model in the future are protected by default. This addresses CWE-915 through positive validation of modifiable attributes.
