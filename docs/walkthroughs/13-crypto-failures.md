# Cryptographic Failures

OWASP: https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/
CWE: CWE-328, CWE-798

Cryptographic failures occur when sensitive data is protected with weak or broken algorithms, or when cryptographic secrets are exposed. This includes using MD5 for password hashing (trivially reversible), hardcoding API keys in client-side code, and failing to use proper key management.

---

## Hashing? Trust Me Bro (`crypto_md5`)

**Difficulty:** Junior
**CWE:** CWE-328
**Route:** `GET /challenges/crypto` (view hashes), `POST /challenges/crypto/crack` (submit cracked password)

### Intern Tier

**Vulnerability:** Passwords are stored as unsalted MD5 hashes. The hash listing endpoint returns all user hashes with the algorithm explicitly labeled as "MD5 (unsalted)."

**Exploit:**

1. Navigate to `/challenges/crypto` to view the hash list
2. Note the hashes and their labeled algorithm. Example:

```json
{"username": "admin", "hash": "5f4dcc3b5aa765d61d8327deb882cf99", "algorithm": "MD5 (unsalted)"}
```

3. Crack the hash using a rainbow table or hashcat:

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
```

4. The hash `5f4dcc3b5aa765d61d8327deb882cf99` is the MD5 of `password`

5. Submit the cracked password:

```bash
curl -X POST http://localhost:8000/challenges/crypto/crack \
  -d "username=admin&password=password"
```

**Solve condition:** The challenge solves when `username` is non-empty, `password` is non-empty, and the MD5 of the submitted password matches the stored hash.

**Why it works:** MD5 is a fast, unsalted hash. Modern GPUs compute billions of MD5 hashes per second. Precomputed rainbow tables provide instant lookup for common passwords. Without a salt, identical passwords produce identical hashes, making attacks even more efficient.

### Junior Tier

**What changed:** Same as intern. Full hash exposure with algorithm labeled.

### Senior Tier

**What changed:** Hashes are displayed but the algorithm is listed as "Unknown." The hashes are still MD5 underneath.

**Bypass:** The 32-character hexadecimal format is a strong indicator of MD5. Any experienced attacker recognizes the format immediately.

**Exploit:**

1. View hashes at `/challenges/crypto`
2. Recognize the 32-character hex strings as MD5
3. Crack using the same tools and submit the password

### Tech Lead Tier

**Defense:** The hash listing returns an empty list. The crack endpoint rejects all attempts with "Hash exposure disabled at this security tier." Passwords are stored using bcrypt with per-user salts.

**Why it works:** Bcrypt is a purpose-built password hashing function with configurable work factor. Each hash includes a unique random salt, making rainbow tables useless. The work factor makes brute-force attacks computationally expensive. Not exposing hashes to users eliminates the attack surface entirely. This addresses CWE-328 by replacing a broken algorithm with a cryptographically appropriate one.

---

## API Keys are Environment Variables, Right? (`crypto_hardcoded_secret`)

**Difficulty:** Junior
**CWE:** CWE-798
**Route:** `GET /challenges/crypto/secrets` (view page), `POST /challenges/crypto/secrets/verify` (submit key)

### Intern Tier

**Vulnerability:** The API key is embedded directly in the page source as a JavaScript variable. No obfuscation or server-side protection.

**Exploit:**

1. Navigate to `/challenges/crypto/secrets`
2. View the page source (Ctrl+U or browser DevTools)
3. Find the plaintext API key:

```javascript
var apiKey = "dbr_partner_S3cr3TK3Y_2026";
```

4. Submit the key:

```bash
curl -X POST http://localhost:8000/challenges/crypto/secrets/verify \
  -d "api_key=dbr_partner_S3cr3TK3Y_2026"
```

**Solve condition:** The challenge solves when the submitted key matches the real key (non-empty).

**Why it works:** Client-side code is fully visible to the user. Anything embedded in JavaScript, HTML, or CSS is accessible. API keys in client-side code can be extracted by any visitor and used to make unauthorized API calls.

### Junior Tier

**What changed:** The key is split into three base64-encoded fragments embedded in JavaScript variables. A decoy key (`dbr_test_NOT_A_REAL_KEY`) is prominently displayed to mislead.

**Bypass:** Concatenate the three fragments and base64-decode.

**Exploit:**

1. Navigate to `/challenges/crypto/secrets`
2. View page source and find three fragment variables
3. In the browser console:

```javascript
atob(fragment_a + fragment_b + fragment_c)
```

4. The decoded result is `dbr_partner_S3cr3TK3Y_2026`
5. Submit the key (the decoy key is rejected with "That's the decoy key")

### Senior Tier

**What changed:** The key is masked (`dbr_*...****_2026`). An HMAC-SHA256 signature is provided, computed with the key as the HMAC secret and `"connection_test"` as the message.

**Bypass:** Since the key space is relatively small (known prefix `dbr_partner_` and suffix `_2026`), the HMAC can be brute-forced or the key can be recovered if any other information leaks.

**Exploit:**

1. View the HMAC signature and test data
2. Brute-force the key by computing HMAC-SHA256 with candidate keys until the signature matches
3. Submit the recovered key

### Tech Lead Tier

**Defense:** No key material is exposed on the client side. The API key is managed entirely server-side. The verification endpoint returns "API keys are managed server-side" for all attempts.

**Why it works:** API keys never belong in client-side code. Server-side key management with proxy endpoints ensures keys are never exposed to browsers. CWE-798 is addressed by removing hardcoded secrets from all client-accessible code.
