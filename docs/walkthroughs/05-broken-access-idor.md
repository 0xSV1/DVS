# Insecure Direct Object Reference

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-639, CWE-269

Insecure Direct Object Reference (IDOR) occurs when an application exposes internal object identifiers (database IDs, filenames) in URLs or parameters and fails to verify that the requesting user is authorized to access the referenced object.

---

## Other People's OKRs (`idor_profile`)

**Difficulty:** Intern
**CWE:** CWE-639
**Route:** `GET /challenges/idor/profile/{user_id}`

### Intern Tier

**Vulnerability:** User profiles are fetched by sequential integer ID with zero authorization checks. No authentication is required. All fields are returned, including `api_key` and `password_hash`.

**Exploit:**

1. Log in as any user (or access unauthenticated)
2. Navigate to your own profile to note your user ID
3. Change the ID in the URL:

```
GET /challenges/idor/profile/1
GET /challenges/idor/profile/2
GET /challenges/idor/profile/3
```

4. Each request returns the full profile of the targeted user, including sensitive fields.

**Solve condition:** The challenge solves when an authenticated user (`current_user is not None`) views a profile with a different `user_id` than their own.

**Why it works:** The application trusts the client to only request its own resources. Sequential integer IDs are trivially enumerable. The absence of ownership checks means any authenticated user can access any profile.

### Junior Tier

**What changed:** Authentication is now required (`current_user is not None`), but no ownership verification. The `password_hash` field is excluded from the response, but `api_key`, `email`, `role`, and `bio` are still exposed.

**Bypass:** Log in as any user and access other users' profiles by changing the ID. The authentication check only verifies you are logged in, not that the profile belongs to you.

**Exploit:**

```
GET /challenges/idor/profile/1
Authorization: Bearer <your_jwt_token>
```

### Senior Tier

**What changed:** Ownership check added: `if current_user.id != user_id and current_user.role != "admin": return error`. However, the role is read from JWT claims, not the database.

**Bypass:** Forge a JWT with `role: "admin"` if you know the signing secret (see the `auth_jwt_weak` challenge). The handler trusts the JWT claim without database verification.

**Exploit:**

1. Crack or forge a JWT with `{"role": "admin"}` (secret is `"secret"`)
2. Access any profile:

```
GET /challenges/idor/profile/1
Authorization: Bearer <forged_admin_jwt>
```

### Tech Lead Tier

**Defense:** Strict ownership verification with database-sourced role check. Non-owners see only `id`, `username`, and `bio`. Admin status is re-queried from the database, not read from JWT claims. Sensitive fields (`api_key`, `password_hash`) are never returned.

**Why it works:** Authorization is enforced server-side using the database as the source of truth for roles. The principle of least privilege ensures non-owners see minimal data. CWE-639 is addressed through proper access control checks on every request.

---

## Peek at the Cap Table (`idor_order`)

**Difficulty:** Junior
**CWE:** CWE-639
**Route:** `GET /challenges/idor/order/{order_id}`

### Intern Tier

**Vulnerability:** Order details are fetched by order ID with no authentication or ownership check. Sensitive data including `credit_card_last4`, `shipping_address`, and `total_price` is returned.

**Exploit:**

1. Access order endpoints by enumerating IDs:

```
GET /challenges/idor/order/1
GET /challenges/idor/order/2
GET /challenges/idor/order/3
```

2. Each response contains the full order details regardless of who placed the order.

**Solve condition:** The challenge solves when an authenticated user views an order that belongs to a different user (`current_user.id != order.user_id`).

### Junior Tier

**What changed:** No significant change. Authentication check added but no ownership verification.

**Exploit:** Log in and access orders belonging to other users by changing the order ID.

### Senior Tier

**What changed:** Authentication required but still no ownership verification. Any authenticated user can view any order.

**Exploit:** Same as junior tier. Log in and enumerate order IDs.

### Tech Lead Tier

**Defense:** Strict ownership check: `if current_user.id != order.user_id: return "Access denied"`. Returns 403 for non-owners.

**Why it works:** Every order access verifies that the requesting user owns the order. CWE-639 is mitigated through server-side authorization on each request.

---

## Promotion Without the Standup (`idor_admin`)

**Difficulty:** Senior
**CWE:** CWE-269
**Route:** `GET /admin`

### Intern Tier

**Vulnerability:** The admin panel has no access control. Any user, authenticated or not, can access it. The panel displays the full user list with API keys, emails, and system statistics.

**Exploit:**

1. Navigate to:

```
GET /admin
```

2. The admin panel renders with full data. No login required.

**Solve condition:** At intern and junior tiers, the challenge solves when any user reaches the admin panel. The absence of access control is itself the vulnerability, so simply arriving at the page proves the exploit.

### Junior Tier

**What changed:** No access control added. Same as intern.

**Solve condition:** Same as intern: any visit to `/admin` solves the challenge.

**Exploit:** Same as intern tier.

### Senior Tier

**What changed:** Authentication is required (`if not current_user: return access_denied`), but no role check. Any authenticated user can access the admin panel.

**Solve condition:** The challenge now requires the player to reach the admin panel as a user whose account is NOT `admin`. Logging in as the admin user and visiting `/admin` does not count. The player must either create or use a non-admin account and find a way to the panel, or forge a JWT for a non-admin user.

**Exploit:** Log in as any regular (non-admin) user and navigate to `/admin`.

### Tech Lead Tier

**Defense:** Both authentication and role verification: `if not current_user or current_user.role != "admin": return access_denied`. Non-admin users receive an error template instead of admin data. Role is verified from a fresh database query.

**Why it works:** The authorization check verifies both identity and role before granting access. CWE-269 (improper privilege management) is addressed by enforcing role-based access control on privileged endpoints.
