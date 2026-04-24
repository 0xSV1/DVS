<h2>Cross-Site Request Forgery</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/" target="_blank">A01:2025 Broken Access Control</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/352.html" target="_blank">CWE-352: Cross-Site Request Forgery</a></p>

<h3>What is it?</h3>
<p>Cross-Site Request Forgery forces an authenticated user's browser to send a forged request to a vulnerable application. Because the browser automatically attaches session cookies to every request to the target domain, the server cannot distinguish a legitimate action from one triggered by an attacker-controlled page.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand why cookie-based authentication alone does not prevent forged requests</li>
    <li>Recognize the difference between same-origin policy protections and what CSRF bypasses</li>
    <li>Learn the synchronizer token pattern and why origin validation is a necessary second layer</li>
    <li>Understand how SameSite cookie attributes reduce (but do not eliminate) CSRF risk</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> No CSRF protection. The server accepts state-changing requests without verifying their origin.</li>
    <li><strong>Junior:</strong> A request header is checked to verify the origin, but the check has a permissive fallback when the header is absent.</li>
    <li><strong>Senior:</strong> A token-based protection pattern is implemented. Consider whether there are weaknesses in how the token is scoped and rotated.</li>
    <li><strong>Tech Lead:</strong> Token validation combined with origin verification and per-request token rotation. Defense in depth with cookie attributes at the framework level.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Understanding CSRF</summary>
    <p>CSRF exploits the fact that browsers automatically include cookies with every request to a domain, regardless of which page initiated the request. If you can get a victim's browser to submit a form to the target application, the server sees it as a legitimate authenticated request.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Bypassing header checks</summary>
    <p>When a server validates a request by checking an HTTP header, consider what happens when that header is missing entirely. Browsers do not always send every header. Research which HTML attributes or meta tags control whether browsers include origin-related headers.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Token-based protection weaknesses</summary>
    <p>CSRF tokens are effective when properly implemented, but they rely on the attacker being unable to read the token value. If there is a cross-site scripting vulnerability elsewhere in the application, it can be chained with CSRF to extract the token. Also consider whether the token's lifetime creates a window of opportunity.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" target="_blank">OWASP CSRF Prevention Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/csrf" target="_blank">PortSwigger: Cross-Site Request Forgery</a></li>
    <li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value" target="_blank">MDN: SameSite Cookies</a></li>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" target="_blank">OWASP Session Management Cheat Sheet</a></li>
</ul>
