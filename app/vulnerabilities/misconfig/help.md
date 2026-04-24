<h2>Security Misconfiguration</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/" target="_blank">A02:2025 Security Misconfiguration</a></p>

<p>Security misconfiguration is one of the most common vulnerability categories in web applications. It covers debug endpoints left enabled in production, overly permissive CORS policies, exposed configuration files, default credentials, and verbose error messages that leak internal details.</p>

<p>This module contains three challenges that demonstrate different facets of misconfiguration.</p>

<hr>

<h3>Challenge 1: Debug Endpoint Exposure</h3>

<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/215.html" target="_blank">CWE-215: Insertion of Sensitive Information Into Debugging Code</a></p>

<h4>What Goes Wrong</h4>
<p>Development debug endpoints that dump application configuration, environment variables, and secrets are left accessible in production. Attackers discover these through directory brute-forcing, predictable paths, or documentation leaks.</p>

<h4>Difficulty Tiers</h4>
<table class="status-table">
    <thead><tr><th>Tier</th><th>Behavior</th></tr></thead>
    <tbody>
        <tr><td>Intern</td><td>Full environment dump with all secrets exposed</td></tr>
        <tr><td>Junior</td><td>Same as Intern</td></tr>
        <tr><td>Senior</td><td>Partial information leak: application metadata only, no secrets</td></tr>
        <tr><td>Tech Lead</td><td>Returns 404; debug endpoint is disabled</td></tr>
    </tbody>
</table>

<details class="help-spoiler">
    <summary>Hint: Exploitation Approach</summary>
    <p>Look for common debug and diagnostic endpoint paths that frameworks expose during development. These paths are well-documented and frequently targeted by scanners.</p>
</details>

<h4>How to Fix</h4>
<p>Disable debug endpoints in production. Use environment-aware configuration that strips debug routes when <code>DEBUG=false</code>. Never expose raw environment variables through any endpoint.</p>

<hr>

<h3>Challenge 2: CORS Misconfiguration</h3>

<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/942.html" target="_blank">CWE-942: Permissive Cross-domain Policy</a></p>

<h4>What Goes Wrong</h4>
<p>Cross-Origin Resource Sharing headers control which external domains can make requests to your API. Misconfigured CORS policies allow attackers to make authenticated cross-origin requests and steal data from logged-in users.</p>

<h4>Difficulty Tiers</h4>
<table class="status-table">
    <thead><tr><th>Tier</th><th>Behavior</th></tr></thead>
    <tbody>
        <tr><td>Intern</td><td><code>Access-Control-Allow-Origin: *</code> with <code>Access-Control-Allow-Credentials: true</code>. Any origin can read responses.</td></tr>
        <tr><td>Junior</td><td>Origin header is reflected back without validation. Looks more secure but trusts any origin.</td></tr>
        <tr><td>Senior</td><td>Same reflection vulnerability. No hints provided.</td></tr>
        <tr><td>Tech Lead</td><td>No CORS headers; same-origin policy enforced by the browser.</td></tr>
    </tbody>
</table>

<details class="help-spoiler">
    <summary>Hint: Exploitation Approach</summary>
    <p>Inspect the CORS-related response headers on API requests. Compare the headers you receive when sending requests with and without an <code>Origin</code> header. The difference reveals how the server makes trust decisions.</p>
    <p>At junior and above, you need to prove cross-origin access by sending a request with an external Origin header:</p>
    <pre><code>curl -H "Origin: https://evil.com" http://localhost:1337/challenges/misconfig/cors-test -v</code></pre>
    <p>Check whether the response reflects your origin in <code>Access-Control-Allow-Origin</code>.</p>
</details>

<h4>How to Fix</h4>
<p>Maintain an explicit allowlist of permitted origins. Validate incoming <code>Origin</code> headers against this list before reflecting them. Be cautious about combining permissive origin policies with credential support.</p>

<hr>

<h3>Challenge 3: Configuration File Disclosure</h3>

<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/538.html" target="_blank">CWE-538: Insertion of Sensitive Information into Externally-Accessible File</a></p>

<h4>What Goes Wrong</h4>
<p>The application serves configuration files over HTTP. These files may contain database credentials, API keys, signing secrets, and cloud provider access keys. Attackers routinely scan for known configuration file paths.</p>

<h4>Difficulty Tiers</h4>
<table class="status-table">
    <thead><tr><th>Tier</th><th>Behavior</th></tr></thead>
    <tbody>
        <tr><td>Intern</td><td>Full configuration file served as plaintext</td></tr>
        <tr><td>Junior</td><td>Same as Intern</td></tr>
        <tr><td>Senior</td><td>Returns 404</td></tr>
        <tr><td>Tech Lead</td><td>Returns 404</td></tr>
    </tbody>
</table>

<details class="help-spoiler">
    <summary>Hint: Exploitation Approach</summary>
    <p>Web applications commonly use dotfiles and data files for configuration. Try requesting paths that are standard for the application's framework and language. Security scanners maintain lists of hundreds of these paths.</p>
</details>

<h4>How to Fix</h4>
<p>Never serve configuration files through the web server. Configure your web server or reverse proxy to block access to dotfiles and data directories. Store secrets in a vault or environment variables injected at deploy time, not in files within the web root.</p>

<hr>

<h3>References</h3>
<ul>
    <li><a href="https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/" target="_blank">OWASP Top 10: A02 Security Misconfiguration</a></li>
    <li><a href="https://cwe.mitre.org/data/definitions/215.html" target="_blank">CWE-215: Insertion of Sensitive Information Into Debugging Code</a></li>
    <li><a href="https://cwe.mitre.org/data/definitions/942.html" target="_blank">CWE-942: Permissive Cross-domain Policy</a></li>
    <li><a href="https://cwe.mitre.org/data/definitions/538.html" target="_blank">CWE-538: Insertion of Sensitive Information into Externally-Accessible File</a></li>
    <li><a href="https://portswigger.net/web-security/cors" target="_blank">PortSwigger: CORS Misconfiguration</a></li>
</ul>
