<h2>Cross-Site Scripting (XSS)</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A05_2025-Injection/" target="_blank">A05:2025 Injection</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank">CWE-79: Cross-site Scripting</a></p>

<h3>What is it?</h3>
<p>XSS occurs when an application includes untrusted data in a web page without proper encoding. An attacker can inject client-side scripts that execute in other users' browsers, stealing cookies, session tokens, or redirecting to malicious sites.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Distinguish between reflected, stored, and DOM-based XSS</li>
    <li>Understand context-dependent output encoding (HTML body vs. JS context vs. attribute)</li>
    <li>Learn why blacklist filtering is insufficient (case bypass, event handlers, encoding tricks)</li>
    <li>Understand Content Security Policy (CSP) as a defense-in-depth measure</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> No sanitization. User input is rendered directly into the page without encoding.</li>
    <li><strong>Junior:</strong> A tag-level blacklist is applied, but it only checks one specific pattern. Think about what it does not check.</li>
    <li><strong>Senior:</strong> HTML entity encoding is applied, but the output context matters. Where does your input end up in the rendered page?</li>
    <li><strong>Tech Lead:</strong> Server-side sanitization library with strict allowlist, combined with browser-enforced Content Security Policy.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Detecting XSS</summary>
    <p>Submit HTML markup in input fields and observe whether it renders as markup or as escaped text. Check the page source to see how your input appears.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Blacklist limitations</summary>
    <p>Blacklists that block specific tags are rarely comprehensive. HTML has many elements and attributes that can execute JavaScript. What happens if the filter is case-sensitive?</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Context-aware escaping</summary>
    <p>HTML encoding prevents injection in an HTML body context, but what if your input is placed inside a JavaScript string literal? The escaping rules for JS strings differ from HTML entities. Examine the page source to find where your input lands.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 4: Full exploit approach</summary>
    <p><strong>Junior:</strong> The blacklist is case-sensitive and only blocks one tag type. Alternative HTML elements with event handler attributes bypass it.<br>
    <strong>Senior:</strong> Your input is placed inside a JavaScript string assignment. You need to break out of the string context, then inject your own statement.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" target="_blank">OWASP XSS Prevention Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/cross-site-scripting" target="_blank">PortSwigger: XSS</a></li>
    <li><a href="https://html5sec.org/" target="_blank">HTML5 Security Cheatsheet</a></li>
</ul>
