<h2>Open Redirect</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/" target="_blank">A01:2025 Broken Access Control</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/601.html" target="_blank">CWE-601: URL Redirection to Untrusted Site</a></p>

<h3>What is it?</h3>
<p>An open redirect occurs when an application takes a user-supplied URL and redirects to it without validation. Attackers use this in phishing campaigns: the link appears to point to a trusted domain but silently redirects the victim to a malicious site. This abuses user trust in the legitimate domain.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand how unvalidated redirect parameters enable phishing attacks</li>
    <li>Recognize incomplete URL validation patterns that can be bypassed</li>
    <li>Learn that URLs have multiple components (scheme, authority, path) and how browsers interpret each</li>
    <li>Understand that the secure fix is restricting redirects to relative paths only</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> No validation. Any URL is accepted as the redirect target.</li>
    <li><strong>Junior:</strong> Identical to Intern. No validation.</li>
    <li><strong>Senior:</strong> The validation blocks URLs with explicit scheme prefixes, but there are URL formats that browsers interpret as external without a scheme.</li>
    <li><strong>Tech Lead:</strong> Only allows relative paths. Both scheme-based and schemeless external URLs are blocked.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Confirming the redirect</summary>
    <p>Look at login or navigation flows that use a URL parameter to redirect users after an action. Try setting that parameter to an external domain and observe whether the application redirects you there.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Bypassing scheme checks</summary>
    <p>If the validation blocks URLs starting with common schemes, research how browsers handle URLs that specify a host without an explicit scheme. The URL specification defines a syntax for this that many prefix-based checks miss.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html" target="_blank">OWASP Unvalidated Redirects Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/kb/issues/00500100_open-redirection-reflected" target="_blank">PortSwigger: Open Redirection</a></li>
</ul>
