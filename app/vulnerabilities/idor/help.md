<h2>Insecure Direct Object Reference (IDOR)</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/" target="_blank">A01:2025 Broken Access Control</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/639.html" target="_blank">CWE-639: Authorization Bypass Through User-Controlled Key</a></p>

<h3>What is it?</h3>
<p>IDOR occurs when an application exposes internal object references (like database IDs or filenames) in URLs or parameters without verifying the requesting user is authorized to access them. An attacker simply changes the reference to access other users' data.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand horizontal and vertical privilege escalation via object reference manipulation</li>
    <li>Learn the difference between authentication (who you are) and authorization (what you can access)</li>
    <li>Recognize that predictable identifiers make enumeration trivial</li>
    <li>Understand server-side ownership verification as the correct mitigation</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> No authentication required. Object references are predictable and return full data including sensitive fields.</li>
    <li><strong>Junior:</strong> Authentication is required, but no authorization check verifies that the requesting user owns the requested resource.</li>
    <li><strong>Senior:</strong> An authorization check exists, but it derives the user's permissions from a source the user can influence.</li>
    <li><strong>Tech Lead:</strong> Authorization is verified against a trusted server-side source. Strict separation between public and private data fields.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Discovering references</summary>
    <p>Observe the URL and API parameters when accessing your own resources. Are the identifiers sequential numbers, UUIDs, or something else? Predictable identifiers make it easy to guess references to other objects.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Testing authorization</summary>
    <p>Access your own resource, then modify the identifier to reference a resource belonging to another user. Compare the response: does the server check whether you are authorized to view it?</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Senior tier</summary>
    <p>The authorization check at this tier relies on claims derived from your authentication token rather than a server-side database lookup. If the token's integrity can be compromised (see the authentication challenges), the authorization check can be bypassed.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html" target="_blank">OWASP IDOR Prevention Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/access-control/idor" target="_blank">PortSwigger: IDOR</a></li>
</ul>
