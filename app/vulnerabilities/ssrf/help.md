<h2>Server-Side Request Forgery (SSRF)</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A10_2025-Server-Side_Request_Forgery_(SSRF)/" target="_blank">A10:2025 SSRF</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/918.html" target="_blank">CWE-918: Server-Side Request Forgery</a></p>

<h3>What is it?</h3>
<p>SSRF occurs when an application makes HTTP requests to URLs supplied by the user without proper validation. An attacker can force the server to make requests to internal services, cloud metadata endpoints, or other infrastructure that should not be externally accessible.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand how SSRF enables access to internal networks from an external position</li>
    <li>Learn about cloud metadata endpoints and their security implications</li>
    <li>Recognize that there are many ways to represent the same network address</li>
    <li>Understand that domain allowlists are the strongest defense, not IP blacklists</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> No URL validation. The server fetches whatever you give it, following redirects.</li>
    <li><strong>Junior:</strong> A hostname blacklist blocks the most obvious internal addresses. Consider how many ways a network address can be represented.</li>
    <li><strong>Senior:</strong> Pre-flight DNS resolution validates the resolved IP. This check happens once, but the actual request happens separately. What if the answer changes between lookups?</li>
    <li><strong>Tech Lead:</strong> Strict domain allowlist with redirect following disabled.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Confirming SSRF</summary>
    <p>Try making the server fetch a URL that points back to itself. If the server returns content from its own internal endpoints, you have confirmed server-side request capability.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Bypassing blacklists</summary>
    <p>IP addresses can be represented in multiple formats beyond the dotted-decimal notation most people are familiar with. Research alternative IP address representations: IPv6, decimal encoding, and alternative loopback addresses.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: High-impact targets in this challenge</summary>
    <p>DVS runs on <code>localhost:8000</code>. Use SSRF to access the app's own internal endpoints: <code>/health</code>, <code>/api/setup/reset</code>, <code>/challenges</code>. The server is talking to itself, which proves you can reach internal services.</p>
</details>

<details class="help-spoiler">
    <summary>Real-world context: Cloud metadata endpoints</summary>
    <p>In production environments, SSRF is most dangerous when the target runs on a cloud provider. These metadata services are reachable from any process on the instance and often return IAM credentials:</p>
    <ul>
        <li><strong>AWS EC2:</strong> <code>http://169.254.169.254/latest/meta-data/</code> returns instance ID, hostname, IAM role credentials at <code>/latest/meta-data/iam/security-credentials/&lt;role-name&gt;</code></li>
        <li><strong>Azure IMDS:</strong> <code>http://169.254.169.254/metadata/instance?api-version=2021-02-01</code> (requires header <code>Metadata: true</code>) returns subscription ID, resource group, managed identity tokens</li>
        <li><strong>GCP:</strong> <code>http://metadata.google.internal/computeMetadata/v1/</code> (requires header <code>Metadata-Flavor: Google</code>) returns project ID, service account tokens</li>
    </ul>
    <p>DVS doesn't run on a cloud instance, so these won't return data here. But in a real pentest, SSRF to <code>169.254.169.254</code> is often the first thing you try.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" target="_blank">OWASP SSRF Prevention Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/ssrf" target="_blank">PortSwigger: SSRF</a></li>
</ul>
