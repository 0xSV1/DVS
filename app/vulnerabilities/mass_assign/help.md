<h2>Mass Assignment</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/" target="_blank">A01:2025 Broken Access Control</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/915.html" target="_blank">CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes</a></p>

<h3>What is it?</h3>
<p>Mass assignment occurs when an application binds user-supplied data directly to internal objects without restricting which fields can be modified. If the API applies every key from the request body to the database model, an attacker can set fields they should never control.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand how unfiltered request body binding leads to privilege escalation</li>
    <li>Recognize the difference between a denylist (blocking specific fields) and an allowlist (permitting only specific fields)</li>
    <li>Learn why Pydantic schemas or explicit field allowlists are the correct mitigation</li>
    <li>Understand that even with an allowlist, including the wrong fields can enable secondary attacks</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> All request body fields are applied to the user model with no filtering.</li>
    <li><strong>Junior:</strong> Identical to Intern. No filtering whatsoever.</li>
    <li><strong>Senior:</strong> An allowlist restricts which fields can be updated, but includes fields that can enable secondary attacks like account takeover.</li>
    <li><strong>Tech Lead:</strong> Strict allowlist limited to safe, non-privileged fields only.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Reconnaissance</summary>
    <p>Compare the API response to the fields you can submit. Does the API return fields in its response that you did not include in your request? What would happen if you sent those extra fields back?</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Privilege escalation</summary>
    <p>Look for fields in the API response that control access levels or permissions. If the server does not filter incoming fields, you can set any attribute the model supports by including it in your request body.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Senior tier approach</summary>
    <p>When the obvious privilege field is blocked, look for other fields in the allowlist that have security implications. Consider fields that control identity (like contact information) and what workflows depend on them.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html" target="_blank">OWASP Mass Assignment Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/api-testing" target="_blank">PortSwigger: API Testing</a></li>
</ul>
