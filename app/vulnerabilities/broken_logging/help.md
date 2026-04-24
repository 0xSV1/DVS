<h2>Broken Logging</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/" target="_blank">A09:2025 Security Logging and Monitoring Failures</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/532.html" target="_blank">CWE-532: Insertion of Sensitive Information into Log File</a></p>

<h3>What is it?</h3>
<p>Security logging failures occur when applications either log too much sensitive data (exposing credentials, tokens, or PII in log files) or fail to restrict access to log endpoints. When audit logs are accessible to unprivileged users, attackers gain visibility into application internals and user activity patterns.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand the risks of exposing audit logs to unprivileged users</li>
    <li>Recognize what data should and should not appear in application logs</li>
    <li>Learn why log access must be restricted to administrative roles</li>
    <li>Understand the balance between useful operational logging and information disclosure</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> Audit logs are fully exposed with all fields, including detailed request information.</li>
    <li><strong>Junior:</strong> Identical to Intern. No access restrictions.</li>
    <li><strong>Senior:</strong> Some fields are stripped from log entries, but metadata about user activity is still visible.</li>
    <li><strong>Tech Lead:</strong> Log access is restricted to administrative roles. Unprivileged users cannot view logs.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Finding the logs</summary>
    <p>Look for the audit log interface. At lower difficulty tiers, there are no access controls on who can view the logs.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Sensitive data in logs</summary>
    <p>Examine the log entries closely. Applications that log request bodies indiscriminately may capture data that should never be persisted in plaintext. Look at what actions generate the most revealing log entries.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" target="_blank">OWASP Logging Cheat Sheet</a></li>
    <li><a href="https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/" target="_blank">OWASP Top 10: Security Logging and Monitoring Failures</a></li>
</ul>
