<h2>Terminal: DeployBro Deployer CLI</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A05_2025-Injection/" target="_blank">A05:2025 Injection</a>,
<a href="https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/" target="_blank">A01:2025 Broken Access Control</a>,
<a href="https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/" target="_blank">A02:2025 Security Misconfiguration</a><br>
<strong>CWE:</strong>
<a href="https://cwe.mitre.org/data/definitions/798.html" target="_blank">CWE-798: Hardcoded Credentials</a>,
<a href="https://cwe.mitre.org/data/definitions/78.html" target="_blank">CWE-78: OS Command Injection</a>,
<a href="https://cwe.mitre.org/data/definitions/269.html" target="_blank">CWE-269: Improper Privilege Management</a></p>

<h3>What is it?</h3>
<p>The DeployBro Deployer is a simulated CLI tool that manages application deployments. It exposes three distinct vulnerability classes: sensitive credential storage in plaintext configuration files, command injection through unsanitized pipeline arguments, and privilege escalation via hidden administrative commands. These reflect real-world patterns found in CI/CD tooling and developer utilities.</p>

<h3>Challenges</h3>
<ul>
    <li><strong>Credential Leak (CWE-798):</strong> The CLI stores API keys and secrets in local configuration files. Explore the filesystem to find them.</li>
    <li><strong>Command Injection (CWE-78):</strong> The deployment pipeline passes user-supplied branch names to shell commands without sanitization. Shell metacharacters in the input execute arbitrary commands.</li>
    <li><strong>Privilege Escalation (CWE-269):</strong> A hidden authentication subcommand promotes the current user to admin without proper authorization checks.</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> Credentials visible in the home directory and shown by default. The <code>deploybro auth escalate</code> command is available. No input sanitization on pipeline commands.</li>
    <li><strong>Junior:</strong> Credentials still present but hidden (dotfiles). Escalation command still works. Command injection still possible through the <code>--branch</code> argument.</li>
    <li><strong>Senior:</strong> Credential files redacted. Escalation command removed. Pipeline input is sanitized to block shell metacharacters.</li>
    <li><strong>Tech Lead:</strong> No credential files in the filesystem. No escalation path. Strict input validation with allowlisted characters only.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Finding Credentials</summary>
    <p>Use <code>ls -a</code> to reveal hidden files and directories. Check <code>.deploybro/</code> and project <code>.env</code> files. Use <code>cat</code> to read their contents.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Command Injection</summary>
    <p>The <code>deploybro pipeline --branch</code> argument is interpolated into a shell command. Try appending a semicolon or pipe followed by a second command: <code>deploybro pipeline --branch "main; whoami"</code></p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Privilege Escalation</summary>
    <p>Not all commands are listed in <code>deploybro help</code>. Check configuration files or try <code>deploybro auth</code> subcommands. The escalation path exists at intern and junior tiers only.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" target="_blank">OWASP Command Injection Prevention</a></li>
    <li><a href="https://cwe.mitre.org/data/definitions/798.html" target="_blank">CWE-798: Hardcoded Credentials</a></li>
    <li><a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank">OWASP: Broken Access Control</a></li>
</ul>
