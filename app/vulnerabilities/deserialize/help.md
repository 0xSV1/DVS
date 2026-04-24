<h2>Insecure Deserialization</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/" target="_blank">A08:2025 Software and Data Integrity Failures</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/502.html" target="_blank">CWE-502: Deserialization of Untrusted Data</a></p>

<h3>What is it?</h3>
<p>Insecure deserialization occurs when an application deserializes data from an untrusted source without validation. Some serialization formats can trigger arbitrary code execution during the deserialization process itself, making them equivalent to passing attacker input to <code>eval()</code>. Even with safer formats, accepting arbitrary fields without schema validation can lead to privilege escalation.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand why certain serialization formats are inherently dangerous when processing untrusted input</li>
    <li>Learn how deserialization can trigger code execution through object lifecycle hooks</li>
    <li>Recognize that switching serialization formats eliminates RCE but not all risks</li>
    <li>Understand why schema validation on deserialized data is necessary even with safe formats</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> User-supplied data is deserialized using a format that supports arbitrary code execution. No restrictions.</li>
    <li><strong>Junior:</strong> Same as Intern. A comment acknowledges the risk, but no fix was applied.</li>
    <li><strong>Senior:</strong> A safer serialization format is used (no code execution risk), but the application accepts any fields without schema validation.</li>
    <li><strong>Tech Lead:</strong> Safe format with strict field allowlist validation. Only expected keys are accepted.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Identifying the format</summary>
    <p>The preferences data is base64-encoded. Decode it and examine the raw bytes. The format of the underlying data is a critical clue: different serialization formats have different risk profiles.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Understanding the risk</summary>
    <p>Some serialization formats call special methods on objects during the loading process. If you can control the serialized data, you can define which methods get called and with what arguments. Research the security implications of the format you identified in Hint 1.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Building the payload</summary>
    <p>Once you know the serialization format, research how it handles object reconstruction. There is a well-documented Python protocol that allows objects to define custom behavior during deserialization. You need to create an object that uses this protocol to execute a system command, serialize it, and base64-encode the result.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" target="_blank">OWASP Deserialization Cheat Sheet</a></li>
    <li><a href="https://docs.python.org/3/library/pickle.html#restricting-globals" target="_blank">Python docs: Restricting Globals for pickle</a></li>
</ul>
