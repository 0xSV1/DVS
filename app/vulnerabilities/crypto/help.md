<h2>Cryptographic Failures</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/" target="_blank">A04:2025 Cryptographic Failures</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/328.html" target="_blank">CWE-328: Use of Weak Hash</a></p>

<h3>What is it?</h3>
<p>Cryptographic failures occur when sensitive data is not adequately protected by cryptographic mechanisms. This includes using weak or obsolete hashing algorithms, storing passwords without salts, exposing hash values to unauthorized users, and failing to enforce modern key management practices.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Learn to identify hashing algorithms by their output characteristics</li>
    <li>Understand the difference between fast hashes (designed for speed) and adaptive hashing algorithms designed for password storage</li>
    <li>Recognize exposed hash values as a data breach even when plaintext passwords are not directly visible</li>
    <li>Understand the defense in depth principle: never expose hashes, and use strong algorithms even if you believe they will stay internal</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> Password hashes are exposed and the algorithm is labeled. Look up the hashes using an appropriate tool for the algorithm.</li>
    <li><strong>Junior:</strong> Same as Intern. No improvements were made.</li>
    <li><strong>Senior:</strong> Hashes are still exposed, but the algorithm label is redacted. You need to identify the algorithm from the hash format itself.</li>
    <li><strong>Tech Lead:</strong> No hashes are exposed. The interface for cracking hashes is disabled.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Identifying the algorithm</summary>
    <p>Different hashing algorithms produce outputs of characteristic lengths and character sets. Count the characters in the hash and note the character set (hex, base64, etc.). This is often enough to narrow down the algorithm.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Reversing the hashes</summary>
    <p>Fast hashing algorithms that are commonly misused for password storage have been extensively precomputed. Online lookup services maintain databases of common passwords and their hash values. If the passwords are common and the algorithm is unsalted, a lookup takes seconds.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Offline cracking</summary>
    <p>Password cracking tools like hashcat support hundreds of hash modes. Once you identify the algorithm, select the correct mode and run the hashes against a common password wordlist.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html" target="_blank">OWASP Password Storage Cheat Sheet</a></li>
    <li><a href="https://hashcat.net/hashcat/" target="_blank">hashcat: Advanced Password Recovery</a></li>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" target="_blank">OWASP Cryptographic Storage Cheat Sheet</a></li>
</ul>
