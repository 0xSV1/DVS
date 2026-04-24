<h2>Unrestricted File Upload</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A04_2025-Insecure_Design/" target="_blank">A04:2025 Insecure Design</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/434.html" target="_blank">CWE-434: Unrestricted Upload of File with Dangerous Type</a></p>

<h3>What is it?</h3>
<p>Unrestricted file upload allows an attacker to upload malicious files that get served directly to other users' browsers. On a static file server, the dangerous types are HTML, SVG, and JS files: browsers render and execute them when accessed. On a PHP server, <code>.php</code> files would execute server-side. The impact depends on what the server will serve and what browsers will run.</p>
<p>The attack here is <strong>stored XSS via file upload</strong>: upload an HTML file containing JavaScript, share the URL, and anyone who visits it runs your script in their browser context on this domain.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand why client-side validation and extension blacklists are insufficient</li>
    <li>Learn the difference between extension checking, MIME type checking, and magic byte validation</li>
    <li>Recognize that file type validation has multiple layers, each with different bypass techniques</li>
    <li>Understand defense-in-depth: validation + randomized filenames + storage outside webroot</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> No validation at all. Original filename is preserved. Files are served directly from a web-accessible directory.</li>
    <li><strong>Junior:</strong> An extension blacklist blocks some dangerous file types. Blacklists are inherently incomplete; think about which extensions are not blocked.</li>
    <li><strong>Senior:</strong> An extension allowlist combined with MIME type checking. Consider which part of this validation is based on client-supplied data.</li>
    <li><strong>Tech Lead:</strong> File content inspection (magic bytes), randomized filenames, storage outside the webroot.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: The attack vector</summary>
    <p>Python and PHP files served statically just display their source code. The dangerous file types are ones the <em>browser</em> will execute: <code>.html</code>, <code>.svg</code>, and <code>.js</code>. Upload a file containing a <code>&lt;script&gt;</code> tag, then visit the URL the server returns. Check whether the browser renders it or downloads it.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Bypassing blacklists</summary>
    <p>Blacklists block known dangerous extensions but cannot anticipate every file type that a browser will interpret as active content. Think about file types beyond server-side scripts that can execute code in a browser context.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Bypassing allowlists with MIME checks</summary>
    <p>Some validation checks rely on data that the client controls. Examine the HTTP request in a proxy tool. Which fields in the upload request describe the file type, and which of those can you modify?</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" target="_blank">OWASP File Upload Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/file-upload" target="_blank">PortSwigger: File Upload Vulnerabilities</a></li>
</ul>
