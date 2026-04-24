<h2>Server-Side Template Injection (SSTI)</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A05_2025-Injection/" target="_blank">A05:2025 Injection</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/1336.html" target="_blank">CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine</a></p>

<h3>What is it?</h3>
<p>SSTI occurs when user input is embedded into a server-side template and processed by the template engine. If the engine evaluates your input as code rather than displaying it as text, you can execute expressions, read configuration, and potentially achieve remote code execution.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand the difference between placing user input <em>in</em> a template (safe) versus using user input <em>as</em> a template (dangerous)</li>
    <li>Learn how template engines resolve expressions and access objects</li>
    <li>Recognize that sandboxed environments limit but may not fully prevent exploitation</li>
    <li>Understand why escaping user input before template compilation is the secure approach</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> User input is compiled directly as a template. Full expression evaluation is possible.</li>
    <li><strong>Junior:</strong> A keyword blacklist restricts certain terms, but template engines offer alternative syntax for accessing the same objects.</li>
    <li><strong>Senior:</strong> The template engine runs in a restricted mode. Direct code execution is blocked, but information leaks may still be possible through permitted expressions.</li>
    <li><strong>Tech Lead:</strong> User input is escaped before insertion into a fixed template. No user-controlled template compilation occurs.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Detecting SSTI</summary>
    <p>Template engines use a specific syntax for expressions. Try submitting a simple arithmetic expression using the engine's expression delimiters. If the output shows the computed result instead of the raw text, the engine is evaluating your input.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Accessing internals</summary>
    <p>Template engines typically expose application configuration and runtime objects. Research what global variables your template engine makes available by default.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Escalating to code execution</summary>
    <p>In Python, every object is connected to its class hierarchy. If you can access any object through the template engine, you can traverse the inheritance chain to reach classes that provide system-level functionality. Research "Python MRO exploitation" for the general technique.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 4: Bypassing keyword filters</summary>
    <p>The Junior tier blocks direct references to certain attributes. Template engines often provide filter functions or alternative attribute access syntax that can reference the same objects without using the blocked keywords directly.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://portswigger.net/web-security/server-side-template-injection" target="_blank">PortSwigger: Server-Side Template Injection</a></li>
    <li><a href="https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.html" target="_blank">HackTricks: Jinja2 SSTI</a></li>
</ul>
