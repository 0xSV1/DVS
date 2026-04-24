<h2>SQL Injection</h2>

<p><strong>OWASP:</strong> <a href="https://owasp.org/Top10/2025/A05_2025-Injection/" target="_blank">A05:2025 Injection</a><br>
<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank">CWE-89: SQL Injection</a></p>

<h3>What is it?</h3>
<p>SQL Injection occurs when user-supplied data is included in a SQL query without proper sanitization or parameterization. An attacker can modify the query's logic to extract data, bypass authentication, or even execute system commands.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand how string interpolation in SQL queries creates injection points</li>
    <li>Recognize common SQLi patterns: UNION-based, boolean-based blind, error-based</li>
    <li>Learn why input validation alone is insufficient and parameterized queries are the correct fix</li>
    <li>Understand the difference between ORM safety and raw SQL risks</li>
</ul>

<h3>Tier Breakdown</h3>
<ul>
    <li><strong>Intern:</strong> Raw string interpolation with no escaping. Full error messages are returned to the client.</li>
    <li><strong>Junior:</strong> Character escaping is applied, but the escaping function does not cover all injection vectors.</li>
    <li><strong>Senior:</strong> ORM-based queries for the main search, with a controlled sort parameter.</li>
    <li><strong>Tech Lead:</strong> Pure ORM with parameterized queries. Input length limits. Strict sort validation.</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Detecting injection</summary>
    <p>Try adding a single quote (<code>'</code>) to the search field. If you see a database error, the input is being embedded in SQL without proper handling.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Exploiting the injection</summary>
    <p>Once you confirm injection is possible, think about how SQL WHERE clauses work. Can you modify the condition so it always evaluates to true?</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Advanced extraction</summary>
    <p>SQL supports combining result sets from multiple queries. If you can match the column count of the original query, you can pull data from other tables, including database metadata tables that describe the schema.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">OWASP SQL Injection Prevention Cheat Sheet</a></li>
    <li><a href="https://portswigger.net/web-security/sql-injection" target="_blank">PortSwigger: SQL Injection</a></li>
    <li><a href="https://sqliteonline.com/" target="_blank">SQLite Online (for testing payloads)</a></li>
</ul>
