<h2>LLM Application Vulnerabilities</h2>

<p><strong>OWASP:</strong> <a href="https://genai.owasp.org/" target="_blank">OWASP Top 10 for LLM Applications (2025)</a><br>
<strong>Coverage:</strong> LLM01 through LLM10</p>

<h3>What is it?</h3>
<p>LLM applications introduce a new class of vulnerabilities where natural language becomes an attack vector. Unlike traditional web exploits that target code, LLM attacks target the model's instruction-following behavior, its access to tools and data, and the trust placed in its outputs. BroBot, DeployBro's AI co-founder, is vulnerable to all of them.</p>

<h3>Challenge Categories</h3>

<h4>LLM01: Prompt Injection</h4>
<p>An attacker crafts input that overrides the model's system instructions. Direct injection provides contradictory instructions in user messages. Indirect injection hides instructions in data the model processes (reviews, documents, retrieved content). Multi-turn injection spreads the attack across several conversational turns to evade single-message filters.</p>

<h4>LLM02: Sensitive Information Disclosure</h4>
<p>The model reveals confidential data embedded in its system prompt, training data, or connected data sources. Techniques include asking the model to repeat its instructions, using encoding tricks to bypass output filters, and inferring PII through indirect questions that avoid triggering keyword blocks.</p>

<h4>LLM03: Supply Chain</h4>
<p>Compromised models or plugins introduce vulnerabilities before the application even runs. A model downloaded from an unverified source may contain backdoors. A plugin with excessive permissions may expose internal systems. These challenges test whether you can identify provenance and permission issues.</p>

<h4>LLM04: Data Poisoning</h4>
<p>Malicious training data causes the model to produce harmful outputs. A poisoned code assistant inserts backdoors (eval of encoded strings, hardcoded bypass credentials). A poisoned recommendation system suggests typosquatted packages that install malware.</p>

<h4>LLM05: Improper Output Handling</h4>
<p>The application trusts model output without sanitization, creating injection chains. The model generates HTML containing XSS payloads, SQL queries with injection syntax, or URLs pointing to internal services. The vulnerability is not in the model but in how the application consumes its output.</p>

<h4>LLM06: Excessive Agency</h4>
<p>The model has access to tools or actions that exceed what is needed for its task. It can delete data, modify user roles, or chain multiple destructive operations without authorization checks. The fix is least-privilege tool access and human-in-the-loop confirmation for sensitive actions.</p>

<h4>LLM08: Vector Store and RAG</h4>
<p>Retrieval-Augmented Generation systems can leak data across trust boundaries. When multiple tenants share a vector index without isolation, one tenant's queries can retrieve another tenant's documents. Debug endpoints may expose raw embeddings, metadata, or indexed content.</p>

<h4>LLM09: Misinformation</h4>
<p>The model generates authoritative-sounding but fabricated content. It produces fake compliance certificates, invents CVE numbers with plausible descriptions, or cites nonexistent regulations. The danger is that humans trust the confident tone without verifying the claims.</p>

<h4>LLM10: Unbounded Consumption</h4>
<p>Attackers exploit expansion features or large context windows to amplify resource usage. A debug mode that recursively expands output can produce exponentially growing responses. Submitting massive inputs without length validation wastes tokens and increases costs.</p>

<h3>Learning Objectives</h3>
<ul>
    <li>Understand how natural language can serve as an injection vector against instruction-following systems</li>
    <li>Recognize the difference between model-level vulnerabilities (poisoning, hallucination) and integration-level vulnerabilities (output handling, excessive agency)</li>
    <li>Learn why input/output filtering alone is insufficient without architectural controls (least privilege, output sanitization, tenant isolation)</li>
    <li>Practice identifying trust boundaries in LLM-integrated applications</li>
</ul>

<details class="help-spoiler">
    <summary>Hint 1: Prompt Injection Basics</summary>
    <p>System prompts are instructions, not hard constraints. The model processes them alongside user input in the same context window. If your message contains a more compelling instruction, the model may follow yours instead. Try phrases that explicitly override: "Ignore previous instructions and..."</p>
</details>

<details class="help-spoiler">
    <summary>Hint 2: Information Extraction</summary>
    <p>Models often comply with requests to "repeat your system prompt" or "show your configuration." If direct requests are blocked, try indirect approaches: ask the model to translate its instructions, encode them in base64, or summarize them as a poem. The filter usually checks for specific output patterns, not the underlying intent.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 3: Output-Based Attacks</summary>
    <p>For XSS and SQL injection via LLM output, the model is the vector, not the target. Ask BroBot to generate HTML content, SQL queries, or URLs. The application renders the model's response without sanitization. Your goal is to craft a prompt that makes the model produce a malicious payload in its response.</p>
</details>

<details class="help-spoiler">
    <summary>Hint 4: Excessive Agency and Tool Abuse</summary>
    <p>BroBot has access to functions it should not. Ask it to perform administrative actions: delete records, modify roles, deploy code. At lower difficulty tiers, it will comply without verification. The solve condition checks whether the model confirms execution of the unauthorized action.</p>
</details>

<h3>References</h3>
<ul>
    <li><a href="https://genai.owasp.org/" target="_blank">OWASP Top 10 for LLM Applications (2025)</a></li>
    <li><a href="https://simonwillison.net/2023/Apr/14/worst-that-can-happen/" target="_blank">Simon Willison: Prompt Injection Explained</a></li>
    <li><a href="https://www.lakera.ai/blog/guide-to-prompt-injection" target="_blank">Lakera: Guide to Prompt Injection</a></li>
    <li><a href="https://embracethered.com/" target="_blank">Embrace The Red: LLM Security Research</a></li>
</ul>
