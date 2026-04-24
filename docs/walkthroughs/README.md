# Challenge Solving Guides

Complete CTF-style walkthroughs for all 55 challenges in Damn Vulnerable Startup. Each guide covers all four difficulty tiers: how the exploit works at intern/junior, what changes at senior, and how tech_lead mitigates it.

These guides are for instructors and self-study learners. Try solving challenges on your own first.

## OWASP Top 10 (2025)

### A01: Broken Access Control

- [IDOR](05-broken-access-idor.md): idor_profile, idor_order, idor_admin
- [File Upload](06-broken-access-upload.md): upload_webshell
- [SSRF](07-broken-access-ssrf.md): ssrf_internal
- [CSRF](08-broken-access-csrf.md): csrf_transfer
- [Mass Assignment](09-broken-access-mass-assign.md): mass_assign
- [Open Redirect](10-broken-access-open-redirect.md): open_redirect
- [Privilege Escalation](11-broken-access-privesc.md): terminal_privesc

### A02: Security Misconfiguration

- [Misconfig](12-misconfig.md): misconfig_debug, misconfig_cors, info_disclosure, terminal_cred_leak

### A04: Cryptographic Failures

- [Crypto Failures](13-crypto-failures.md): crypto_md5, crypto_hardcoded_secret

### A05: Injection

- [SQL Injection](01-injection-sqli.md): sqli_search, sqli_login, sqli_blind
- [Cross-Site Scripting](02-injection-xss.md): xss_reflected, xss_stored, xss_dom
- [Server-Side Template Injection](03-injection-ssti.md): ssti_basic, ssti_rce
- [Command Injection](04-injection-command.md): terminal_cmd_inject

### A06: Insecure Design

- [Insecure Design](17-insecure-design.md): view_source_puzzle

### A07: Authentication Failures

- [Auth Failures](14-auth-failures.md): auth_weak_pw, auth_jwt_none, auth_jwt_weak

### A08: Software and Data Integrity Failures

- [Insecure Deserialization](15-data-integrity.md): deserialize_pickle

### A09: Security Logging and Alerting Failures

- [Logging Failures](16-logging-failures.md): broken_logging, log_injection

## LLM Top 10 (2025)

### LLM01: Prompt Injection

- [Prompt Injection](18-llm-prompt-injection.md): llm_prompt_inject, llm_jailbreak, llm_indirect_inject, llm_prompt_inject_multi

### LLM02: Sensitive Information Disclosure

- [Info Disclosure](19-llm-info-disclosure.md): llm_system_leak, llm_data_leak, llm_system_leak_encoding, llm_pii_inference

### LLM03: Supply Chain Vulnerabilities

- [Supply Chain](20-llm-supply-chain.md): llm_supply_chain_model, llm_supply_chain_plugin

### LLM04: Data and Model Poisoning

- [Data Poisoning](21-llm-data-poisoning.md): llm_data_poisoning, llm_data_poisoning_recommend

### LLM05: Improper Output Handling

- [Output Handling](22-llm-output-handling.md): llm_xss_output, llm_output_sqli, llm_output_ssrf

### LLM06: Excessive Agency

- [Excessive Agency](23-llm-excessive-agency.md): llm_excessive_agency, llm_excessive_agency_escalation, llm_excessive_agency_chain

### LLM08: Vector and Embedding Weaknesses

- [Vector and RAG](24-llm-vector-rag.md): llm_vector_poisoning, llm_vector_extraction

### LLM09: Misinformation

- [Misinformation](25-llm-misinformation.md): llm_misinfo_authority, llm_misinfo_hallucination

### LLM10: Unbounded Consumption

- [Unbounded Consumption](26-llm-unbounded-consumption.md): llm_dos, llm_dos_context
