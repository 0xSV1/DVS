# Security Policy

## Intentional vs. Unintentional Vulnerabilities

Damn Vulnerable Startup (DVS) is a **deliberately vulnerable** web application designed for security training. The vulnerabilities in the challenge modules (`app/vulnerabilities/`) are **intentional** and should NOT be reported as security issues.

Intentional vulnerability categories include:
- SQL injection, XSS, SSTI, SSRF, CSRF
- Broken access control (IDOR, privilege escalation)
- Insecure authentication (weak JWT, none algorithm, weak passwords)
- Security misconfiguration (exposed debug endpoints, permissive CORS)
- Insecure deserialization
- LLM prompt injection and system prompt leakage
- Cryptographic failures (MD5 hashing, hardcoded secrets)

## Reporting Unintentional Vulnerabilities

If you discover a vulnerability in the **framework itself** (challenge registry, scoring system, session management, WebSocket manager, middleware, or deployment configuration) that is NOT part of a challenge, please report it responsibly.

**How to report**: Open a GitHub issue with the label `security` describing the vulnerability, its impact, and reproduction steps.

The following components should be secure:
- Session cookie signing and validation
- Challenge solve tracking and flag generation
- WebSocket notification system
- Database reset and seed functionality
- Admin-only framework endpoints (not challenge endpoints)
- Docker and deployment configurations

## Scope

DVS is designed to run **locally or in isolated environments**. Do NOT deploy DVS on public-facing infrastructure without network isolation. The intentional vulnerabilities include remote code execution vectors that could compromise the host system.
