# CLAUDE.md

DVS is a deliberately vulnerable web application for security training, targeting OWASP Top 10 (2025) and LLM Top 10 (2025). The fictional startup is called DeployBro. Tone is satirical; security education is serious.

## Commands

- Dev server: `uvicorn app.main:app --reload --port 8000`
- Test: `pytest tests/ -v --tb=short`
- Lint: `ruff check . && ruff format --check .`
- Seed DB: `python -m app.db.seed`
- Reset DB (running): `curl -X POST http://localhost:8000/api/setup/reset`
- CTFd export: `python -m app.ctf_export --key <key> --output dvs_ctfd.csv`

## Stack

FastAPI + SQLAlchemy 2.0 (sync, SQLite) + Jinja2 + PyJWT + vanilla CSS/JS. Python 3.11+. Use `async def` for all route handlers. Use type hints on all function signatures. Use `from __future__ import annotations` in every file. Use `ruff` for all formatting and linting. Use `pip` with `requirements.txt` for dependencies.

LLM backend is pluggable: mock (default), OpenAI, Anthropic, Ollama. The fine-tuned `brobot-qwen3.5-uncensored:4b` model runs via Ollama; see `docs/brobot-model-explainer.md`.

## Difficulty Dispatch Pattern

IMPORTANT: Every vulnerability module dispatches to four separate handler files. Never use if/elif difficulty branching in a single file; this breaks the View Source feature.

- `handlers/intern.py`: zero security, raw f-strings, hardcoded secrets
- `handlers/junior.py`: cosmetic security, incomplete blacklists, flawed escaping
- `handlers/senior.py`: real security with subtle flaws, ORM with raw fallbacks
- `handlers/tech_lead.py`: actually secure reference implementation

Follow the dispatcher pattern in `app/vulnerabilities/sqli/router.py` for all new modules.

## Challenge Solve Detection

Every handler implementing a challenge must call `solve_if()` with the correct `challenge_key` from `data/challenges.yml`. An unsolvable challenge is a bug.

All LLM challenges must be fully solvable with `LLM_PROVIDER=mock`. Real providers are optional enhancements. When adding LLM challenges, add patterns to `app/llm/mock_provider.py` and training examples to `scripts/generate_challenge_training.py`.

## Flag Generation

Flags are deterministic HMAC-SHA256: same `CTF_KEY` + same `challenge_key` = same flag. Follow the pattern in `app/core/challenge_utils.py`. Never hardcode the CTF key; read from `data/ctf.key` or `CTF_KEY` env var.

## Framework Security

DVS vulnerabilities are intentional. Framework vulnerabilities are not.

- Keep challenge registry, scoring, WebSocket manager, and middleware secure
- Sign session cookies via Starlette `SessionMiddleware` with strong `SECRET_KEY`
- Check `current_user.role == "admin"` on admin-only framework endpoints
- All seed data is fictional; never store real user data

## Vulnerability Handler Docstrings

Include a module-level docstring in every handler file with: OWASP category, CWE ID, difficulty tier, vulnerability description, example exploit, and fix reference. Follow the format in `app/vulnerabilities/sqli/handlers/intern.py`.

## Prohibited Patterns

- No frontend frameworks (React, Vue, Svelte); use Jinja2 + vanilla JS
- No ORM migrations (Alembic); DB is ephemeral, rebuilt on startup
- No `pickle` usage outside the deserialization challenge
- No dependencies not in `requirements.txt`
- No challenges requiring network egress unless gated by a feature flag
- No real API keys or credentials anywhere; all secrets are fictional

## Testing

Tests prove exploitability at low tiers and mitigation at high tiers. Parametrize across all four difficulty tiers. Follow the pattern in `tests/test_sqli.py`. Every new challenge must ship with a test proving it is solvable. Target 80%+ coverage on vulnerability handlers.

## Adding New Modules

### Vulnerability Module
1. Create `app/vulnerabilities/<name>/` with `router.py` and four handler files
2. Create `templates/<name>.html` and `help.md`
3. Add entries to `data/challenges.yml`
4. Register the router in `app/main.py`
5. Write tests covering all four tiers
6. Update challenge count in `README.md`

### LLM Challenge
1. Create system prompt in `app/vulnerabilities/llm/prompts/<key>.txt`
2. Add keyword patterns to `app/llm/mock_provider.py`
3. Add training examples to `scripts/generate_challenge_training.py`
4. Add entry to `data/challenges.yml`
5. Add behavior patch to `data/brobot_behavior_patches.json`
6. Write a test verifying the mock provider responds to the exploit payload
7. Verify solvability with `LLM_PROVIDER=mock`

## Git

- Branches: `feat/<desc>`, `fix/<desc>`, `docs/<desc>`
- Commits: Conventional Commits format, e.g. `feat(sqli): add blind SQLi challenge`
- PRs: all CI passing, at least one test per new challenge, no unintentional vulns

## Satirical Tone

Humor punches up at startup culture, not at learners. Every joke should also teach something. Read `app/templates/` for the established voice. Common patterns: fake compliance badges, impossible metrics ("1.5M users" with 47 DB rows), `# TODO: add security later` comments, loading states like "Consulting the AI co-founder..."

## Context Loading

- For env vars and config: read `.env.example` and `app/core/config.py`
- For challenge registry format: read `data/challenges.yml`
- For Docker setup: read `docker-compose.yml` and `Dockerfile`
- For dependency rationale: read `requirements.txt`
- For BroBot model training: read `docs/brobot-model-explainer.md`
- For the mock LLM patterns: read `app/llm/mock_provider.py`
- For challenge solving guides: read `docs/walkthroughs/`

IMPORTANT: Every vulnerability module dispatches to four separate handler files. Never use if/elif difficulty branching in a single file.
