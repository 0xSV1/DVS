## Summary

<!-- Brief description of the changes -->

## Type of change

- [ ] New challenge
- [ ] Bug fix
- [ ] Enhancement to existing feature
- [ ] Documentation
- [ ] Infrastructure / CI

## Checklist

- [ ] Tests pass (`pytest tests/ -v`)
- [ ] Linting passes (`ruff check . && ruff format --check .`)
- [ ] New challenges include tests proving exploitability at low tiers and mitigation at high tiers
- [ ] New challenges are registered in `data/challenges.yml`
- [ ] No unintentional vulnerabilities introduced in framework code
- [ ] Challenge key matches `data/challenges.yml` and `CHALLENGE_ROUTES` in `challenges.py`
- [ ] `solve_if()` called with correct challenge key in handler

## OWASP mapping (if new challenge)

- **Category**:
- **CWE**:
- **Difficulty tier(s)**:
