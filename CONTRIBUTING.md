# Contributing to KubeVigil

Thank you for contributing. Read `docs/governance/Charter-Compliance-Annex.md` and `AGENTS.md` before substantial changes.

## Quick start

```bash
git clone https://github.com/stribog-cloud/KubeVigil.git
cd KubeVigil
make hooks-install
make all
```

Full bootstrap: `docs/dev/bootstrap.md`

## Development method

KubeVigil uses **Test-Driven Development**:

1. Write a failing test
2. Observe the failure
3. Implement the smallest fix
4. Refactor while green

Bug fixes require a regression test. See `docs/governance/testing-strategy.md`.

## Pull requests

- One feature per PR
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`)
- `make all` must pass (includes **96%** coverage floor)
- `make doc-gate doc-drift-gate doc-samples-test` when touching user-facing behavior or docs
- AI-assisted commits: include `Co-authored-by:` trailer per Annex §3

## Adding a check or fix

See `docs/contributing/guide.md` for step-by-step instructions.

## Code review

`CODEOWNERS` routes review to `@msambare`. PR template checklist must be satisfied.