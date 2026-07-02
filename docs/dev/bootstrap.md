---
title: "Developer Bootstrap"
audience: contributor
created: 2026-07-02
updated: 2026-07-02
type: project/dev-tutorial
status: review-draft
tags: [kubevigil, developer, bootstrap, onboarding, tutorial]
version: "1.1.0"
revision: 2
project: kubevigil
parent_moc: "[[MOC - KubeVigil Developer Documentation]]"
owners: [maintainers (@msambare)]
---

# Developer Environment Bootstrap

**Onboarding budget: 6 commands** to a green smoke check.

This is a **tutorial** (single named path to a verifiable end state), not a reference sheet.

## Prerequisites

- Go 1.25+
- `make`, `git`
- `golangci-lint` ([install](https://golangci-lint.run/usage/install/))
- `gitleaks` ([install](https://github.com/gitleaks/gitleaks#installing))
- `govulncheck` (`go install golang.org/x/vuln/cmd/govulncheck@latest`)

## Bootstrap

```bash
git clone https://github.com/stribog-cloud/KubeVigil.git
cd KubeVigil
go version          # must be 1.25+
make hooks-install
make all            # format, lint, vet, test, 96% coverage, secrets, vuln, build, smoke, doc gates
```

## Smoke check

```bash
./bin/kubevigil version
./bin/kubevigil list checks | head
./bin/kubevigil scan -f test/fixtures/privileged/pod-privileged-true.yaml
```

## Verification

| Step | Pass criterion |
|------|----------------|
| `make all` | Exit 0 |
| `version` | Prints semver |
| `list checks` | Non-empty table |
| `scan -f` | Exit 0 or 1 with findings for privileged fixture |

## Optional

- **Bats** — `test/e2e/` end-to-end tests
- **Kind** — live cluster e2e

## First task

Pick a checker with the `good first issue` label, or add a table-driven test case to an existing checker per `docs/contributing/guide.md`.

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers | Initial developer bootstrap. |
| 2 | 2026-07-02 | maintainers | Retyped as tutorial (`type: project/dev-tutorial`, `status: review-draft`); `make all` includes doc gates (audit F13/F18). |