---
title: "Developer Bootstrap"
audience: contributor
created: 2026-07-02
type: project/dev-bootstrap
status: reference
---

# Developer Environment Bootstrap

**Onboarding budget: 6 commands** to a green smoke check.

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
make all            # format, lint, vet, test, 96% coverage, secrets, vuln, build, smoke
```

## Smoke check

```bash
./bin/kubevigil version
./bin/kubevigil list checks | head
./bin/kubevigil scan -f test/fixtures/privileged/pod-privileged-true.yaml
```

## Optional

- **Bats** — `test/e2e/` end-to-end tests
- **Kind** — live cluster e2e

## First task

Pick a checker with the `good first issue` label, or add a table-driven test case to an existing checker per `docs/contributing/guide.md`.