---
title: "ADR-002 YAML Node Round-Trip"
created: 2026-07-02
updated: 2026-07-02
type: project/adr
adr_status: accepted
status: governing-reference
tags: [adr, kubevigil, fix]
project: kubevigil
version: "1.0.0"
revision: 2
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# ADR-002: yaml.v3 Node API for Fix Round-Trip

## adr_status

accepted

## Status

Accepted

## Context

Operators store manifests in Git with comments, ordering, and formatting that `yaml.Marshal` destroys.

## Decision

The fix engine navigates and mutates `yaml.v3` AST nodes in place. No round-trip through Go structs for patching.

## Alternatives Considered

| Option | Outcome |
|--------|---------|
| Do nothing (use `yaml.Marshal`) | Rejected — destroys comments and field order; breaks Git diffs |
| String-replacement patches | Rejected — fragile on indentation and multi-doc files |
| `yaml.v3` Node API in place (chosen) | Preserves formatting; higher implementation cost |

## Forces

- Git diffs must be minimal and reviewable
- Multi-document YAML and inline comments are common in production repos
- Checker logic already uses unstructured objects; fix must not re-marshal through them

## Verification

- Golden fix integration tests in `test/integration/fix_integration_test.go`
- `internal/fix/yaml_patcher.go` uses `yaml.Node` navigation exclusively
- `golangci-lint` custom check or review gate: no `yaml.Marshal` in `internal/fix/`

## Consequences

- Higher implementation complexity in `internal/fix/yaml_patcher.go`
- Golden fix integration tests lock formatting fidelity

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers | Initial ADR filed during charter compliance program. |
| 2 | 2026-07-02 | maintainers | Added mandatory template fields: Alternatives, Forces, Verification (audit F16). |