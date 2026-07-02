---
title: "ADR-002 YAML Node Round-Trip"
created: 2026-07-02
type: project/adr
status: accepted
tags: [adr, kubevigil, fix]
---

# ADR-002: yaml.v3 Node API for Fix Round-Trip

## Status

Accepted

## Context

Operators store manifests in Git with comments, ordering, and formatting that `yaml.Marshal` destroys.

## Decision

The fix engine navigates and mutates `yaml.v3` AST nodes in place. No round-trip through Go structs for patching.

## Consequences

- Higher implementation complexity in `internal/fix/yaml_patcher.go`
- Golden fix integration tests lock formatting fidelity