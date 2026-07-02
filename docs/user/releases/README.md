---
title: "User Release Notes"
audience: operator, integrator
created: 2026-07-02
type: project/user-releases
status: reference
---

# User Release Notes

User-facing changes by version. Producer changelog: `CHANGELOG.md` at repository root.

## v0.5.0 (2026-02-20)

**Security hardening**

- MCP and fix paths reject symlinks and enforce backup directory boundaries
- YAML parsing limits reduce memory exhaustion risk from malicious manifests

**Fix**

- `runAsUser` field no longer corrupted when applying run-as-root remediation

**Documentation**

- Checker counts and configuration keys corrected across user docs

**Upgrade:** Download latest release or `brew upgrade kubevigil`. No configuration migration required.

## Earlier versions

See `CHANGELOG.md` for full history.