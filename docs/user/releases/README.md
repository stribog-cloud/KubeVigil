---
title: "User Release Notes"
audience: operator, integrator
created: 2026-07-02
updated: 2026-07-06
type: project/user-releases
status: review-draft
tags: [kubevigil, user, releases, changelog]
version: "1.1.0"
revision: 2
project: kubevigil
parent_moc: "[[MOC - KubeVigil User Documentation]]"
owners: [maintainers (@msambare)]
---

# User Release Notes

User-facing changes by version. Producer changelog: `CHANGELOG.md` at repository root.

## v1.0.0 (2026-07-06)

First stable release. CLI commands and flags, exit codes, the 8 output
formats, the configuration schema, and the 6 MCP tools now carry
semantic-versioning stability guarantees.

**New**

- GitHub Action for manifest scanning in CI with SARIF output — see the
  [GitHub Action guide](../../integrations/github-action.md)
- Container images: `docker run ghcr.io/stribog-cloud/kubevigil:1.0.0 version`
  (multi-arch amd64/arm64, distroless, non-root)
- Every release now ships SBOMs (SPDX), a Sigstore-signed checksums file, and
  SLSA build provenance attestations

**Fixed**

- Windows builds work again (the v0.5.0+ development line briefly broke
  `windows/amd64` compilation in the MCP path-confinement layer)

**Verification**

```bash
# checksum verification (unchanged)
sha256sum -c --ignore-missing kubevigil_checksums.txt

# cosign signature over the checksums file (new)
cosign verify-blob \
  --certificate kubevigil_checksums.txt.pem \
  --signature kubevigil_checksums.txt.sig \
  --certificate-identity-regexp 'github.com/stribog-cloud/KubeVigil' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  kubevigil_checksums.txt
```

**Upgrade:** `brew upgrade kubevigil`, re-run the install script, or pull the
new tag. No configuration migration required.

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