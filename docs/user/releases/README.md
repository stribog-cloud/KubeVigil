---
title: "User Release Notes"
audience: operator, integrator
created: 2026-07-02
updated: 2026-07-06
type: project/user-releases
status: review-draft
tags: [kubevigil, user, releases, changelog]
version: "1.1.0"
revision: 3
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

# cosign signature over the checksums file — identity is anchored to the
# release workflow, not just the repo, so it can't match a run from any
# other workflow in this repository.
cosign verify-blob \
  --certificate kubevigil_checksums.txt.pem \
  --signature kubevigil_checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/stribog-cloud/KubeVigil/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  kubevigil_checksums.txt

# cosign signature over the container image manifest (keyless, same issuer
# and anchored identity as above) — verifies the image itself, not just the
# checksums file
cosign verify \
  --certificate-identity-regexp '^https://github\.com/stribog-cloud/KubeVigil/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/stribog-cloud/kubevigil:1.0.0
```

**Upgrade:** `brew upgrade kubevigil`, re-run the install script, or pull the
new tag. No configuration migration required.

**Release recovery:** if a release run fails mid-way — for example, the
per-arch images were pushed to GHCR but the manifest list, cosign signatures,
or GitHub release itself were never created — do not try to resume the same
tag in place. Delete the partial `<version>-amd64` / `<version>-arm64` GHCR
tags (and any partial `<version>` manifest), then re-run by either cutting a
new `-rc.N` pre-release tag to validate the fix, or fixing the underlying
issue and re-pushing the tag. GoReleaser's `--clean` flag (already used in
`release.yml`) clears stale local `dist/` state on the re-run, and re-pushing
the same per-arch image tags is safe since Docker registries overwrite by
digest.

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