---
title: "KubeVigil — Release Evidence"
created: 2026-07-02
updated: 2026-07-02
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "0.5.0"
release-date: "2026-02-20"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v0.5.0` on `2026-02-20`. Per Engineering Charter §7.4.

> **Filing note.** This record is filed retrospectively during the charter-compliance program (2026-07-02) because v0.5.0 shipped before the Release Evidence artifact existed. Hashes are taken from the published Krew manifest (`deploy/krew/kubevigil.yaml`) and GitHub release artifacts.

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (see `.goreleaser.yaml`) |
| Build environment | GoReleaser cross-compile; Go 1.25.7 per `go.mod` |
| Expected artifact hash (SHA-256) | `e704fa6e82637c0d02fd57d32791b242567b7219f1f6db10657763924d97a55e` (linux/amd64 tarball) |
| Observed artifact hash (SHA-256) | `e704fa6e82637c0d02fd57d32791b242567b7219f1f6db10657763924d97a55e` |
| Hash match | yes |
| Artifact path(s) | `https://github.com/stribog-cloud/KubeVigil/releases/download/v0.5.0/kubevigil_0.5.0_linux_amd64.tar.gz` |

---

## Integrity Reference

| Artifact | SBOM pointer | Signature pointer | Verification command |
|---|---|---|---|
| `kubevigil_0.5.0_linux_amd64.tar.gz` | Not filed for v0.5.0 | GitHub release checksums file | `sha256sum kubevigil_0.5.0_linux_amd64.tar.gz` |

---

## Smoke Test Record

> Run against the shipped artifact, not the source tree.

| Test / Command | Expected outcome | Observed outcome | Pass |
|---|---|---|---|
| `kubevigil version` | Prints `v0.5.0` | `KubeVigil v0.5.0` | yes |
| `kubevigil list checks` | Lists 110 checks | 110 checks enumerated | yes |
| `kubevigil scan -f test/fixtures/privileged/pod-privileged-true.yaml` | Finding on privileged container | Finding reported | yes |

**Overall smoke result:** PASS

---

## Size Budget Compliance

| Property | Value |
|---|---|
| Declared size budget | Not declared in Annex §1.3 for v0.5.0 |
| Observed artifact size | ~15 MB compressed (linux/amd64 tarball) |
| Within budget | N/A — no budget filed at release time |
| Notes | Size budget discipline applies to future releases per Charter Compliance Annex §1.3 |

---

## Source / Artifact Boundary

| Property | Value |
|---|---|
| Source root | Repository root (`internal/`, `cmd/`) |
| Generated / excluded paths | `test/` fixtures and harnesses per Annex §1.3 |
| Artifact root | GoReleaser `dist/` binaries and GitHub release archives |
| Boundary declaration location | Charter Compliance Annex §1.3 |

---

## Provenance Trailer

| Property | Value |
|---|---|
| Built by | GoReleaser CI on tag `v0.5.0` |
| AI-attribution | N/A — release predates charter-compliance program |
| Build tooling | GoReleaser, Go 1.25.7 |
| Build timestamp (UTC) | 2026-02-20 (release date per CHANGELOG) |
| Release commit SHA | Tag `v0.5.0` on `main` |
| Release tag | `v0.5.0` |
| Signing key / identity | GitHub release checksums (no cosign at v0.5.0) |

---

## Release Checklist

- [x] Hash match verified (linux/amd64 reference artifact)
- [ ] SBOM present and linked (deferred — not produced for v0.5.0)
- [x] Smoke tests pass against the shipped artifact
- [x] Size budget met (N/A — no budget declared)
- [x] Source/artifact boundary matches Compliance Annex §1.3
- [x] Release commit tagged and pushed
- [x] This evidence record filed to the project's audit trail

---

*Filed by maintainers (@msambare) on 2026-07-02. This record is append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-02 | Retrospective release evidence filed for v0.5.0. Closes audit finding F11. |