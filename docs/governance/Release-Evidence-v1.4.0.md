---
title: "KubeVigil — Release Evidence"
created: 2026-07-06
updated: 2026-07-06
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "1.4.0"
release-date: "2026-07-06"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v1.4.0` on `2026-07-06`. Per Engineering Charter §7.4.

> **Filing note.** Filed at release time. Hashes are the authoritative SHA-256
> values from the Sigstore-signed `kubevigil_checksums.txt` on the GitHub
> Release. Tag `v1.4.0` → commit `2ab96c6`. This release adds the image
> vulnerability layer (`kubevigil vuln`, OSV.dev CVE fusion).

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (`.goreleaser.yaml`) |
| Build environment | GitHub Actions `ubuntu-latest`; Go 1.25.11; GoReleaser 2.16.0; `CGO_ENABLED=0`; `-s -w` + version ldflags |
| Release workflow | `.github/workflows/release.yml` (run 28795614287, conclusion: success) |
| Release commit | `2ab96c6` |
| Verify command | `sha256sum -c --ignore-missing kubevigil_checksums.txt` |

Authoritative artifact digests:

| Artifact | SHA-256 |
|---|---|
| `kubevigil_1.4.0_linux_amd64.tar.gz` | `94afc6981d4b3c7fa65e1324350a593f129cdd3b060c6f73c07c19e6bf672967` |
| `kubevigil_1.4.0_linux_arm64.tar.gz` | `b57280884b7110ec85c4fff06373320e3e8308cdc55abdb4bdcb6320bc428d58` |
| `kubevigil_1.4.0_darwin_amd64.tar.gz` | `b49704cc6c6b418de7b80e9e22a7d66122e525c8bcf43472df3cad688db38869` |
| `kubevigil_1.4.0_darwin_arm64.tar.gz` | `cf2df2d4f4708faee9d4acd19d4a970d37628c88dbaea8c8115d5741dd3a5adb` |
| `kubevigil_1.4.0_windows_amd64.zip` | `73ebf808a909d71d36572a8c5f6391238d09c5c379e1fe2831308c373c496441` |

## Integrity Reference

| Reference | Location |
|---|---|
| SBOM (SPDX 2.3, per archive) | `kubevigil_1.4.0_<os>_<arch>.<ext>.sbom.spdx.json` on the GitHub Release (5 documents) |
| Checksums signature (Cosign, keyless) | `kubevigil_checksums.txt.sig` + `.pem` |
| Container image | `ghcr.io/stribog-cloud/kubevigil:1.4.0` (multi-arch), digest `sha256:780be503d50bf779742673a11c3fc2ec4d8493c73a6596a569000d49c0e13659` |
| Image signature + provenance | Cosign keyless (`docker_signs`) + SLSA build provenance over the image digest |

Verification results at release time:

- `cosign verify-blob …` over the checksums file → **Verified OK** (anchored to the release workflow identity).
- `gh attestation verify oci://ghcr.io/stribog-cloud/kubevigil:1.4.0` → **provenance verified** (exit 0).
- Image pulled and run **anonymously** → `KubeVigil 1.4.0`; `kubevigil vuln --help` renders.

## Smoke Test Record

Run against the **shipped** `darwin_arm64` binary and the published container image.

| Command | Expected | Observed | Pass |
|---|---|---|---|
| `kubevigil version` | `1.4.0` | `KubeVigil 1.4.0` | ✅ |
| `kubevigil list checks` | 150 built-in checks | `Total: 150 checks` | ✅ |
| `kubevigil vuln --help` | describes the SBOM/OSV.dev command | full usage shown | ✅ |
| container: `docker run ghcr.io/…/kubevigil:1.4.0 version` | `1.4.0` | `KubeVigil 1.4.0` (anonymous) | ✅ |

Additional runtime verification: `kubevigil vuln` against an SBOM containing
django 3.2.0 returned 55 vulnerability findings, each with a CVSS-derived
severity and a package-specific fixed version, over the live OSV.dev API;
`--fail-on critical` exited 1.

Overall verdict: **PASS**.

## Size Budget Compliance (Annex §8.2)

Budget: ≤ 50 MB uncompressed binary, ≤ 20 MB compressed archive.

| Platform | Archive size | Within ≤20 MB |
|---|---|---|
| linux/amd64 | 13.4 MB | ✅ |
| linux/arm64 | 11.9 MB | ✅ |
| darwin/amd64 | 13.6 MB | ✅ |
| darwin/arm64 | 12.4 MB | ✅ |
| windows/amd64 | 13.8 MB | ✅ |

Shipped `darwin/arm64` binary: **40.1 MB** uncompressed (≤ 50 MB). Within budget.

## Source / Artifact Boundary

| Property | Value |
|---|---|
| Source root | `github.com/stribog-cloud/KubeVigil` @ `2ab96c6` |
| Excluded from source tree | per `.gitignore` / Annex §8.1 |
| Artifact root | GitHub Release `v1.4.0` + `ghcr.io/stribog-cloud/kubevigil:1.4.0` |
| Boundary declaration | Annex §1.3, §8.1 |

## Provenance Trailer

| Field | Value |
|---|---|
| Built by | GitHub Actions (`stribog-cloud/KubeVigil`, `release.yml`) |
| AI attribution | Prepared with Claude Code; `Co-authored-by: Claude` on AI-assisted commits |
| Build tooling | GoReleaser 2.16.0, Go 1.25.11, syft, cosign |
| Release commit | `2ab96c6` |
| Release tag | `v1.4.0` (annotated, SSH-signed; accepted by the `required_signatures` tag ruleset) |
| Signing identity | Sigstore keyless OIDC + SLSA build provenance |

## Release Checklist

- [x] Hash match verified; all 5 archive digests recorded
- [x] SBOM present and linked (5 SPDX documents)
- [x] Cosign signature over checksums verified ("Verified OK")
- [x] SLSA provenance attestation present and verified (archives + image)
- [x] Smoke tests pass against the shipped artifact, incl. the new `vuln` command
- [x] Size budget met (Annex §8.2)
- [x] GitHub Release published as latest; GHCR image public + anonymously pullable
- [x] Red-team + fix cycle before tag — per-package fixed-version resolution, bounded OSV response, validated + escaped advisory ids (gosec G704 SSRF), reproduced clean against the CI-pinned linter
- [x] This evidence record filed to the project's audit trail

*Filed by maintainers (@msambare) on 2026-07-06. Append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-06 | Initial release evidence for v1.4.0, filed at release time. |
