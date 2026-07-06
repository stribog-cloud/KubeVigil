---
title: "KubeVigil — Release Evidence"
created: 2026-07-06
updated: 2026-07-06
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "1.5.0"
release-date: "2026-07-06"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v1.5.0` on `2026-07-06`. Per Engineering Charter §7.4.

> **Filing note.** Filed at release time. Hashes are the authoritative SHA-256
> values from the Sigstore-signed `kubevigil_checksums.txt` on the GitHub
> Release. Tag `v1.5.0` → commit `8fe5b37`. This release fixes a pre-existing
> CSV formula-injection vulnerability and ~13 checker false-negatives found by a
> post-v1.3 adversarial red-team.

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (`.goreleaser.yaml`) |
| Build environment | GitHub Actions `ubuntu-latest`; Go 1.25.11; GoReleaser 2.16.0; `CGO_ENABLED=0`; `-s -w` + version ldflags |
| Release workflow | `.github/workflows/release.yml` (run 28800237588, conclusion: success) |
| Release commit | `8fe5b37` |
| Verify command | `sha256sum -c --ignore-missing kubevigil_checksums.txt` |

Authoritative artifact digests:

| Artifact | SHA-256 |
|---|---|
| `kubevigil_1.5.0_linux_amd64.tar.gz` | `0c36a9dd7c7a913fea8b85d8d19222c8553f254c65712dc2c448f315f4f5f6e2` |
| `kubevigil_1.5.0_linux_arm64.tar.gz` | `8bfdd866217dc3bf1bb45d468a6b327a99f585897cce7aeb5f2b036e308d6885` |
| `kubevigil_1.5.0_darwin_amd64.tar.gz` | `861c773207c14eb3e8fdeb96532e6de0058ee6d56bbaaf468d0c7d7031be4888` |
| `kubevigil_1.5.0_darwin_arm64.tar.gz` | `d0635ba3d6acfdd215a4b6afc62ba5b55357aaecaa414175049f48d701d22931` |
| `kubevigil_1.5.0_windows_amd64.zip` | `5298d553d64f161406dec336dd66412cf83382377a170887f805549103e13421` |

## Integrity Reference

| Reference | Location |
|---|---|
| SBOM (SPDX 2.3, per archive) | `kubevigil_1.5.0_<os>_<arch>.<ext>.sbom.spdx.json` on the GitHub Release (5 documents) |
| Checksums signature (Cosign, keyless) | `kubevigil_checksums.txt.sig` + `.pem` |
| Container image | `ghcr.io/stribog-cloud/kubevigil:1.5.0` (multi-arch), digest `sha256:1e36bff4e18a05ae80f605ed7d4c26bb2104c42aa2fc9e093a785662df9aa0d0` |
| Image signature + provenance | Cosign keyless (`docker_signs`) + SLSA build provenance over the image digest |

Verification results at release time:

- `cosign verify-blob …` over the checksums file → **Verified OK** (anchored to the release workflow identity).
- `gh attestation verify oci://ghcr.io/stribog-cloud/kubevigil:1.5.0` → **provenance verified** (exit 0).
- Image pulled and run **anonymously** → `KubeVigil 1.5.0`, `Total: 150 checks`.

## Smoke Test Record

Run against the **shipped** `darwin_arm64` binary and the published container image.

| Command | Expected | Observed | Pass |
|---|---|---|---|
| `kubevigil version` | `1.5.0` | `KubeVigil 1.5.0` | ✅ |
| `kubevigil list checks` | 150 built-in checks | `Total: 150 checks` | ✅ |
| container: `docker run ghcr.io/…/kubevigil:1.5.0 version` | `1.5.0` | `KubeVigil 1.5.0` (anonymous) | ✅ |
| CSV-injection fix | `=…` resource cell neutralized with a leading `'` | shipped binary emits `,'=evil` | ✅ |

The CSV-injection fix was confirmed against the binary built from the exact
release commit (`8fe5b37`): a Pod named `=evil` produces a CSV whose Resource
cell is `'=evil` (quote-neutralized), not a live formula.

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
| Source root | `github.com/stribog-cloud/KubeVigil` @ `8fe5b37` |
| Excluded from source tree | per `.gitignore` / Annex §8.1 |
| Artifact root | GitHub Release `v1.5.0` + `ghcr.io/stribog-cloud/kubevigil:1.5.0` |
| Boundary declaration | Annex §1.3, §8.1 |

## Provenance Trailer

| Field | Value |
|---|---|
| Built by | GitHub Actions (`stribog-cloud/KubeVigil`, `release.yml`) |
| AI attribution | Prepared with Claude Code; `Co-authored-by: Claude` on AI-assisted commits |
| Build tooling | GoReleaser 2.16.0, Go 1.25.11, syft, cosign |
| Release commit | `8fe5b37` |
| Release tag | `v1.5.0` (annotated, SSH-signed; accepted by the `required_signatures` tag ruleset) |
| Signing identity | Sigstore keyless OIDC + SLSA build provenance |

## Release Checklist

- [x] Hash match verified; all 5 archive digests recorded
- [x] SBOM present and linked (5 SPDX documents)
- [x] Cosign signature over checksums verified ("Verified OK")
- [x] SLSA provenance attestation present and verified (archives + image)
- [x] Smoke tests pass against the shipped artifact, incl. the CSV-injection fix
- [x] Size budget met (Annex §8.2)
- [x] GitHub Release published as latest; GHCR image public + anonymously pullable
- [x] This release IS the outcome of an adversarial red-team + fix cycle — every fixed defect was empirically reproduced against the built binary, fixed, and regression-tested before tag
- [x] This evidence record filed to the project's audit trail

*Filed by maintainers (@msambare) on 2026-07-06. Append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-06 | Initial release evidence for v1.5.0, filed at release time. |
