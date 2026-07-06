---
title: "KubeVigil — Release Evidence"
created: 2026-07-06
updated: 2026-07-06
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "1.2.0"
release-date: "2026-07-06"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v1.2.0` on `2026-07-06`. Per Engineering Charter §7.4.

> **Filing note.** Filed at release time. Hashes are the authoritative SHA-256
> values from the Sigstore-signed `kubevigil_checksums.txt` on the GitHub
> Release. Tag `v1.2.0` → commit `30c60f1`. This release adds the validating
> admission webhook (opt-in runtime surface).

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (`.goreleaser.yaml`) |
| Build environment | GitHub Actions `ubuntu-latest`; Go 1.25.11; GoReleaser 2.16.0; `CGO_ENABLED=0`; `-s -w` + version ldflags |
| Release workflow | `.github/workflows/release.yml` (run 28783769902, conclusion: success) |
| Release commit | `30c60f1` |
| Verify command | `sha256sum -c --ignore-missing kubevigil_checksums.txt` |

Authoritative artifact digests:

| Artifact | SHA-256 |
|---|---|
| `kubevigil_1.2.0_linux_amd64.tar.gz` | `6d9f732baa6f898c19976bc5b36936c246bbd3cedbc4242218b2c806ffe2dfd3` |
| `kubevigil_1.2.0_linux_arm64.tar.gz` | `956e013ed53e8e470c68f9d118b4e0d97a6847fb1a34857d07e801f3a3cf2d7e` |
| `kubevigil_1.2.0_darwin_amd64.tar.gz` | `7a47043935061fbb59d6ccadbe0bbd5e3c8a1ac204c82a797856eb9a5f40a352` |
| `kubevigil_1.2.0_darwin_arm64.tar.gz` | `a6880e817260a0c1bc71f914a5c33ef55e30b2bbabfe54e310979183e4c38918` |
| `kubevigil_1.2.0_windows_amd64.zip` | `f855615073cf74e28ebfdc7e13fad6295d4dd82578216f7f059a513cbdd629e5` |

## Integrity Reference

| Reference | Location |
|---|---|
| SBOM (SPDX 2.3, per archive) | `kubevigil_1.2.0_<os>_<arch>.<ext>.sbom.spdx.json` on the GitHub Release (5 documents) |
| Checksums signature (Cosign, keyless) | `kubevigil_checksums.txt.sig` + `.pem` |
| Container image | `ghcr.io/stribog-cloud/kubevigil:1.2.0` (multi-arch), digest `sha256:203266bd8c8a36c023c5ee00765c76ce009e68be5d456add0cce956a122cb0b9` |
| Image signature + provenance | Cosign keyless (`docker_signs`) + SLSA build provenance over the image digest |

Verification results at release time:

- `cosign verify-blob …` over the checksums file → **Verified OK** (anchored to the release workflow identity).
- `gh attestation verify oci://ghcr.io/stribog-cloud/kubevigil:1.2.0` → **provenance verified** (exit 0).
- Image pulled and run **anonymously** → `KubeVigil 1.2.0`.

## Smoke Test Record

Run against the **shipped** `darwin_arm64` binary, exercising the new webhook surface.

| Command | Expected | Observed | Pass |
|---|---|---|---|
| `kubevigil version` | `1.2.0` | `KubeVigil 1.2.0` | ✅ |
| `kubevigil webhook --help` | describes the admission webhook | full usage shown | ✅ |
| `kubevigil list checks` | 110 built-in checks | `Total: 110 checks` | ✅ |
| container: `docker run ghcr.io/…/kubevigil:1.2.0 version` | `1.2.0` | `KubeVigil 1.2.0` (anonymous) | ✅ |

Additional runtime verification (dev): a live `kubevigil webhook` instance denied
a privileged pod (403 with a 6-finding reason) and denied a 20,000-container
amplification object in ~40 ms (the red-team blocker fix); `/healthz` returned 200.

Overall verdict: **PASS**.

## Size Budget Compliance (Annex §8.2)

Budget: ≤ 50 MB uncompressed binary, ≤ 20 MB compressed archive.

| Platform | Archive size | Within ≤20 MB |
|---|---|---|
| linux/amd64 | 14.0 MB | ✅ |
| linux/arm64 | 12.4 MB | ✅ |
| darwin/amd64 | 14.2 MB | ✅ |
| darwin/arm64 | 12.9 MB | ✅ |
| windows/amd64 | 14.3 MB | ✅ |

Shipped `darwin/arm64` binary: **39.8 MB** uncompressed (≤ 50 MB). Within budget.

## Source / Artifact Boundary

| Property | Value |
|---|---|
| Source root | `github.com/stribog-cloud/KubeVigil` @ `30c60f1` |
| Excluded from source tree | per `.gitignore` / Annex §8.1 |
| Artifact root | GitHub Release `v1.2.0` + `ghcr.io/stribog-cloud/kubevigil:1.2.0` |
| Boundary declaration | Annex §1.3, §8.1 |

## Provenance Trailer

| Field | Value |
|---|---|
| Built by | GitHub Actions (`stribog-cloud/KubeVigil`, `release.yml`) |
| AI attribution | Prepared with Claude Code; `Co-authored-by: Claude` on AI-assisted commits |
| Build tooling | GoReleaser 2.16.0, Go 1.25.11, syft, cosign |
| Release commit | `30c60f1` |
| Release tag | `v1.2.0` (annotated, SSH-signed; accepted by the `required_signatures` tag ruleset) |
| Signing identity | Sigstore keyless OIDC + SLSA build provenance |

## Release Checklist

- [x] Hash match verified; all 5 archive digests recorded
- [x] SBOM present and linked (5 SPDX documents)
- [x] Cosign signature over checksums verified ("Verified OK")
- [x] SLSA provenance attestation present and verified (archives + image)
- [x] Smoke tests pass against the shipped artifact, incl. the new webhook command
- [x] Size budget met (Annex §8.2)
- [x] GitHub Release published as latest; Homebrew tap serves `1.2.0`; GHCR image public + anonymously pullable
- [x] Two adversarial red-team passes; all findings fixed before tag — incl. the amplification fail-open bypass (BLOCKER) and the deploy-manifest dogfood findings
- [x] This evidence record filed to the project's audit trail

*Filed by maintainers (@msambare) on 2026-07-06. Append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-06 | Initial release evidence for v1.2.0, filed at release time. |
