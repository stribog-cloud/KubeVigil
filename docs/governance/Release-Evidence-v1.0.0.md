---
title: "KubeVigil — Release Evidence"
created: 2026-07-06
updated: 2026-07-06
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "1.0.0"
release-date: "2026-07-06"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v1.0.0` on `2026-07-06`. Per Engineering Charter §7.4.

> **Filing note.** Filed at release time (not retrospectively). All hashes below
> are the authoritative SHA-256 values from the signed `kubevigil_checksums.txt`
> published to the GitHub Release, cross-checked against the downloaded
> artifacts. Release tag `v1.0.0` → commit `c7cde1a`.

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (`.goreleaser.yaml`) |
| Build environment | GitHub Actions `ubuntu-latest`; Go 1.25.11; GoReleaser 2.16.0; `CGO_ENABLED=0`; `-s -w` + version ldflags |
| Release workflow | `.github/workflows/release.yml` (run 28771164525, conclusion: success) |
| Release commit | `c7cde1a` |
| Verify command | `sha256sum -c --ignore-missing kubevigil_checksums.txt` |

Authoritative artifact digests (from the Sigstore-signed `kubevigil_checksums.txt`):

| Artifact | SHA-256 |
|---|---|
| `kubevigil_1.0.0_linux_amd64.tar.gz` | `b8cdbd6a526d8c111e19cb8c664e97c6639e41a247576eca0f98a505c1a7c37e` |
| `kubevigil_1.0.0_linux_arm64.tar.gz` | `768591959ad89c254a71109c696045441ac3925c739fa0be1b7d9ea943d1e01f` |
| `kubevigil_1.0.0_darwin_amd64.tar.gz` | `f904ccd1a2d7609bf75e20bcdcc268dcd8b5e0a3ff0fc86382a78590aa282057` |
| `kubevigil_1.0.0_darwin_arm64.tar.gz` | `a05fa9e913533c88c6da16551790cf075d183da1eef57f9438517cf4ce4791e4` |
| `kubevigil_1.0.0_windows_amd64.zip` | `9866fab42b6b80672c0ce756be20e7057fa4a8e866c5ecd7cd91961dd66dd2f9` |

Local re-download of `linux_amd64.tar.gz` recomputed to
`b8cdbd6a…c1a7c37e` — **hash match: yes**.

## Integrity Reference

| Reference | Location |
|---|---|
| SBOM (SPDX 2.3, per archive) | `kubevigil_1.0.0_<os>_<arch>.<ext>.sbom.spdx.json` on the GitHub Release (5 documents) |
| Checksums signature (Cosign, keyless) | `kubevigil_checksums.txt.sig` + `kubevigil_checksums.txt.pem` |
| Container image | `ghcr.io/stribog-cloud/kubevigil:1.0.0` (multi-arch), digest `sha256:f180c52273a057cf8d82ade1c3a1cfa5c0fd4fb0e4c03e93a49ad31ac771e3bd` |
| Image signature | Cosign keyless (`docker_signs`, `.goreleaser.yaml`) |
| SLSA build provenance | `actions/attest-build-provenance` over the 5 archives + checksums **and** the container image digest |

Verify commands:

```bash
# checksums signature (verified during release certification: "Verified OK")
cosign verify-blob \
  --certificate kubevigil_checksums.txt.pem \
  --signature   kubevigil_checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/stribog-cloud/KubeVigil/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  kubevigil_checksums.txt

# container image signature
cosign verify \
  --certificate-identity-regexp '^https://github.com/stribog-cloud/KubeVigil/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/stribog-cloud/kubevigil:1.0.0

# provenance
gh attestation verify oci://ghcr.io/stribog-cloud/kubevigil:1.0.0 -R stribog-cloud/KubeVigil
```

**Cosign checksums signature: verified OK** at release time with the anchored
identity regex above.

## Smoke Test Record

Run against the **shipped** `darwin_arm64` binary extracted from the release archive.

| Command | Expected | Observed | Pass |
|---|---|---|---|
| `kubevigil version` | reports `1.0.0` | `KubeVigil 1.0.0`, commit `c7cde1a` | ✅ |
| `kubevigil list checks` | 110 checks | `Total: 110 checks` | ✅ |
| `kubevigil scan -f test/fixtures/privileged` | findings → nonzero exit | exit `1` (findings ≥ fail-on) | ✅ |

Overall verdict: **PASS**.

## Size Budget Compliance (Annex §8.2)

Budget: ≤ 50 MB per uncompressed binary, ≤ 20 MB per compressed archive.

| Platform | Archive size | Within ≤20 MB |
|---|---|---|
| linux/amd64 | 12.3 MB | ✅ |
| linux/arm64 | 10.9 MB | ✅ |
| darwin/amd64 | 12.5 MB | ✅ |
| darwin/arm64 | 11.4 MB | ✅ |
| windows/amd64 | 12.7 MB | ✅ |

Uncompressed binaries measure 36–40 MB per platform (≤ 50 MB). **Within budget.**

## Source / Artifact Boundary

| Property | Value |
|---|---|
| Source root | `github.com/stribog-cloud/KubeVigil` @ `c7cde1a` |
| Excluded from source tree | `docs/internal/`, `CLAUDE*.md`, `.claude/`, `.beads/`, build artifacts (`.gitignore`; Annex §8.1) |
| Artifact root | GitHub Release `v1.0.0` + `ghcr.io/stribog-cloud/kubevigil` |
| Boundary declaration | Annex §1.3 (coverage boundary) and §8.1 (public release profile) |

## Provenance Trailer

| Field | Value |
|---|---|
| Built by | GitHub Actions (`stribog-cloud/KubeVigil`, `release.yml`) |
| AI attribution | Prepared with Claude Code; commits carry `Co-authored-by: Claude <noreply@anthropic.com>` |
| Build tooling | GoReleaser 2.16.0, Go 1.25.11, syft (SBOM), cosign (Sigstore keyless) |
| Build timestamp | 2026-07-06T06:03:29Z (binary build stamp) |
| Release commit | `c7cde1a` |
| Release tag | `v1.0.0` (annotated, SSH-signed; accepted by the `required_signatures` tag ruleset) |
| Signing identity | Sigstore keyless OIDC (`token.actions.githubusercontent.com`) + SLSA build provenance |

## Release Checklist

- [x] Hash match verified (linux/amd64 re-download; all 5 archive digests recorded)
- [x] SBOM present and linked (5 SPDX documents)
- [x] Cosign signature over checksums verified ("Verified OK")
- [x] SLSA provenance attestation present (archives + checksums + image digest)
- [x] Smoke tests pass against the shipped artifact (version / list checks / scan)
- [x] Size budget met (Annex §8.2)
- [x] Source/artifact boundary matches Annex §1.3 / §8.1
- [x] Release commit tagged, signed, and pushed (`v1.0.0` → `c7cde1a`)
- [x] GitHub Release published; Homebrew tap serves `1.0.0`; krew manifest regenerated
- [ ] GHCR package visibility set to **public** — pending a maintainer one-click (Settings → Packages → `kubevigil` → Change visibility / Inherit from repository). The image, its Cosign signature, and its SLSA provenance are already published by the release pipeline; only registry visibility remains. Until then, `docker pull` requires authentication.
- [x] This evidence record filed to the project's audit trail

*Filed by maintainers (@msambare) on 2026-07-06. Append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-06 | Initial release evidence for v1.0.0, filed at release time. |
