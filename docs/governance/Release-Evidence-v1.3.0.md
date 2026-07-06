---
title: "KubeVigil — Release Evidence"
created: 2026-07-06
updated: 2026-07-06
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "1.3.0"
release-date: "2026-07-06"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v1.3.0` on `2026-07-06`. Per Engineering Charter §7.4.

> **Filing note.** Filed at release time. Hashes are the authoritative SHA-256
> values from the Sigstore-signed `kubevigil_checksums.txt` on the GitHub
> Release. Tag `v1.3.0` → commit `04188c9`. This release adds 40 new security
> checks (110 → 150) — a detection-breadth expansion with no new subsystem.

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (`.goreleaser.yaml`) |
| Build environment | GitHub Actions `ubuntu-latest`; Go 1.25.11; GoReleaser 2.16.0; `CGO_ENABLED=0`; `-s -w` + version ldflags |
| Release workflow | `.github/workflows/release.yml` (run 28791419022, conclusion: success) |
| Release commit | `04188c9` |
| Verify command | `sha256sum -c --ignore-missing kubevigil_checksums.txt` |

Authoritative artifact digests:

| Artifact | SHA-256 |
|---|---|
| `kubevigil_1.3.0_linux_amd64.tar.gz` | `b6854f12849558f9a9092ddae49b39c90b099be7f815f004730a633622d94c23` |
| `kubevigil_1.3.0_linux_arm64.tar.gz` | `d03f2f66b591900f1f595f6e60bfe502427eedb003150002b506ed9c3014682d` |
| `kubevigil_1.3.0_darwin_amd64.tar.gz` | `f65a86a32695b5d7233cb605c4fa881698af9f41fa4f159153568cfcd9ae41c4` |
| `kubevigil_1.3.0_darwin_arm64.tar.gz` | `e99b937c8ca76c42bf88f4c11be1569aaffddb02de0fca10722d12849053be0e` |
| `kubevigil_1.3.0_windows_amd64.zip` | `51281cf4735a11f6cbed8d58d4a512e097037b3ba04ebb4fbca1f6e13c1eddb8` |

## Integrity Reference

| Reference | Location |
|---|---|
| SBOM (SPDX 2.3, per archive) | `kubevigil_1.3.0_<os>_<arch>.<ext>.sbom.spdx.json` on the GitHub Release (5 documents) |
| Checksums signature (Cosign, keyless) | `kubevigil_checksums.txt.sig` + `.pem` |
| Container image | `ghcr.io/stribog-cloud/kubevigil:1.3.0` (multi-arch), digest `sha256:4f04fb052cb9463a8b31708db06c905cef4bb2219d2ab7dd040673a46d83e51e` |
| Image signature + provenance | Cosign keyless (`docker_signs`) + SLSA build provenance over the image digest |

Verification results at release time:

- `cosign verify-blob …` over the checksums file → **Verified OK** (anchored to the release workflow identity).
- `gh attestation verify oci://ghcr.io/stribog-cloud/kubevigil:1.3.0` → **provenance verified** (exit 0).
- Image pulled and run **anonymously** → `KubeVigil 1.3.0`, `Total: 150 checks`.

## Smoke Test Record

Run against the **shipped** `darwin_arm64` binary and the published container image.

| Command | Expected | Observed | Pass |
|---|---|---|---|
| `kubevigil version` | `1.3.0` | `KubeVigil 1.3.0` (commit `04188c9`) | ✅ |
| `kubevigil list checks` | 150 built-in checks | `Total: 150 checks` | ✅ |
| container: `docker run ghcr.io/…/kubevigil:1.3.0 version` | `1.3.0` | `KubeVigil 1.3.0` (anonymous) | ✅ |
| container: `docker run ghcr.io/…/kubevigil:1.3.0 list checks` | 150 checks | `Total: 150 checks` | ✅ |

Additional verification: the 40 new checks were confirmed firing in **live** mode
against a Kind cluster (RBAC deletecollection, postStart network hook, zero grace
period, and others), not only in manifest mode.

Overall verdict: **PASS**.

## Size Budget Compliance (Annex §8.2)

Budget: ≤ 50 MB uncompressed binary, ≤ 20 MB compressed archive.

| Platform | Archive size | Within ≤20 MB |
|---|---|---|
| linux/amd64 | 13.4 MB | ✅ |
| linux/arm64 | 11.9 MB | ✅ |
| darwin/amd64 | 13.6 MB | ✅ |
| darwin/arm64 | 12.4 MB | ✅ |
| windows/amd64 | 13.7 MB | ✅ |

Shipped `darwin/arm64` binary: **40.0 MB** uncompressed (≤ 50 MB). Within budget.

## Source / Artifact Boundary

| Property | Value |
|---|---|
| Source root | `github.com/stribog-cloud/KubeVigil` @ `04188c9` |
| Excluded from source tree | per `.gitignore` / Annex §8.1 |
| Artifact root | GitHub Release `v1.3.0` + `ghcr.io/stribog-cloud/kubevigil:1.3.0` |
| Boundary declaration | Annex §1.3, §8.1 |

## Provenance Trailer

| Field | Value |
|---|---|
| Built by | GitHub Actions (`stribog-cloud/KubeVigil`, `release.yml`) |
| AI attribution | Prepared with Claude Code; `Co-authored-by: Claude` on AI-assisted commits |
| Build tooling | GoReleaser 2.16.0, Go 1.25.11, syft, cosign |
| Release commit | `04188c9` |
| Release tag | `v1.3.0` (annotated, SSH-signed; accepted by the `required_signatures` tag ruleset) |
| Signing identity | Sigstore keyless OIDC + SLSA build provenance |

## Release Checklist

- [x] Hash match verified; all 5 archive digests recorded
- [x] SBOM present and linked (5 SPDX documents)
- [x] Cosign signature over checksums verified ("Verified OK")
- [x] SLSA provenance attestation present and verified (archives + image)
- [x] Smoke tests pass against the shipped artifact (`Total: 150 checks`)
- [x] Size budget met (Annex §8.2)
- [x] GitHub Release published as latest; GHCR image public + anonymously pullable
- [x] Two-agent red-team pass superseded by a maintainer red-team + fix cycle; all findings fixed before tag — framework display-name backfill (8 MITRE + 10 NSA), one prose/mapping inconsistency (`hostaliases-injection` → T1557), one fabricated CIS id rejected, per-category doc counts corrected against the binary
- [x] This evidence record filed to the project's audit trail

*Filed by maintainers (@msambare) on 2026-07-06. Append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-06 | Initial release evidence for v1.3.0, filed at release time. |
