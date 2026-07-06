---
title: "KubeVigil — Release Evidence"
created: 2026-07-06
updated: 2026-07-06
type: stribog/release-evidence
status: governing-reference
tags: [stribog, release, evidence, kubevigil, governance]
release-version: "1.1.0"
release-date: "2026-07-06"
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Release Evidence

Release `v1.1.0` on `2026-07-06`. Per Engineering Charter §7.4.

> **Filing note.** Filed at release time. Hashes are the authoritative SHA-256
> values from the Sigstore-signed `kubevigil_checksums.txt` on the GitHub
> Release. Tag `v1.1.0` → commit `517ce3a`. This release adds the CEL custom
> policy engine and finding baselining (both opt-in, no schema/output-contract
> break).

---

## Reproducible Build

| Property | Value |
|---|---|
| Build command | `goreleaser release --clean` (`.goreleaser.yaml`) |
| Build environment | GitHub Actions `ubuntu-latest`; Go 1.25.11; GoReleaser 2.16.0; `CGO_ENABLED=0`; `-s -w` + version ldflags |
| Release workflow | `.github/workflows/release.yml` (run 28780434207, conclusion: success) |
| Release commit | `517ce3a` |
| Verify command | `sha256sum -c --ignore-missing kubevigil_checksums.txt` |

Authoritative artifact digests:

| Artifact | SHA-256 |
|---|---|
| `kubevigil_1.1.0_linux_amd64.tar.gz` | `6c2b7452f370f1eb90c5c0998aef44f6ebe0f074ffa8ec229eed5802b649d87f` |
| `kubevigil_1.1.0_linux_arm64.tar.gz` | `873692ba52496d45e4aa4271d1d596846145e0eacea731280ece525c99267d9d` |
| `kubevigil_1.1.0_darwin_amd64.tar.gz` | `1c2e4e8ca7aa11d235aa4175c162282a3860d3ca35eeff219633e51a69c5aa04` |
| `kubevigil_1.1.0_darwin_arm64.tar.gz` | `af556811f4dc3c343e86fc58cd0227858e28cb3f8db47bd28d0a9d4341c60d0b` |
| `kubevigil_1.1.0_windows_amd64.zip` | `9b8bad98fa5a725e11740527ebff59db5cc29a4c50a0d609642eba409ffb3123` |

## Integrity Reference

| Reference | Location |
|---|---|
| SBOM (SPDX 2.3, per archive) | `kubevigil_1.1.0_<os>_<arch>.<ext>.sbom.spdx.json` on the GitHub Release (5 documents) |
| Checksums signature (Cosign, keyless) | `kubevigil_checksums.txt.sig` + `.pem` |
| Container image | `ghcr.io/stribog-cloud/kubevigil:1.1.0` (multi-arch), digest `sha256:1bb013944d2189610181fc37f89d5d9673c19b998ceda459e36ae21b6af93886` |
| Image signature + provenance | Cosign keyless (`docker_signs`) + SLSA build provenance over the image digest |

Verification results at release time:

- `cosign verify-blob …` over the checksums file → **Verified OK** (anchored to the release workflow identity).
- `gh attestation verify oci://ghcr.io/stribog-cloud/kubevigil:1.1.0` → **provenance verified** (exit 0).
- `linux/amd64` archive re-download recomputed to the digest above → **hash match**.

## Smoke Test Record

Run against the **shipped** `darwin_arm64` binary, exercising the new features.

| Command | Expected | Observed | Pass |
|---|---|---|---|
| `kubevigil version` | `1.1.0` | `KubeVigil 1.1.0` | ✅ |
| `kubevigil list checks` | 110 built-in checks | `Total: 110 checks` | ✅ |
| `kubevigil policy validate configs/example-policies.yaml` | valid | `OK: 4 policies valid` | ✅ |
| `kubevigil scan -f test/fixtures/privileged --save-baseline b.json` | baseline written | `Baseline written … (198 findings)` | ✅ |
| `kubevigil scan … --baseline b.json --fail-on-new` | exit 0 (no drift) | exit 0 | ✅ |
| container: `docker run ghcr.io/…/kubevigil:1.1.0 version` | `1.1.0` | `KubeVigil 1.1.0` (anonymous pull) | ✅ |

Overall verdict: **PASS**.

## Size Budget Compliance (Annex §8.2)

Budget: ≤ 50 MB uncompressed binary, ≤ 20 MB compressed archive.

| Platform | Archive size | Within ≤20 MB |
|---|---|---|
| linux/amd64 | 13.7 MB | ✅ |
| linux/arm64 | 12.1 MB | ✅ |
| darwin/amd64 | 13.9 MB | ✅ |
| darwin/arm64 | 12.6 MB | ✅ |
| windows/amd64 | 14.0 MB | ✅ |

Shipped `darwin/arm64` binary: **39.2 MB** uncompressed (≤ 50 MB). The cel-go
dependency added roughly 1.5 MB to archives vs v1.0.0; still comfortably within
budget.

## Source / Artifact Boundary

| Property | Value |
|---|---|
| Source root | `github.com/stribog-cloud/KubeVigil` @ `517ce3a` |
| Excluded from source tree | per `.gitignore` / Annex §8.1 (unchanged) |
| Artifact root | GitHub Release `v1.1.0` + `ghcr.io/stribog-cloud/kubevigil:1.1.0` |
| Boundary declaration | Annex §1.3, §8.1 |

## Provenance Trailer

| Field | Value |
|---|---|
| Built by | GitHub Actions (`stribog-cloud/KubeVigil`, `release.yml`) |
| AI attribution | Prepared with Claude Code; `Co-authored-by: Claude` on AI-assisted commits |
| Build tooling | GoReleaser 2.16.0, Go 1.25.11, syft, cosign |
| Release commit | `517ce3a` |
| Release tag | `v1.1.0` (annotated, SSH-signed; accepted by the `required_signatures` tag ruleset) |
| Signing identity | Sigstore keyless OIDC + SLSA build provenance |

## Release Checklist

- [x] Hash match verified (linux/amd64; all 5 archive digests recorded)
- [x] SBOM present and linked (5 SPDX documents)
- [x] Cosign signature over checksums verified ("Verified OK")
- [x] SLSA provenance attestation present and verified (archives + image)
- [x] Smoke tests pass against the shipped artifact, incl. the new policy/baseline features
- [x] Size budget met (Annex §8.2)
- [x] GitHub Release published as latest; Homebrew tap serves `1.1.0`
- [x] GHCR image public (visibility inherited from the repo) and anonymously pullable
- [x] Two adversarial red-team passes completed; all findings fixed before tag (incl. the fingerprint-collision security fix)
- [x] This evidence record filed to the project's audit trail

*Filed by maintainers (@msambare) on 2026-07-06. Append-only after filing.*

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-06 | Initial release evidence for v1.1.0, filed at release time. |
