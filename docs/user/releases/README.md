---
title: "User Release Notes"
audience: operator, integrator
created: 2026-07-02
updated: 2026-07-06
type: project/user-releases
status: review-draft
tags: [kubevigil, user, releases, changelog]
version: "1.4.0"
revision: 6
project: kubevigil
parent_moc: "[[MOC - KubeVigil User Documentation]]"
owners: [maintainers (@msambare)]
---

# User Release Notes

User-facing changes by version. Producer changelog: `CHANGELOG.md` at repository root.

## v1.4.0 (2026-07-06)

**Image vulnerability scanning.** Posture is only half the picture — an image can
be perfectly configured and still ship known-vulnerable software. The new
`kubevigil vuln` command scans a container image's SBOM (SPDX or CycloneDX) against
the [OSV.dev](https://osv.dev) vulnerability database and reports known CVEs as
findings, **fused into the same report** as a posture scan — same severities,
same `--fail-on` gating, same eight output formats.

```bash
syft myapp:1.4.0 -o spdx-json > app.spdx.json
kubevigil vuln --sbom app.spdx.json --image myapp:1.4.0 --fail-on high
```

Severity is derived from each advisory's CVSS score, and every finding names the
affected package and the fixed version to upgrade to. The command needs network
access to `api.osv.dev`; the SBOM is generated out-of-band by syft, trivy, or
`docker sbom`. See the [Vulnerability Scanning guide](../../scanning/vulnerability-scanning.md).

**Upgrade:** `brew upgrade kubevigil` or pull the new release. The feature is
opt-in — existing scans are unchanged.

## v1.3.0 (2026-07-06)

**40 new security checks (110 → 150).** KubeVigil's built-in catalogue grows across
RBAC escalation paths, the Gateway API, admission-controller configuration, CRD
hardening, workload isolation, storage, scheduling, and secret hygiene — for
example wildcard-scoped mutating webhooks, dangling ExternalName services, missing
CRD conversion webhooks, Windows HostProcess containers, and TLS secrets with weak
keys. Compliance coverage grew with them (MITRE ATT&CK now maps 34 techniques).

**Upgrade:** `brew upgrade kubevigil`. The new checks run automatically; expect
more findings on an unchanged cluster. Use `--min-severity` or exemptions to tune
the signal.

## v1.2.0 (2026-07-06)

**Admission webhook.** KubeVigil can now gate deployments in real time, not just
audit them. `kubevigil webhook` serves a Kubernetes ValidatingAdmissionWebhook
that scans each admitted object with the same checks and your custom policies,
**denying** anything with findings at or above `--fail-on` severity (with a clear
reason) and surfacing the rest as `kubectl` warnings. It fails **open** — a
webhook fault never blocks your cluster's admissions. Deploy manifests and a
TLS/cert-manager guide are in `deploy/webhook/`; see the
[Admission Webhook guide](../../integrations/admission-webhook.md).

**Upgrade:** `brew upgrade kubevigil` or pull the new release. The webhook is
opt-in — nothing changes unless you deploy it.

## v1.1.0 (2026-07-06)

**Custom policies (CEL).** Write your own checks as CEL expressions in
`.kubevigil.yaml` or a `--policy-file`, and they run alongside the built-in
checks with the same severity, exemptions, compliance mapping, and output
formats. Validate them with `kubevigil policy validate`. See the
[Custom Policies guide](../../policies/custom-policies.md).

**Baseline & drift.** Accept the current findings as a baseline
(`kubevigil scan --save-baseline baseline.json`), then in CI fail only on
findings that are *new* relative to it (`--baseline baseline.json --fail-on-new`).
Findings are annotated new/existing and resolved findings are reported. See the
[Baseline & Drift guide](../../policies/baseline-drift.md).

**Upgrade:** `brew upgrade kubevigil` or pull the new release. No configuration
migration required — both features are opt-in.

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