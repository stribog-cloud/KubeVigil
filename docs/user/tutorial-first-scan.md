---
title: "Tutorial — Your First Manifest Scan"
audience: operator
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
aliases: [first-scan-tutorial, manifest-scan-tutorial]
type: project/user-tutorial
status: review-draft
tags: [kubevigil, tutorial, scanning, onboarding]
version: "1.0.0"
revision: 1
project: kubevigil
parent_moc: "[[MOC - KubeVigil User Documentation]]"
owners: [maintainers (@msambare)]
---

# Tutorial — Your First Manifest Scan

**Goal:** Install KubeVigil, scan a sample manifest, and read your first finding — in under five minutes.

**Prerequisites:** Go 1.25+ or a release binary; a terminal.

## Step 1 — Install

```bash
go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest
kubevigil version
```

You should see a version string (for example `1.0.0`).

## Step 2 — Pick a manifest

Clone the repository or use any local YAML file. This tutorial uses the bundled privileged-pod fixture:

```bash
export MANIFEST=test/fixtures/privileged/pod-privileged-true.yaml
```

If you are not in the repo root, point `MANIFEST` at any Deployment or Pod YAML on disk.

## Step 3 — Run the scan

```bash
kubevigil scan -f "$MANIFEST" -o text
```

**Expected result:** Exit code `1` (findings present) and at least one line mentioning `privileged` with severity **Critical** or **High**.

## Step 4 — Inspect structured output

```bash
kubevigil scan -f "$MANIFEST" -o json | head -40
```

JSON output lists each finding with `checker`, `severity`, `resource`, and `message` fields — suitable for CI parsers.

## Step 5 — List what ran

```bash
kubevigil list checks | head -20
```

This shows registered check IDs. Manifest mode runs only checks that support offline YAML (not live-cluster-only checks).

## Verification checklist

| Check | Pass criterion |
|-------|----------------|
| Binary runs | `kubevigil version` prints a version |
| Scan completes | `scan -f` returns 0 or 1 (not 2+) |
| Finding present | Output mentions `privileged` for the sample fixture |
| JSON valid | `scan -o json` parses as JSON |

## Next steps

- [Quickstart](../getting-started/quickstart.md) — cluster scans and output formats
- [Why manifest scanning?](explanation-why-manifest-scan.md) — when offline scans fit your workflow
- [CI integration](../scanning/ci-integration.md) — gate merges on findings

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers | Initial Diátaxis tutorial (audit F18). |