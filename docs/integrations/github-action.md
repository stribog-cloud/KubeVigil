# GitHub Action

KubeVigil ships a first-party composite GitHub Action (`action.yml` at the
repository root) that downloads a release binary, scans your manifests, and
writes a report -- no `go install` or manual download step required.

## Usage

```yaml
name: KubeVigil Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  kubevigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: KubeVigil Scan
        uses: stribog-cloud/KubeVigil@main # pin to a release tag once available, e.g. @v1.0.0
        with:
          files: ./k8s/
```

By default this writes a SARIF report to `kubevigil-results.sarif` and never
fails the build on findings -- only a real scan or configuration error fails
the step. See the two worked examples below for gating the build on findings
and for uploading results to GitHub Code Scanning.

> Pin `uses:` to a release tag (or, for maximum supply-chain assurance, a full
> commit SHA) rather than `@main` in production workflows -- the same guidance
> CI already follows for third-party actions (see `.github/workflows/ci.yml`).

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `files` | Yes | -- | Path to a manifest file or directory to scan (passed to `kubevigil scan -f`) |
| `version` | No | `latest` | KubeVigil release to install: a tag (e.g. `v1.0.0`) or `latest` |
| `format` | No | `sarif` | Report format: `text`, `json`, `yaml`, `markdown`, `html`, `sarif`, `junit`, `csv` |
| `output-file` | No | `kubevigil-results.sarif` | Path to write the report to |
| `fail-on` | No | *(empty)* | Minimum severity (`info`, `low`, `medium`, `high`, `critical`) that fails the step. Empty means findings never fail the build -- only scan/config errors do. |
| `config` | No | *(empty)* | Path to a `.kubevigil.yaml` configuration file (passed as `--config`) |
| `flags` | No | *(empty)* | Extra raw CLI flags appended verbatim to `kubevigil scan` |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Exit code returned by the underlying `kubevigil scan` command (see [Exit Codes](../reference/exit-codes.md)) |
| `output-file` | Path to the generated report file (same value as the `output-file` input) |

## How `fail-on` and the build result interact

The `kubevigil scan` exit code contract is: `0` clean, `1` findings at or
above the fail-on threshold, `2` scan error, `3` configuration error. The
action always fails the step on exit codes `2` and `3` (real errors). Whether
exit code `1` (findings) fails the step depends on whether you set `fail-on`:

- `fail-on` unset (default) -- the step succeeds even if findings were
  detected; a warning annotation is emitted and `exit-code` reports the raw
  value so you can branch on it downstream.
- `fail-on` set (e.g. `high`) -- the value is passed through as
  `kubevigil scan --fail-on <value>`, and the step fails when findings meet
  or exceed that severity.

## Example: fail the build on critical findings

```yaml
- name: KubeVigil Scan
  uses: stribog-cloud/KubeVigil@main
  with:
    files: ./k8s/
    format: sarif
    output-file: kubevigil-results.sarif
    fail-on: critical
```

## Example: upload SARIF to GitHub Code Scanning

```yaml
permissions:
  security-events: write

steps:
  - uses: actions/checkout@v4

  - name: KubeVigil Scan
    id: kubevigil
    uses: stribog-cloud/KubeVigil@main
    with:
      files: ./k8s/
      format: sarif
      output-file: kubevigil-results.sarif

  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.kubevigil.outputs.output-file }}
```

`if: always()` ensures the SARIF file uploads even on a run where a later
step fails for an unrelated reason. Findings then appear under **Security >
Code scanning alerts** on the repository.

## Release asset verification

The action resolves the requested `version` to a GitHub release tag (or
queries `releases/latest` when `version: latest`), downloads the matching
`kubevigil_<version>_linux_<arch>.tar.gz` archive and the release's
`kubevigil_checksums.txt`, and verifies the archive's SHA256 checksum before
extracting and running the binary. A checksum mismatch or missing entry fails
the step with exit code `3`.

## See Also

- [SARIF Integration](sarif.md) -- SARIF structure and other CI platforms
- [JUnit Integration](junit.md) -- CI/CD test result integration
- [Exit Codes](../reference/exit-codes.md) -- scan and fix exit codes
- [Output Formats](../scanning/output-formats.md) -- all 8 supported formats
