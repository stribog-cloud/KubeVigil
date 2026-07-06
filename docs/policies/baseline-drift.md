# Baseline & Drift Detection

A first scan of an existing cluster or a large manifest repository often surfaces hundreds of findings. Failing CI on all of them blocks every future change until the backlog is cleared -- which usually means the gate gets disabled instead. Baselines solve this by letting you gate on **new** findings only: accept what's already there, and fail only when a change introduces something that wasn't present before.

A baseline is a small, portable JSON file -- no database, no server -- containing the fingerprints of a scan's findings. A later scan can compare itself against that file and classify every finding as `new` or `existing`, plus report findings that no longer appear (`resolved`).

## The Save -> Scan -> Gate Workflow

1. **Save a baseline** once, from a scan you consider "current state, not our problem to block on today":

   ```bash
   kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml \
     --save-baseline baseline.json
   ```

   ```console
   Baseline written to baseline.json (24 findings)
   ```

   `--save-baseline <path>` writes the baseline and exits `0` -- it does not also print a report or apply the severity gate. Commit `baseline.json` to your repository (or store it as a CI artifact) so later runs can compare against it.

2. **On every subsequent scan**, compare against the committed baseline with `--baseline`:

   ```bash
   kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml \
     --baseline baseline.json
   ```

   Every finding is still shown, in every output format, exactly as normal -- baselining doesn't hide anything. It just annotates each finding and prints a one-line summary to stderr after the report:

   ```console
   Baseline drift: 0 new, 26 existing, 0 resolved
   ```

3. **Gate CI on new findings only** with `--fail-on-new`:

   ```bash
   kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml \
     --baseline baseline.json --fail-on-new
   ```

   This exits `1` only if at least one finding is `new` relative to the baseline -- pre-existing findings never fail the build, regardless of severity. `--fail-on-new` requires `--baseline`; using it alone is a configuration error (exit code `3`):

   ```console
   $ kubevigil scan -f manifests/ --fail-on-new
   ... (full report prints to stdout first) ...
   Config error: --fail-on-new requires --baseline
   (exit code 3)
   ```

4. **When you deliberately accept new findings** (e.g. after a security review decides a finding is acceptable, or after triaging a batch of new issues), refresh the baseline the same way you created it -- re-run with `--save-baseline` against the current state and commit the updated file.

### Example: catching a real regression

Starting from a baseline saved against a known-good manifest, adding `privileged: true` to a container produces:

```console
$ kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml --baseline baseline.json
...
Baseline drift: 2 new, 26 existing, 0 resolved
$ echo $?
0
$ kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml --baseline baseline.json --fail-on-new
...
Baseline drift: 2 new, 26 existing, 0 resolved
$ echo $?
1
```

Without `--fail-on-new`, the scan still exits based on `--fail-on` severity as usual (in this example, `0`, because nothing crossed the configured severity gate). `--fail-on-new` is a separate, stricter gate that looks only at drift.

Conversely, removing a `hostPath` volume and adding a missing label on the same manifest resolves those findings:

```console
Baseline drift: 0 new, 23 existing, 3 resolved
```

`resolved` is a count only -- the baseline file stores opaque fingerprints (see below), not human-readable finding details, so there is no built-in "show me what got fixed" report. To see *which* findings disappeared, diff the current scan's output against a previous full report (e.g. two JSON scans), rather than relying on the baseline file itself.

## Fingerprint Identity

Two findings are considered "the same problem" -- and therefore share a fingerprint -- when they match on:

```
Checker + Kind + Namespace + Resource + Container
```

(a SHA-256 hash of these five fields, joined by a null separator). Deliberately **excluded**: the finding's `Message`, `Severity`, and `FieldPath`. This means:

- Editing a finding's wording or changing a checker's severity via `checks.overrides` does not turn an existing finding into a "new" one.
- `FieldPath` is excluded specifically because array indices in a path (e.g. `spec.containers[1].securityContext`) can shift between otherwise-identical scans just from unrelated YAML reordering -- including it would produce false "new" findings on every reorder.
- A finding that isn't scoped to a single container (most checks outside the workload category, and all custom policy findings from this release) has an empty `Container` component -- fine, since the fingerprint still uniquely identifies "this checker, on this resource."
- Custom policy findings fingerprint identically to built-in ones -- a custom policy's `id` fills the `Checker` slot, so renaming a policy's `id` will make its findings look "new" even though the underlying condition didn't change.

The baseline file itself is a flat, de-duplicated, sorted list of fingerprint hashes:

```json
{
  "version": "v1",
  "tool_version": "v1.1.0",
  "fingerprints": [
    "0900d681b4fc6b9f7163c49a15bc42153671d884cc4a928cf5c18c26712996a2",
    "..."
  ]
}
```

(`created_at` exists in the schema for future use but the `scan` command does not currently stamp it, so it is omitted from the file.)

Note the fingerprint count in the file can be lower than the finding count reported by `--save-baseline` (e.g. "24 findings" saved from a 26-finding scan) -- some checks (Pod Security Standards baseline/restricted violations, in particular) can emit more than one finding for the same checker+resource+container, which collapse to a single fingerprint.

## Reading the Drift Summary

After a `--baseline` scan, KubeVigil prints exactly one line to stderr:

```
Baseline drift: <new> new, <existing> existing, <resolved> resolved
```

- **New** -- count of *findings in this scan* (not unique fingerprints) whose fingerprint is absent from the baseline.
- **Existing** -- count of findings in this scan whose fingerprint is present in the baseline.
- **Resolved** -- count of baseline fingerprints absent from this scan's findings.

Each finding also gets a `status` field (`"new"` or `"existing"`) in its serialized form. This is visible in the JSON and YAML output formats, since `Finding.Status` serializes with those struct tags; it is not currently surfaced as a column/badge in the text, Markdown, HTML, CSV, SARIF, or JUnit reports -- those formats show the same finding list they always do, with baselining affecting only the stderr summary and the exit code:

```bash
kubevigil scan -f manifests/ --baseline baseline.json -o json | jq '.scan_result.findings[] | select(.status == "new")'
```

## Baselines Interact With Filter Flags -- Keep Them Consistent

`--severity`, `--namespace`, `--exclude-namespace`, `--include-system-namespaces`, `--exclude-infra`, and `--framework` are all applied to the finding set **before** a baseline is either saved or compared. This means the baseline only ever sees the *filtered* findings from whichever run produced or compared it.

If the flags differ between the run that saved the baseline and a later comparison run, previously-filtered-out findings will look "new" even though nothing changed. For example, saving a baseline with `--severity high` (5 findings) and then comparing an unchanged manifest without that filter reports:

```console
$ kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml --severity high --save-baseline baseline-high.json
Baseline written to baseline-high.json (5 findings)

$ kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml --baseline baseline-high.json
Baseline drift: 21 new, 5 existing, 0 resolved
```

Those 21 "new" findings are not regressions -- they were simply never in the (severity-filtered) baseline to begin with. **Use the same filter flags (or the same `.kubevigil.yaml` `settings`) every time you save or compare a baseline**, ideally by running both through the identical CI job/script rather than by hand.

## CI Recipe: GitHub Actions

Gate a pull request on new findings only, while still uploading the full result for review:

```yaml
name: KubeVigil Drift Gate

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install KubeVigil
        run: go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest

      - name: Scan against committed baseline
        run: |
          kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml \
            --baseline baseline.json --fail-on-new -o results.sarif
        continue-on-error: true
        id: scan

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Fail on new findings
        if: steps.scan.outcome == 'failure'
        run: |
          echo "New findings relative to baseline.json -- see the SARIF results above."
          exit 1
```

To refresh `baseline.json` after intentionally accepting new findings, run the `--save-baseline` command locally (with the same flags used in CI) and commit the updated file in the same pull request.

## See Also

- [Custom Policies](custom-policies.md) -- custom policy findings baseline identically to built-in ones
- [Exit Codes](../reference/exit-codes.md) -- full exit code reference for `scan` and `fix`
- [CLI Reference](../reference/cli-reference.md) -- `--baseline`, `--save-baseline`, `--fail-on-new` flag details
