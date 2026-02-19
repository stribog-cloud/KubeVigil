# PROMPT — Report Format Audit: Usability, Structure & Parity

> **Role:** You are a report quality engineer. The HTML report is the gold standard — the user has refined it to their satisfaction. Your job is to audit the other 7 report formats (Text, JSON, YAML, Markdown, CSV, SARIF, JUnit) for gaps in usability, actionability, and structure, then fix every gap you find. No changes to the HTML report.

---

## Pre-Flight

**Read these files first:**

- `CLAUDE.md` — Project identity, architecture overview
- `AGENTS.md` — Tasks workflow, session completion rules
- `internal/report/reporter.go` — Shared infrastructure (sortFindings, formatFrameworks, severityEmoji)
- `internal/report/summary.go` — ExecutiveSummary, ComputeSummary (the shared data available to all reporters)
- `internal/report/aggregate.go` — AggregatedFinding (grouping infrastructure)

**Then read every reporter file:**

```bash
cat internal/report/text.go
cat internal/report/json.go
cat internal/report/yaml.go
cat internal/report/markdown.go
cat internal/report/csv.go
cat internal/report/sarif.go
cat internal/report/junit.go
```

**Skim the HTML reporter to understand the gold standard's data model:**

```bash
head -400 internal/report/html.go   # data structures and Generate()
```

**Read all existing tests:**

```bash
cat internal/report/text_test.go
cat internal/report/json_test.go
cat internal/report/yaml_test.go
cat internal/report/markdown_test.go
cat internal/report/csv_test.go
cat internal/report/sarif_test.go
cat internal/report/junit_test.go
cat internal/report/contract_test.go
cat internal/report/golden_test.go
```

**Verify baseline:**

```bash
go test ./internal/report/... -count=1
go test ./... -count=1
```

**Ground rules:**

- **File Tasks issues before starting work.** One issue per format.
- **TDD.** Write or update tests FIRST, then implement. Every change must have a corresponding test.
- **Coverage must not drop.** Must remain ≥ 93.8%.
- **Do NOT modify html.go or html_remediation.go.** The HTML report is done.
- **Do NOT modify checker.go or any checker files.** Report formats consume existing data — they don't change what's collected.
- **Follow AGENTS.md** for session completion (commit, push, verify CI).

---

## Known Gaps by Format

Use this as your audit checklist. Verify each gap exists before filing issues. Some may have been addressed since this prompt was written.

### 1. Text Report (`text.go`, 176 lines)

**Gaps:**

- **No namespace classification.** Findings are flat — no App/Infra/Cluster grouping. The HTML report groups by tier; text should too, with section headers like `── Application Namespaces ──`, `── Infrastructure Namespaces ──`, `── Cluster-Scoped ──`.
- **No compliance summary.** No framework references in the summary. Add a "Compliance" section after findings showing framework control counts (e.g., "CIS v1.8: 12 controls violated · MITRE ATT&CK v14: 8 techniques · NSA/CISA v1.2: 5 controls").
- **No passed checks listing.** The executive summary says "X clean" but doesn't list which checks passed. Add a collapsible-equivalent: "N checks passed: check-a, check-b, ..." (on one line, or a compact list if > 10).
- **Redundant bottom summary.** The "Summary" section at line ~131 repeats severity counts already shown in the "Executive Summary" at line ~40. Remove the redundant block; keep only the executive summary.
- **No top risks.** `ComputeSummary` provides `TopRisks` (top 5 most severe findings). Add a "Top Risks" section between executive summary and findings.

**Tasks issue:** `report-text-parity` (type: `chore`, priority: P2)

### 2. JSON Report (`json.go`, 124 lines)

**Gaps:**

- **No check_aggregates.** Consumers must group findings themselves. Add `check_aggregates` array to the JSON output (mirrors `ExecutiveSummary.CheckAggregates`). Each entry: `{checker, severity, count, resources, namespaces}`.
- **No passed_checks.** Add `passed_checks` string array to summary.
- **No top_risks.** Add `top_risks` array (top 5 findings from `ComputeSummary`).
- **No namespace tier breakdown.** Add `tier_breakdown` object: `{app: {count, critical, high, ...}, infra: {...}, cluster: {...}}` using `AppStats`, `InfraStats`, `ClusterScopedCounts` from `ExecutiveSummary`.
- **No posture scores per tier.** Add `app_posture_score` and `infra_posture_score` alongside existing `posture_score`.

**Tasks issue:** `report-json-parity` (type: `chore`, priority: P2)

### 3. YAML Report (`yaml.go`, 108 lines)

**Gaps:**

- **Missing check_coverage in summary.** JSON has `check_coverage` (TotalRun, WithFindings, Clean, Skipped, Errored) but YAML's `yamlSummary` omits it entirely. Add it.
- **All the same gaps as JSON.** No check_aggregates, no passed_checks, no top_risks, no tier breakdown, no per-tier posture scores.
- **YAML and JSON should have structural parity.** They are both machine-readable formats. A consumer switching between `-o json` and `-o yaml` should get the same data fields. After fixing, diff the struct fields — they should match 1:1.

**Tasks issue:** `report-yaml-parity` (type: `chore`, priority: P2)

### 4. Markdown Report (`markdown.go`, 415 lines)

**Gaps (minor — this format is already solid):**

- **No top risks section.** The HTML report has a "Top Risks" section highlighting the 5 worst findings. Add a "### Top Risks" section between the executive summary and the findings breakdown. Use `ComputeSummary.TopRisks`.
- **No per-tier posture scores.** The executive summary shows overall posture score but not App/Infra scores. Add them to the metrics table if > 0 (i.e., if there are app or infra findings).

**Tasks issue:** `report-markdown-parity` (type: `chore`, priority: P3)

### 5. CSV Report (`csv.go`, 72 lines)

**Gaps:**

- **No metadata header.** CSV consumers (Excel, Pandas, BigQuery) have no way to know which scan produced this file. Add a comment-style metadata header before the data rows:
  ```
  # KubeVigil Scan Report
  # Version: <tool_version>
  # Scan Mode: <mode>
  # Date: <timestamp>
  # Posture Score: <score>/100
  # Total Findings: <count>
  ```
  Use `#` prefix so CSV parsers that support comments can skip these, and parsers that don't will treat them as data (which is fine — the first real row has the column headers).
- **No Auto_Fixable column.** Each finding has a `FixHint` field. Add a boolean column `Auto_Fixable` (true/false) so users can filter in Excel for "what can be auto-fixed."
- **No CurrentValue / DesiredValue columns.** These exist on the Finding struct but aren't exported. Useful for spreadsheet analysis ("show me all findings where current_value is true").

**Tasks issue:** `report-csv-parity` (type: `chore`, priority: P2)

### 6. SARIF Report (`sarif.go`, 219 lines)

**Gaps:**

- **Rule shortDescription is just the checker name.** SARIF viewers (GitHub Security, VS Code) display this to users. It should be the checker's human-readable description, not its kebab-case ID. Use the checker's `Description()` — but since the report layer only receives `ScanResult` (not checker interfaces), pass descriptions via `ScanMeta` or a new field. **Alternative:** If the finding's `Message` is more descriptive, use that as `fullDescription` on the rule.
  - **Investigation needed:** Check if `ScanMeta` or `ScanResult` already carries checker descriptions. If not, assess whether the message field on findings is sufficient for rule descriptions. Do NOT modify the checker interface or engine — work with what the report layer already receives. If a proper description is not available, use the finding message as `fullDescription.text` on the rule (deduplicated per checker).
- **No remediation text on results.** SARIF spec supports `message.markdown` and the result can carry a `fixes` array. Add remediation as `relatedLocations` message or `message.markdown` on each result.
- **No help/helpUri on rules.** SARIF rules support `help.text` and `helpUri`. Set `helpUri` to the relevant doc page (e.g., `https://github.com/stribog-cloud/kubevigil/blob/master/docs/checks/<category>.md`). Set `help.text` to the remediation text (deduplicated per rule).
- **No fix information.** For auto-fixable findings (`FixHint != nil`), add a SARIF `fix` object. This enables GitHub's "Apply fix" button. **Stretch goal** — implement only if straightforward; SARIF fix objects require replacement text and regions.

**Tasks issue:** `report-sarif-parity` (type: `chore`, priority: P2)

### 7. JUnit Report (`junit.go`, 130 lines)

**Gaps:**

- **No passed test cases.** Clean checks are completely absent — CI dashboards show 0% pass rate. Every check that ran with zero findings should appear as a `<testcase>` WITHOUT a `<failure>` child, grouped in a "passed-checks" test suite. This makes CI dashboards show meaningful pass/fail ratios.
- **No timestamp.** The `<testsuites>` element should have a `timestamp` attribute (`result.ScanMeta.StartTime`). JUnit spec supports this and CI tools use it for trend analysis.
- **No time attributes.** Test suites and test cases should have `time` attributes. Use scan duration for the top-level suite, and omit or set to "0" for individual cases (we don't have per-check timing).
- **Suite name not descriptive.** Top-level `<testsuites>` should have `name="KubeVigil Security Scan"` for better CI dashboard display.

**Tasks issue:** `report-junit-parity` (type: `chore`, priority: P2)

---

## Shared Improvements

These apply across multiple formats:

1. **`ComputeSummary` already provides everything.** Check aggregates, passed checks, top risks, tier stats, posture scores — it's all computed. Most gaps exist because reporters simply don't use the data that's already available.

2. **`buildFrameworkGroups` is defined in html.go.** If other formats need framework grouping (Text compliance summary), either:
   - Extract it into `reporter.go` as a shared function, OR
   - Build a simpler compliance summary directly from findings (preferred — avoid coupling to HTML types)

3. **Format-specific tests.** Every change must have a corresponding test assertion. For structured formats (JSON, YAML, SARIF, JUnit), unmarshal the output and assert on specific fields. For text formats (Text, Markdown, CSV), assert on substring presence.

---

## Parallelization

| Agent | Format(s) | Est. Complexity |
|-------|-----------|-----------------|
| Agent 1 | Text | Medium — structural changes (tier grouping, compliance section, dedup) |
| Agent 2 | JSON + YAML | Medium — must achieve structural parity between the two |
| Agent 3 | CSV | Low — add metadata header and 3 columns |
| Agent 4 | SARIF | Medium-High — SARIF spec compliance, rule descriptions, help URIs |
| Agent 5 | JUnit | Medium — passed test cases, timestamp, time attributes |
| Agent 6 | Markdown | Low — add top risks section and tier scores |
| Agent 7 | Final verification + shared refactoring | Runs LAST after all others |

**Dependencies:**
- If Agent 1 (Text) needs `buildFrameworkGroups`, Agent 7 should refactor it to a shared location first — OR Agent 1 builds a simpler compliance summary independently.
- Agent 2 (JSON + YAML) should work on both simultaneously to ensure structural parity.
- All agents share `internal/report/` — be aware of merge conflicts in `reporter.go` if multiple agents add shared helpers.

---

## TDD Workflow (mandatory for each format)

For EVERY format change:

1. **Write the test first.** Add a test case that asserts the new behavior (e.g., "JSON output contains check_aggregates field"). This test MUST FAIL before implementation.
2. **Implement the fix.** Modify the reporter to make the test pass.
3. **Run `go test ./internal/report/... -count=1`** — verify the specific package passes.
4. **Run `go test ./... -count=1`** — verify nothing else broke.
5. **Check coverage:** `go test -coverprofile=/tmp/kv-report.out ./... && go tool cover -func=/tmp/kv-report.out | tail -1` — must be ≥ 93.8%.

**Golden test updates:** If `golden_test.go` uses snapshot files, update them after intentional output changes. Do NOT blindly regenerate — review each diff to ensure it matches the intended change.

---

## Final Verification

After all agents complete:

```bash
# 1. All tests pass
go test ./... -count=1

# 2. Linting clean
go vet ./...

# 3. Coverage not dropped
go test -coverprofile=/tmp/kv-final.out ./...
go tool cover -func=/tmp/kv-final.out | tail -1
# Must be ≥ 93.8%

# 4. No changes to HTML
git diff --name-only | grep -v html && echo "OK: HTML untouched"
# html.go and html_remediation.go must NOT appear in the diff

# 5. JSON/YAML structural parity
# Run a quick check: generate both formats from the same input, compare top-level keys

# 6. SARIF schema validation (if possible)
# Download SARIF schema and validate: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json

# 7. JUnit schema validation (if possible)
# Validate against JUnit XSD

# 8. Verify all Tasks issues are closed
```

---

## Completion Criteria

- [ ] **Text:** Namespace tier grouping, compliance summary, passed checks, top risks, no redundant summary
- [ ] **JSON:** check_aggregates, passed_checks, top_risks, tier_breakdown, per-tier posture scores
- [ ] **YAML:** Structural parity with JSON (same fields), including check_coverage
- [ ] **Markdown:** Top risks section, per-tier posture scores in summary table
- [ ] **CSV:** Metadata header, Auto_Fixable column, CurrentValue/DesiredValue columns
- [ ] **SARIF:** Descriptive rule text, remediation on results, help/helpUri on rules
- [ ] **JUnit:** Passed test cases, timestamp, time attributes, descriptive suite name
- [ ] All 7 Tasks issues filed and closed
- [ ] All tests pass (`go test ./...`)
- [ ] `go vet ./...` clean
- [ ] Coverage ≥ 93.8%
- [ ] HTML report unchanged
- [ ] Git committed and pushed per AGENTS.md
- [ ] CI passes

---

## Rules

- **File before fixing.** All 7 Tasks issues filed before any code changes.
- **TDD is mandatory.** Test first, implement second, verify third. No exceptions.
- **Do NOT touch html.go or html_remediation.go.** These files are done.
- **Do NOT modify checker code.** Work with the data the report layer already receives.
- **Verify after every format.** Run `go test ./internal/report/...` after each format change, full `go test ./...` after completing each format.
- **Coverage is a floor.** 93.8% must not drop.
- **JSON and YAML must be structurally identical.** If you add a field to JSON, add it to YAML. If they diverge, it's a bug.
- **SARIF must remain valid.** Every change must comply with the SARIF 2.1.0 spec. Do not invent custom fields outside of `properties`.
- **JUnit must remain valid XML.** Test by parsing the output with `encoding/xml`.
- **Be conservative with shared helpers.** If you refactor something into `reporter.go`, make sure all existing tests still pass. Prefer duplication over premature abstraction if unsure.
- **Context window management.** Each agent should work on its assigned format(s) independently. Do not load all format files simultaneously. Read only what you need for the current task.
