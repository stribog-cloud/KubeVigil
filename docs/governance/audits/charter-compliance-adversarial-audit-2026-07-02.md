---
title: "Charter Compliance — Independent Adversarial Audit 2026-07-02"
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
type: project/audit
status: governing-reference
tags: [audit, charter, kubevigil, red-team, adversarial]
project: kubevigil
version: "1.0.0"
revision: 1
owners: [maintainers (@msambare)]
parent_moc: "[[MOC - KubeVigil Governance]]"
---

# Charter Compliance — Independent Adversarial Audit — 2026-07-02

## Verdict

**FAIL — not full Stribog Charter compliance, in letter or spirit.**

The engineering substrate of branch `charter-compliance` is genuinely solid: code
builds and vets clean, 24 test packages pass (including `-race`), coverage is a real
96.4% on the declared scope, and the standard Go quality gates (lint, gitleaks,
govulncheck) all pass. That part is not theater.

The Charter-compliance layer bolted on top of it largely **is** theater. It describes
compliance more than it achieves it: doc "gates" that cannot fail on the regressions
they claim to catch, a public-surface reference that documents API names which do not
exist, an ADR that claims credit for security hardening never performed on this branch,
a threat model and waiver register that omit a known code-documented residual risk, and
a self-signed "Pass" closeout with no captured evidence and no independent critique pass.

This branch should **not** be certified as meeting the Charter until the findings below
are remediated.

## Method

Independent adversarial red-team. Seven subagents (five launched + two spawned children)
each owned a domain — governance, documentation, security & privacy, delivery/testing,
and independent build-reality — with instructions to *disprove* the compliance claim, not
confirm it. The synthesizing reviewer (Opus main thread) then adversarially reconciled
the agents against each other and against the source of truth (the Stribog Charter,
cloned from `github.com/stribog-cloud/charters`, and the actual KubeVigil source), and
dropped findings that did not survive verification (see "Corrected / false alarms").

Two "build-reality" agents ran every gate and reported exit 0 across the board — and were
**wrong** about enforcement: they mistook "the gate runs and passes" for "the gate
enforces its stated property." Direct reading of the gate scripts + mutation testing by
the documentation agent proved the gates pass on deliberately broken input. This
disagreement is itself the headline: the branch's gates are green because they cannot go
red, not because the underlying property holds.

## What is actually real (verified, independently reproduced)

- `go build ./...`, `go vet ./...`, `gofmt -l .` — all clean.
- `go test ./...` — 24/24 packages `ok`; `make test` with `-race` — 22/22 `ok`. Zero
  failures, panics, or skips.
- `make coverage` — **96.4%** on `internal/`+`cmd/`; floor genuinely enforced in the
  Makefile (`awk … exit 1`). Whole-repo figure 95.5% (includes `test/helpers`). The
  headline number is real, not fabricated.
- `golangci-lint` — 0 issues. `gitleaks` — no leaks. `govulncheck` — no vulnerabilities.
- `go.mod`/`go.sum` — tidy and verified. Dependency changes are version bumps only; no
  new modules, no downgrades to known-vulnerable versions.

## Findings (ranked; severity then cross-agent confirmation)

Severity → beads priority mapping: CRITICAL = P0, HIGH = P1, MEDIUM = P2, LOW = P3.

### CRITICAL

**F1 — ADR-003 "MCP path hardening" is fabricated; a live residual file-read risk is left undisclosed.**
`git diff main..charter-compliance -- internal/mcp/` changes only a test file — zero
production hardening was added on this branch. ADR-003 (`docs/governance/adr/003-mcp-path-hardening.md`,
"Accepted (implemented v0.5.0)") credits pre-existing v0.5.0 code as if it were this
work. Meanwhile `internal/mcp/tools_scan.go:261-264` self-documents that `scan_manifests`
/`fix` do **not** restrict scan paths ("Path restriction is deferred to a future phase"),
giving an MCP client an arbitrary absolute-path file-read primitive scoped to the OS
user's own permissions (a real data-egress path under prompt-injection). The branch
neither hardens this nor discloses it via a waiver or a threat-model entry — it papers
over it while claiming to have fixed it.
*Charter:* Security-Posture §3.2 (SAR must address the change's security implications),
§6.2 (risk acceptance recorded in the waiver register), §12 ("governance theater").
*Remediation:* Either implement real path confinement (root-jail / allowlist / reject
`..` after clean, relative to a workspace boundary) **or** correct ADR-003 to stop
claiming this branch hardened anything and file a scoped waiver with a compensating
control and target phase. Add the corresponding STRIDE row (see F8).

**F2 — All four documentation "gates" are non-enforcing; proven by mutation.**
`scripts/doc-drift-gate.sh` greps `docs/dev/public-surface.md` for hardcoded substrings
and never reads Go source — a doc-greps-doc tautology that cannot detect drift by
construction. Worse, it checks **phantom** MCP tool names (`kubevigil_scan`,
`kubevigil_get_findings`, `kubevigil_get_summary`, line 14) that do not exist; the real
registered names in `internal/mcp/server.go` are `scan_cluster`, `scan_manifests`,
`get_findings`, `get_summary`, `list_checks`, `get_remediation`. Mutation tests
confirmed: `doc-gate.sh` passes with a fabricated CHANGELOG version; `doc-drift-gate.sh`
passes with the required substrings hidden inside a URL fragment and a joke sentence;
`doc-samples-test.sh` exercises only `version`/`list`/`scan` and never the `fix`
subcommand or any documented flag; `doc-a11y.sh` has dead code and only catches literally
empty `![]()`.
*Charter:* Universal Charter §5.9 (drift gate + doc-to-release gate are binding);
Developer-Documentation §4.4 (drift gate must verify every documented surface exists in
source; names the "phantom endpoint" anti-pattern).
*Remediation:* Make `doc-drift-gate.sh` derive the tool/command lists from source
(`internal/mcp/server.go`, the cobra command tree) and diff against the doc; fix the
phantom names in `public-surface.md`; extend `doc-samples-test.sh` to cover `fix` + flags;
replace/remove the dead code in `doc-a11y.sh`.

**F3 — Invalid `status: reference` frontmatter in 100% of new docs.**
`docs/dev/architecture.md`, `bootstrap.md`, `deprecations.md`, `public-surface.md`,
`docs/user/support.md`, `docs/user/releases/README.md` all use `status: reference` — a
value not in the fixed Stribog vocabulary
(`draft-scaffold|review-draft|design-reference|governing-reference|frozen-reference|superseded|archived`).
*Charter:* Documentation Standard §10.1 ("Projects may not invent additional statuses").
*Remediation:* Set each doc to a valid status matching its grade.

### HIGH

**F4 — Self-certified "Pass" with no captured evidence and no independent critique pass.**
The closeout asserts "96.4%" with no `make coverage`/`go test` transcript, run IDs, or CI
link. No Critique-Persona artifact exists despite the Charter mandating one for
charter-touching work. Signoff is the same party that authored the change.
*Charter:* AI-Agent-Execution §4.2 ("'tests pass' is not evidence"), §10.4 (mandatory
critique pass), §11 (distinct hats). *Remediation:* Attach real command evidence; record
an independent critique pass; add a dated reviewer signoff distinct from the author.

**F5 — Fabricated review dates.** Every pinned-document row in `Charter-Compliance-Annex.md`
§0 is stamped `2026-07-02` (audit date); the actual `last_updated` of the pinned Charter
docs is `2026-05-12`. *Charter:* AI-Agent-Execution §4.4 (no confabulated evidence);
Charter-Governance §5.2. *Remediation:* Record each document's real last-reviewed date.

**F6 — Coverage-floor conflict unreconciled.** New docs + Makefile assert a 96% floor;
the repo's own `CLAUDE.md` states 94.0% twice. Two contradictory governing floors.
*Charter:* Charter-Governance §12 (no silent obsolescence). *Remediation:* Pick one
floor, update all governing docs, and sunset the stale one explicitly.

**F7 — Waiver register empty and Data-Privacy declared "N/A" while a known residual risk
exists.** `WAIVER-REGISTER.md` ("No active waivers") and the Annex Data-Privacy "N/A —
no PII" declaration coexist with the F1 arbitrary-read path, which is a live PII/data
egress vector via the MCP channel. *Charter:* Security-Posture §6.2 ("'we'll look at it
later' is not a triage outcome"). *Remediation:* File the F1 waiver; re-evaluate the
Data-Privacy applicability in light of the MCP read surface.

**F8 — Threat model omits the MCP data-egress attack surface.** `threat-model.md` STRIDE
Information-Disclosure row covers only the CLI's on-disk `scan-results/` output, not the
MCP server returning `CurrentValue` for a caller-controlled path. The recent main-branch
"PII/secrets leak prevention layers" work is not referenced or reconciled. *Charter:*
Security-Posture §2.1. *Remediation:* Add the MCP egress STRIDE row + controls; add a
maintenance-trigger entry for the PII-layer work.

**F9 — Vacuous coverage-padding tests.** `internal/checker/cloud/metadata_test.go` and
`internal/checker/cluster/metadata_test.go` assert only `NotEmpty` on metadata methods,
never call `.Run()`, and duplicate the per-checker tests that already exist — they cannot
fail on any real logic regression. Built to fill the self-narrowed coverage boundary
(see F19). *Charter:* AI-Agent-Execution §3.4 (no vacuous tests). *Remediation:* Delete
or replace with behavioral assertions.

**F10 — Revision-History section missing from every governing/reference doc** (including
the closeout). *Charter:* Documentation Standard §12 (required for every governing or
reference-grade document). *Remediation:* Add a Revision History table to each.

**F11 — Mandated artifacts never filed.** No Project Applicability Matrix (only an inline
Annex table) and no Release Evidence artifact despite v0.5.0 already being tagged/shipped.
*Charter:* Charter-Governance §2.2; Release-Evidence template (Universal §7.4).
*Remediation:* File both from the templates; if Release Evidence is genuinely deferred,
waive it explicitly.

**F12 — Documented commands are broken.** `docs/dev/architecture.md` shows
`go test ./test/integration/ -run TestCheckerContract`, which matches nothing (real:
`TestAllCheckersContract`) and exits 0 with "no tests to run" — false green for a
contributor. The samples gate does not execute it. *Charter:* Developer-Documentation §5
(code samples must be tested). *Remediation:* Fix the command; have `doc-samples-test.sh`
exercise it.

### MEDIUM

**F13 — BUILD-PLAN overclaim.** `BUILD-PLAN.md` marks "`make all` enforces … full gate
set" done; `all: format lint vet test coverage secrets vuln build smoke` contains none of
the four doc gates (CI-only). *Remediation:* Add doc gates to `make all` or correct the
claim.

**F14 — `doc-a11y.sh` effectively inert.** Dead `while … < /dev/null` loop (lines 16-20);
the one live check only catches literally-empty `![]()`; zero images exist in `docs/`; and
it depends on `rg`, which the CI `doc-gates` job never installs — if `rg` is absent the
`if` short-circuits to success (fails open). *Remediation:* Rewrite to a real, portable
alt-text check; install its dependency in CI or drop the `rg` dependency.

**F15 — `//nolint:gosec` framed as hardening.** `internal/engine/manifest_parser.go:90`
and `internal/mcp/tools_scan.go:294` add `//nolint:gosec` (the entire functional change
to `manifest_parser.go`), suppressing G304 rather than fixing or waiving the path concern,
while the ADR/CHANGELOG narrative frames annotation as a security fix. *Remediation:*
Justify each suppression against the real finding or remove it and address G304.

**F16 — ADRs miss mandatory template fields.** None of ADR-001/002/003 have `adr_status`,
"Alternatives Considered" (incl. do-nothing), "Forces", "Verification", or "Revision
History"; `status: accepted` is itself an invalid document-grade status. *Remediation:*
Bring all three ADRs to the ADR template shape.

**F17 — Closeout missing mandatory sections + placeholder.** No scoped criteria table
with per-item Pass/Partial/Fail, no findings section, no validation-performed section, no
dated reviewer signoff; contains a literal unresolved cross-ref "Public release profile —
Declared in Annex **§X**". *Remediation:* Rebuild from the Audit-Closeout template.

**F18 — Diátaxis not implemented.** No tutorial or explanation content in the new docs;
`bootstrap.md` is a tutorial (single named path to a verifiable end state) mislabeled
`reference`. *Charter:* Documentation Diátaxis model. *Remediation:* Add the missing
quadrants or stop claiming full Diátaxis coverage; retype `bootstrap.md`.

**F19 — Coverage boundary narrowed to `internal/`+`cmd/`.** `COVER_PKGS` excludes `test/`
(disclosed in the Annex, but drawn to make the number achievable and paired with the F9
duplicate tests). *Charter:* Testing-Strategy §5.4 (exclusion is a governance change, not
a number-flatterer). *Remediation:* Justify the exclusion on principle or restore
whole-module measurement.

**F20 — CI hygiene.** The coverage gate was relocated inline-YAML → Makefile with no
disclosure; `ci.yml` sets no least-privilege `permissions:` block; third-party actions
are pinned to mutable tags (`@v4`, `@v5`, `@v7`) rather than SHAs. *Remediation:* Document
the relocation as a governed change; add `permissions:`; pin actions to SHAs.

**F21 — `doc-samples-test.sh` coverage gap.** Exercises only `version`/`list`/`scan`;
never the entire `fix` subcommand or its documented flags. *Remediation:* Extend the gate.

### LOW

**F22 — Rendered-diagram path claimed but absent.** Annex §2.2 states
`docs/governance/diagrams/rendered/` (SVG) as fact; only the `.d2` source exists, and the
closeout lists rendering as a residual item — the two artifacts contradict.
*Remediation:* Render the diagrams or mark the path as pending in the Annex.

**F23 — Flaky coverage gate.** `make coverage` intermittently crashes with
`cover: bufio.Scanner: token too long`, yielding an empty percentage that then fails the
floor check; passes on retry. *Remediation:* Fix the coverage pipeline's line-length
handling so the gate is deterministic.

**F24 — Backup posture unexamined.** The `backup.go` change is a no-op `nolint` comment;
the threat model claims backup-path EoP "fully mitigated" without noting backups inherit
ambient file permissions and use predictable `<path>.kubevigil-backup-<ts>` names.
*Remediation:* Note the residual in the threat model or tighten backup perms.

**F25 — Frontmatter fields missing.** All six new docs omit ~6 of 11 required frontmatter
fields (`updated`, `tags`, `version`, `revision`, `parent_moc`, `owners`).
*Remediation:* Complete the frontmatter contract.

## Corrected / false alarms (dropped after verification)

- **CODEOWNERS "missing" — FALSE.** The file exists at `.github/CODEOWNERS` (48 bytes,
  `@msambare`). One agent checked only the repo root; corrected.
- **"CI coverage gate removed/weakened" — FALSE (as a break).** Enforcement moved from an
  inline `bc` check into the Makefile's `awk … exit 1`; the CI job still fails below the
  floor. The undisclosed *relocation* remains a MEDIUM governance point (F20), not a
  broken gate.
- **"Closeout claims a 94% floor" — misframing.** The closeout claims 96%/96.4% and is
  internally self-consistent; the 94% lives only in the stale `CLAUDE.md` (the real
  conflict, F6).
- **Coverage 96.4% is real**, reproduced by three independent agents; not fabricated.
- **Standard Go gates genuinely pass** (build/vet/fmt/test/lint/secrets/vuln). Not theater.

## Prioritized remediation backlog

| ID | Severity | Theme | Effort |
|----|----------|-------|--------|
| F1 | CRITICAL | Withdraw/correct ADR-003; implement path confinement OR file waiver + STRIDE | M–L |
| F2 | CRITICAL | Make doc gates source-derived + fix phantom tool names | M |
| F3 | CRITICAL | Fix invalid `status` vocabulary in all new docs | S |
| F4 | HIGH | Real evidence + independent critique pass + dated signoff | S–M |
| F5 | HIGH | Correct fabricated pin dates | S |
| F6 | HIGH | Reconcile 94/96 coverage floor across all governing docs | S |
| F7 | HIGH | File F1 waiver; re-evaluate Data-Privacy N/A | S |
| F8 | HIGH | Add MCP data-egress STRIDE row + PII-layer reconciliation | S |
| F9 | HIGH | Delete/replace vacuous metadata tests | S |
| F10 | HIGH | Add Revision History to every governing/reference doc | S |
| F11 | HIGH | File Applicability Matrix + Release Evidence (or waive) | M |
| F12 | HIGH | Fix broken documented test command | S |
| F13–F21 | MEDIUM | BUILD-PLAN claim, a11y gate, nolint framing, ADR fields, closeout shape, Diátaxis, coverage boundary, CI hygiene, samples coverage | M (aggregate) |
| F22–F25 | LOW | Rendered diagrams, flaky coverage, backup posture, frontmatter | S (aggregate) |

## Bottom line

Real code, real tests, real standard gates — wrapped in a compliance narrative that fails
the Charter's **letter** (invalid status vocabulary, missing required sections and
artifacts, a phantom-endpoint API doc, gates that cannot fail) and its **spirit**
(self-certified with no critique pass, fabricated dates, a waiver register kept empty to
protect a "Pass," and a security ADR taking credit for work not done). Remediate F1–F12
before re-asserting Charter compliance.

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers (@msambare), independent adversarial audit | Initial audit — 25 findings, ranked; 4 prior-agent claims corrected as false alarms. |
