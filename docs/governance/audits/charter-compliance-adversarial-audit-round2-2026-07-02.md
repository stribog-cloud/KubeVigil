---
title: "Charter Compliance — Independent Adversarial Re-Audit (Round 2) 2026-07-02"
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
type: project/audit
status: governing-reference
tags: [audit, charter, kubevigil, red-team, adversarial, round-2]
project: kubevigil
version: "2.0.0"
revision: 1
owners: [maintainers (@msambare)]
parent_moc: "[[MOC - KubeVigil Governance]]"
---

# Charter Compliance — Independent Adversarial Re-Audit (Round 2) — 2026-07-02

## Verdict

**Materially better than round 1 — most findings genuinely fixed — but the compliance
claim still does not hold.**

Round 1 was theater. Round 2 (remediation commit `fa39059`, +3759/−156 across 68 files) is
real engineering: actual path-confinement code with red-first tests, a source-derived doc
drift gate that mutation-tests clean, real review dates pulled from source front matter,
genuine governance artifacts, and verified CI hardening. Credit is due.

But it over-reached its own "full compliance" claim. Five round-1 findings remain open, the
remediation self-certified again with no independent review, and it introduced **new**
defects — including a HIGH security regression (a TOCTOU race that re-opens the arbitrary
file read) and, most concretely, **a branch that fails its own gate at HEAD**: `doc-a11y`
is red on the committed tree, so `make all` and the CI `doc-gates` job fail on the very
commit whose closeout claims "Pass."

Do not certify. Close the items below first.

## Method

Second independent adversarial red-team, completely fresh slate — five domain auditors
(governance, documentation, security & privacy, delivery/testing, build-reality) instructed
to verify each round-1 closure adversarially (CLOSED / STILL-OPEN / REGRESSED) and to hunt
new defects in the remediation. This round mandated **mutation testing** (prove each gate
can now go *red*, not merely that it is green) and a **live re-run of the F1 file-read PoC**,
because exit-0 observation is exactly what fooled round 1.

Process note (for evidence integrity): 2 of the 5 launched auditors "flaked" — they spawned
child agents and returned without running anything (the round-1 failure mode). Those two
domains (docs-mutation, build-reality) were executed directly by the synthesizing reviewer.
Nested flaked children transiently mutated the shared worktree; this was detected and
cleaned (final `git status` clean). Two claims were **retracted on verification** (see
"Dropped / false alarms").

## Round-1 findings — verification verdicts

**Closed (verified genuinely fixed): F1(core), F2, F3, F7, F8, F10, F11, F12, F13, F14,
F15, F16, F17, F18, F19, F20, F22, F24.** Highlights:
- **F1 core** — real `internal/pathguard` (`ResolveWithinRoot`/`AssertWithinRoot`),
  `--workspace-root` flag + `KUBEVIGIL_WORKSPACE_ROOT` env, wired into MCP + engine. Live
  PoC confirmed absolute / `..` / static-symlink / unicode paths **rejected**. ADR-003
  honestly rewritten. *Caveat: TOCTOU regression, see R1.*
- **F2** — `doc-drift-gate.sh` derives tool names from `internal/mcp/server.go` and CLI
  commands from the cobra tree; `public-surface.md` matches the 6 real tools. Mutation
  proven **bidirectional**: injected phantom tool → red; dropped real tool → red; phantom
  CLI command → red; wrong checker count → red.
- **F3** — status-vocabulary gate enforces (inject `status: reference` → red).
- **F11** — Applicability Matrix + Release Evidence filed; release SHA-256 verified against
  the actual `gh release view v0.5.0`.
- **F14** — a11y gate quality fixed (dead code removed, `rg` fail-open removed, catches
  empty *and* whitespace alt; no-rg-in-PATH → still red). *But the gate is now red at HEAD,
  see R2.*
- **F20** — CI hardened: least-privilege `permissions:`, third-party actions SHA-pinned
  (checkout SHA verified to resolve to v4), relocation disclosed.

**Still open:**
- **F4** — self-certified. Audit (`5fc9fb9`) and remediation (`fa39059`) are the **same git
  identity**; no independent Critique-Persona artifact exists. Distinct-hats is asserted,
  not demonstrated. *(AI-Agent-Execution §10.4, §11.)*
- **F5** — the Data-Privacy pin row rewritten to fix F5 still reads "revision 2"; the source
  `Stribog-Data-and-Privacy-Standard.md` is `revision: 5`. A stale fact inside the fixed row.
- **F6** — the tracked/public branch is uniformly 96%, but the session-loaded (gitignored)
  `CLAUDE.md` still says "Coverage floor: 94.0%" (lines 175, 271). Internal inconsistency.
- **F9** — not fixed. `internal/checker/cluster/checker_contract_test.go` is still
  reflection-only (asserts metadata, never calls `.Run()`, never inspects a Finding);
  `internal/checker/cloud/metadata_test.go` was **deleted with no replacement** (R5).
- **F21** — partial. `doc-samples-test.sh` now runs `fix` dry-run, but exercises **no
  documented flag**; renaming `--risk-level` in the CLI reference → gate stays green.
- **F25** — narrower gap: the 6 dev/user docs now carry most fields but use `updated:` not
  the Charter-mandated `last_updated:`, and omit `aliases:`.
- **F23** — not re-verified. The round-1 flaky `make coverage` crash was not observed this
  round, but coverage sits at 96.0% vs a 96% floor (zero headroom), so a determinism fix is
  still warranted.

## New defects introduced/surfaced by the remediation

**R1 [HIGH] TOCTOU race re-opens the arbitrary file read.** Confinement validates via
`Lstat`, but the read is `os.ReadFile(path)` after `os.Stat` (which *follows* symlinks) with
no held file descriptor / `O_NOFOLLOW` (`internal/engine/manifest_parser.go:41,69,169`;
`internal/pathguard` returns a path string, not an fd). A symlink swapped into the workspace
root between validate and read is followed → arbitrary file read returns over the MCP
channel. Reproduced in a scratch PoC (deleted; tree clean). Confinement holds only against a
non-racing attacker. *Fix:* read via an already-validated open fd (`O_NOFOLLOW` /
`openat2(RESOLVE_NO_SYMLINKS)`), not by re-resolving the path string at each layer.
*Charter:* Security-Posture §2.1/§3.2.

**R2 [HIGH] The branch fails its own gate at HEAD.** `doc-a11y` is **red** on the committed
tree because `docs/governance/audits/charter-compliance-closeout-2026-07-02.md:124` embeds a
literal `![](bad.png)` in a table cell documenting the a11y mutation test. `.github/workflows/ci.yml`
and `make all` both run `doc-a11y`, so CI fails on this exact commit while the closeout
claims "Pass" — the "Pass" evidence (a `make all` exit-0 log) predates this line and is not
reproducible on HEAD. Independently confirmed by three auditors; `make all` exits 2 on a
clean checkout of `fa39059`. *Fix:* make the a11y regex markdown-aware (ignore inline-code/table
examples) or escape the example; then re-run and capture real evidence. *Charter:* Universal
§5.9; AI-Agent-Execution §4.2 (reproducible evidence).

**R3 [HIGH] Same-commit governing contradiction on Data-Privacy applicability.**
`docs/governance/Project-Applicability-Matrix.md:37` marks the Data-Privacy Standard
`not applicable`; `docs/governance/Charter-Compliance-Annex.md:31,58` (same commit) marks it
`Partial`. Two "single source of truth" docs answer the same question oppositely, neither
cross-referencing the other; the Annex cites "threat model §5" for the Partial rationale but
the threat model contains no Data-Privacy mention. *Charter:* Charter-Governance
(single-source-of-truth). *Fix:* reconcile to one answer (Partial is the honest one given
R1).

**R4 [MEDIUM] `doc-gate.sh` version check is doc-vs-doc, not vs authoritative source.** It
regex-matches the version across CHANGELOG.md and `docs/user/releases/README.md` against
*each other*, never against `git tag` / `internal/version`. A mutation setting both docs
consistently to a fabricated `0.5.99` (real tag `v0.5.0`) passes. A real version drift would
go undetected. *(Its status-vocabulary check is genuinely real; only the version check is
theater.)*

**R5 [MEDIUM] F9 fixed by subtraction — `cloud` package lost its dedicated test.**
`internal/checker/cloud/metadata_test.go` was deleted with no behavioral replacement; the
package now relies solely on the pre-existing generic contract test and per-checker files
(untouched). Net regression in the one package cited by name in F9.

**R6 [MEDIUM] `doc-gate.sh` status-vocabulary check skips `docs/governance/**`.** It iterates
only `docs/dev/*.md` and `docs/user/*.md` — a blind spot over the highest-stakes
(governing-reference) doc class. No live defect today (they all use a valid value), but the
gate can't catch a future violation there.

**R7 [MEDIUM] Same-commit factual drift on when the MCP fix shipped.**
`docs/governance/MASTER-REFERENCE.md:120` still reads "MCP path injection … Mitigated
v0.5.0," contradicting the rewritten ADR-003 (which explicitly disclaims v0.5.0 credit) and
the closeout. A security-relevant "when fixed" claim inconsistent across governing docs.

**R8 [MEDIUM] Soft phantom documentation reference.**
`docs/user/explanation-why-manifest-scan.md` points readers to `docs/mcp-setup.md` for the
workspace-root control, but `mcp-setup.md` does not document `--workspace-root` /
`KUBEVIGIL_WORKSPACE_ROOT` at all. The target exists but lacks the promised content — a
phantom-reference variant introduced this round.

**R9 [LOW] `Makefile:64` lists the four doc gates twice** in the `all:` prerequisites
(copy-paste). Harmless (Make de-dupes) but sloppy in a governance-critical file.

**R10 [LOW] Default MCP workspace root is the process cwd when unset.**
`pathguard.DefaultWorkspaceRoot()` falls back to `os.Getwd()`; if `kubevigil mcp-server` is
launched from `$HOME` or `/` (plausible IDE/agent default), the confinement boundary is the
whole home dir / filesystem. Config/deployment-guidance gap — docs should require an explicit
narrow root.

**R11 [LOW] Pre-existing broken relative link** — `docs/STYLE-GUIDE.md:41`
(`../scanning/output-formats.md` resolves outside the repo). Introduced in Phase 3, predates
this remediation; noted for completeness, not attributed to the F1–F25 work.

**R12 [MEDIUM] Path confinement is MCP-only; the CLI `scan`/`fix` path is unconfined.**
`internal/engine/scanner.go` exposes `ScanManifestWithinRoot` (confined, used only by MCP's
`handleScanManifests`) and `ScanManifest` (unconfined, used by `cmd/kubevigil/scan.go` and
`internal/fix/fixer.go`). Live test: `cd / && kubevigil scan -f /tmp/<outside-workspace>.yaml`
returned a full report with no block; `kubevigil fix` on the same file analyzed it. This is
largely **by design** — the CLI path is operator-supplied and the code's own G304 `nolint`
justification marks it "operator-trusted"; the actual trust boundary (an untrusted MCP
caller) *is* confined. The defect is one of **scope accuracy, not a fresh vuln**: ADR-003,
the threat model, and the closeout speak of "path confinement" without stating it applies to
the MCP surface only and that the CLI is intentionally operator-trusted. A reader reasonably
infers CLI confinement that does not exist. *Fix:* state the MCP-only scope explicitly in
ADR-003 + threat model (or, for defense-in-depth, offer an opt-in `--workspace-root` on the
CLI too). *Charter:* Security-Posture §2.1 (attack-surface/scope clarity).

## Dropped / false alarms (red-teaming the red team)

- **"doc-drift-gate is one-directional"** (reviewer's own first-pass result) — **retracted.**
  The phantom row had been appended at EOF, outside the parsed MCP table; a correctly-placed
  in-table phantom makes the gate go red. The gate is bidirectional.
- **"a gate regenerates `docs/reference/cli-reference.md`"** (delivery auditor) — **dropped.**
  Concurrency contamination from a flaked child agent; in isolation the gates leave the tree
  clean (read-only).
- **`server.go` compile errors** (editor diagnostics) — **dropped.** gopls analyzing the
  worktree file without a `go.work`; `go build ./...` and `go vet ./...` are clean, handlers
  are defined in `tools_scan.go`/`tools_findings.go`.

## Prioritized backlog (round 2)

| ID | Sev | Item |
|----|-----|------|
| R1 | HIGH | Fix TOCTOU: read via validated fd / `O_NOFOLLOW`, not path re-resolution |
| R2 | HIGH | Unbreak `doc-a11y` at HEAD (markdown-aware regex or escape the example); re-capture evidence |
| R3 | HIGH | Reconcile Data-Privacy applicability (Matrix vs Annex) to one answer |
| F4 | HIGH | Genuine independent critique pass + reviewer distinct from author |
| F9/R5 | MED | Give cloud/cluster checkers real behavioral tests (call `.Run()`), restore deleted coverage |
| R4 | MED | `doc-gate` version check against `git tag`/`internal/version`, not doc-vs-doc |
| R6 | MED | Extend status-vocab gate to `docs/governance/**` |
| R7 | MED | Fix MASTER-REFERENCE "Mitigated v0.5.0" vs ADR-003 |
| R8 | MED | Document `--workspace-root` in `mcp-setup.md` or fix the cross-ref |
| R12 | MED | State MCP-only confinement scope in ADR-003/threat model (CLI is operator-trusted by design) |
| F5 | MED | Correct Data-Privacy pin revision (2 → 5) |
| F6 | MED | Reconcile the gitignored `CLAUDE.md` 94% floor |
| F21 | MED | Exercise documented `fix` flags in `doc-samples-test.sh` |
| F25 | LOW | `last_updated:`/`aliases:` on the 6 dev/user docs |
| R9/R10/R11/F23 | LOW | Makefile dedup; default-root guidance; STYLE-GUIDE link; coverage determinism |

## Bottom line

Round 1 was paper; round 2 is real work that oversold its own completion. The blockers now
are concrete and few: a HIGH TOCTOU that re-enables the arbitrary read under a race, a branch
that is red on its own CI at HEAD, a same-commit governing contradiction, still-vacuous
checker tests, and still no independent review. Close R1–R3, F4, and F9, and the Charter
claim becomes defensible.

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers (@msambare), independent adversarial re-audit | Round-2 re-audit of remediation `fa39059`: 18 of 25 findings verified closed, 7 still open, 11 new defects (R1–R11); 3 prior-pass claims retracted after verification. |
