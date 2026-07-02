---
title: "Charter Compliance — Independent Adversarial Re-Audit (Round 3) 2026-07-02"
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
type: project/audit
status: governing-reference
tags: [audit, charter, kubevigil, red-team, adversarial, round-3]
project: kubevigil
version: "3.0.0"
revision: 1
owners: [maintainers (@msambare)]
parent_moc: "[[MOC - KubeVigil Governance]]"
---

# Charter Compliance — Independent Adversarial Re-Audit (Round 3) — 2026-07-02

## Verdict

**Strongest round yet — 16 of 19 tracked items genuinely closed — but still not certifiable.**

The round-2 remediation (commit `c7223b0`, +950/−235 across 31 files) is real, honest, minimal
work: the TOCTOU leaf-swap is closed with an `O_NOFOLLOW` fd-based read, the doc drift gate is
bidirectional and code-derived, the version gate now reads the authoritative git tag, the
checker tests are genuinely behavioral, and the round-2 cross-document contradictions are
reconciled. Verified by direct execution, not just reading: **`make all` exits 0 on a clean
HEAD** with all four gates green (the round-2 R2 blocker is gone).

Two things still block certification, and one of them is the crux of the whole exercise:

1. **The independent-critique control (F4) is fabricated.** The one mechanism that exists
   specifically to stop an author from grading their own homework was "fixed" by writing a
   critique document — authored in the same commit, by the same git identity, that echoes the
   round-2 findings rather than surfacing new ones. Genuine independence cannot be
   self-manufactured; the actual independent review is *this external audit series*.
2. **A real CI-red regression that local testing cannot catch.** R4's new dependency on
   `git tag` combined with a shallow CI checkout means the `doc-gates` job fails in CI while
   `make all` passes locally.

Plus a narrower residual TOCTOU, a mis-marked "Fixed", a non-canonical verdict, and gate
blind spots. Details below.

## Method

Third independent adversarial red-team, fresh slate, maximum stringency. To eliminate the
round-1/2 failure modes (auditors that flaked by spawning children and returning "I'll wait",
and concurrent agents colliding on the shared worktree), this round split the work: **the
orchestrator ran every empirical check itself** (clean-HEAD `make all`, gate mutation tests,
read of the confined read-path, CI-config inspection) as a single serialized writer, while
four **read-only** domain agents (governance, security, delivery/testing, gate-logic) verified
closures by reading code/diffs/charter and predicting gate behavior. All four agents completed;
no worktree collisions.

## Closed — verified (16 of 19)

- **R1 (TOCTOU) — code-level closed for the leaf-swap.** `pathguard.OpenRegularWithinRoot`
  opens the confined path `O_RDONLY|O_NOFOLLOW` and `fstat`s the held fd;
  `manifest_parser.go:parseFileWithinRoot` reads via `io.ReadAll(io.LimitReader(f, …))` — the
  MCP confined path no longer re-resolves by name or calls `os.ReadFile(path)`. A leaf swapped
  to a symlink after validation now fails the open. *(Residual parent-component race tracked
  as a new finding.)*
- **R2 — a11y green at HEAD.** `doc-a11y.sh` is now markdown-aware (strips fenced/inline code
  before scanning); the closeout's `![](bad.png)` example is backtick-wrapped and no longer
  self-trips. Confirmed by direct `make all` → exit 0.
- **R3 — Data-Privacy applicability reconciled.** Matrix and Annex both say `partial`;
  threat-model §5.1 now contains the cited rationale.
- **R4 — version gate authoritative.** `doc-gate.sh` derives the version from
  `git tag -l 'v[0-9]*'`; a fabricated version (consistent across docs) now fails. *(But see
  the CI shallow-clone finding.)*
- **R5 / F9 — checker tests behavioral.** `cloud/checkers_behavioral_regression_test.go` and
  `cluster/behavioral_regression_test.go` call `.Run()` on real fixtures and assert finding
  content; the reflection-only test was deleted.
- **R6** — status-vocab gate now scans `docs/governance/**`. **R7** — MASTER-REFERENCE MCP row
  corrected to "charter-compliance branch" (the two remaining "v0.5.0" rows are legitimately
  pre-existing features). **R8** — `mcp-setup.md` now documents `--workspace-root`. **R9** —
  Makefile gates de-duplicated. **R11** — STYLE-GUIDE link fixed. **R12** — confinement scope
  honestly documented as MCP-only, CLI operator-trusted; verified against code.
- **F5** — Data-Privacy pin corrected to revision 5. **F21** — sample gate exercises
  `fix --risk-level moderate`, `-o diff`, `--apply --yes` with hash verification. **F25** —
  `last_updated:`/`aliases:` added to the 6 docs.
- **F6 — reconciled within branch scope.** All tracked/public docs are uniformly 96%. (The only
  residual 94.0% is in the *gitignored* main-repo `CLAUDE.md` at lines 175/271, which is
  outside the branch's reach — a maintainer must hand-edit it.)

## Still open / new defects

### HIGH

**F4 — the "independent critique" is theater (persona collapse).**
`docs/governance/audits/charter-compliance-critique-round2-2026-07-02.md` was authored, the fix
it critiques was authored, and the closeout certifying it as independent was authored — all in
the same commit `c7223b0`, by the same git identity, under one `Co-authored-by` trailer. Its
`owners: [independent-critique-reviewer]` is a label, not an identity; its C1–C8 "challenges"
restate the round-2 findings the author already planned to fix, surfacing nothing new. This is
the exact anti-pattern `Critique-Persona-Template.md §7` and Charter-Governance §11.1 forbid.
*Root reality:* genuine independence cannot be self-manufactured in a solo repo. The fix is to
**cite this external adversarial audit series as the independent critique** (or route a
genuinely separate reviewer/model/session), not to write a self-authored critique doc.
*Charter:* Charter-Governance §11.1; Critique-Persona-Template §7.

**NEW-1 — CI `doc-gates` job is red on a shallow checkout (R4 side-effect).**
The `doc-gates` job uses `actions/checkout@v4` with no `fetch-depth: 0` (only the
`secrets-scan` job sets it). GitHub's default checkout fetches depth 1 and **no tags**, so
`doc-gate.sh`'s `git tag -l 'v[0-9]*'` returns empty → `fail "no release tag found"` → the job
fails on every CI run, independent of doc content. `make all` passes locally only because a
local clone has tags. This is an R2-class "green locally, red in CI" regression introduced by
the R4 fix. *Fix:* add `with: { fetch-depth: 0 }` (or `fetch-tags: true`) to the `doc-gates`
checkout, or have `doc-gate.sh` tolerate a tagless CI checkout. *Charter:* Operational-Delivery
(gates must actually run in the pipeline).

### MEDIUM

**NEW-2 — R1 residual: parent-component TOCTOU not eliminated.** `O_NOFOLLOW` guards only the
*final* path component; symlinks in *parent* components are still followed by the `OpenFile`,
and the validate (`ResolveWithinRoot`/`Lstat` + parent walk) and open are two separate
operations on a path string, not one atomic `openat2(RESOLVE_NO_SYMLINKS)` / dir-fd-relative
open. A race that swaps a parent directory for a symlink-to-outside between validation and open
can still escape. Exploitation is hard (narrow window, requires write in the workspace), and
much lower than round 2, but the "no window between validation and read" bar is not met.
*Fix:* `openat2(RESOLVE_NO_SYMLINKS)` on Linux with a portable dir-fd-relative fallback.

**NEW-3 — TOCTOU test does not test a race.** `TestOpenRegularWithinRoot_RejectsTOCTOUSymlinkSwap`
and its sibling place the symlink *before* calling the function — they prove "reject a symlink
present at open time," not "survive a swap during the validate→open window." The threat model
cites these as evidence for a race it doesn't exercise. *Charter:* AI-Agent-Execution §4.2.

**F23 — mis-marked "Fixed" on non-reproduction.** The closeout claims F23 fixed via "five
consecutive `make coverage` at 96.0%". The original defect was a `cover: bufio.Scanner: token
too long` crash on long lines; nothing in the diff touches scanner buffering. "It didn't crash
five times" is not a root-cause fix — it is the exit-0-observation anti-pattern. Coverage also
still sits exactly at the 96% floor with zero headroom. *Charter:* AI-Agent-Execution §3.4/§4.2.

**NEW-4 — closeout verdict uses non-canonical "Pass".** `Audit-Closeout-Template` mandates one
of `pass | pass-with-remediation | pass-with-deferred-findings | fail`. The closeout says
"**Pass** (Reference tier — pending binding Charter Owner signoff)". Given F4 open and Charter
Owner signoff explicitly pending, the honest value is `pass-with-deferred-findings`. The R6 gate
checks `status:` frontmatter vocabulary but not this verdict cell, so it passes silently.

**NEW-5 — no gate exercises the MCP surface or most output formats.** None of the four gates
starts `mcp-server` or invokes any of the 6 MCP tool handlers at runtime; `doc-samples-test.sh`
smoke-tests only `-o text`/`-o diff` (2 of 8 documented formats) and only `--risk-level
moderate`. A broken MCP tool handler (the security-sensitive path-handling surface) or a broken
`sarif`/`json`/`html` output would pass all gates with `make all` green. *Fix:* add an
MCP-tool smoke test and cover the remaining formats.

### LOW

- **R10 — default workspace-root fix is documentation-only.** `pathguard.DefaultWorkspaceRoot()`
  still falls back to `os.Getwd()` with no runtime `slog.Warn`; only the flag help and ADR
  prose gained a warning. *Fix:* log a warning on cwd fallback (or refuse to start without an
  explicit root).
- **NEW-6 — `doc-gate.sh` has a stale hardcoded `## \[0\.5\.` literal** (line 15) that will
  keep passing after the next version bump (`grep -q` matches anywhere in history), never
  asserting 0.5.x is *current*.
- **NEW-7 — drift gate's checker-count check is an unanchored substring `grep -q "$count"`** —
  110→11 with a coincidental "11" elsewhere in the doc would falsely pass. Anchor to
  `\*\*NNN\*\*`.

## Prioritized backlog (round 3)

| ID | Sev | Item |
|----|-----|------|
| F4 | HIGH | Real independent critique — cite the external audit series or route a genuinely separate reviewer; stop self-authoring |
| NEW-1 | HIGH | Fix CI `doc-gates` shallow checkout (`fetch-depth: 0`/`fetch-tags`) so the tag-based version gate can run |
| NEW-2 | MED | Close residual parent-component TOCTOU (`openat2(RESOLVE_NO_SYMLINKS)` / dir-fd) |
| NEW-3 | MED | Add a real race-based TOCTOU test (or stop citing the synchronous one as race evidence) |
| F23 | MED | Actually fix the `bufio.Scanner: token too long` root cause; add headroom above the floor |
| NEW-4 | MED | Set the closeout verdict to the canonical `pass-with-deferred-findings` |
| NEW-5 | MED | Add MCP-tool smoke test + cover remaining output formats in the sample gate |
| R10 | LOW | Warn/refuse at runtime on cwd workspace-root fallback |
| NEW-6 | LOW | Replace the stale `## \[0\.5\.` literal with a tag-derived check |
| NEW-7 | LOW | Anchor the checker-count check to `**NNN**` |
| F6 | LOW | Hand-update the gitignored main-repo `CLAUDE.md` 94%→96% (out of branch scope) |

## Bottom line

Rounds 1→2→3 show a real trajectory: theater → real-but-overclaimed → genuinely-solid-with-two-blockers.
The engineering is now honest and verifiable. What remains is telling: the hardest finding to
close is F4, because *independence is the one thing you cannot certify about yourself* — the
maintainer keeps trying to self-manufacture it, and the actual independent critique is this
audit. Close F4 (by citing this series) and NEW-1 (the CI break), address the residual TOCTOU
and the honest verdict, and the Charter claim finally holds.

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers (@msambare), independent adversarial re-audit | Round-3 re-audit of remediation `c7223b0`: 16 of 19 items verified closed; F4/F23/R10 still open; 7 new defects (NEW-1..7). `make all` verified green on clean HEAD; CI shallow-clone tag break verified. |
