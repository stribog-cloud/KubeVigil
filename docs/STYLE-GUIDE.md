# Documentation Style Guide

All documentation in `docs/` follows these conventions.

## Structure

- **H1** (`#`): Page title — one per file
- **H2** (`##`): Major sections
- **H3** (`###`): Subsections
- **H4** (`####`): Rarely; prefer keeping nesting shallow

## Tone

- Second person ("you"), active voice
- Present tense for features ("KubeVigil scans..."), imperative for instructions ("Run the command...")
- Concise — no filler phrases like "In order to" or "It should be noted that"

## Formatting

- **Commands**: fenced code blocks with `bash` language tag
- **Flags/options**: inline code (`--severity`)
- **Check IDs**: inline code (`privileged-container`)
- **File paths**: inline code (`.kubevigil.yaml`)
- **Severity levels**: **Critical**, **High**, **Medium**, **Low**, **Info** (bold)

## Command Examples

Always show real, runnable commands:

```bash
kubevigil scan -f deployment.yaml
kubevigil scan -n production --severity high
kubevigil fix manifests/ --apply --risk-level moderate
```

## Cross-References

Use relative links from the file's location:

```markdown
See [Output Formats](../scanning/output-formats.md) for details.
```

## Tables

Use for structured data (check lists, flag references, exit codes):

```markdown
| Flag | Description | Default |
|------|-------------|---------|
| `--severity` | Minimum severity | all |
```

## Check Documentation Format

Each check entry in a category page should include:

```markdown
### `check-id`

**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Description of what the check detects and why it matters.

**Remediation:**
Brief guidance on how to fix the finding.
```

Include framework mappings where applicable (CIS, MITRE, NSA).
