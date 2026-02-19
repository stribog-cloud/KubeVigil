package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cloud"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cluster"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/crd"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/image"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/network"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/psa"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/rbac"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/scheduling"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/secrets"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/storage"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/supply_chain"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/fix"
)

// fixtureDir returns the path to fix test fixtures.
func fixFixtureDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../test/fixtures/fix")
	require.NoError(t, err)
	return dir
}

// copyFixtureFile copies a fixture into a temp directory.
func copyFixtureFile(t *testing.T, fixtureName string) string {
	t.Helper()
	src := filepath.Join(fixFixtureDir(t), fixtureName)
	data, err := os.ReadFile(src)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, fixtureName)
	require.NoError(t, os.WriteFile(dst, data, 0o644))
	return dst
}

// newFixer creates a Fixer with the given fix config, using default registries.
func newFixer(t *testing.T, fixCfg fix.Config) *fix.Fixer {
	t.Helper()
	scanCfg := config.Default()
	scanCfg.Settings.IncludeSystemNamespaces = true
	return fix.NewFixer(fix.DefaultRegistry(), checker.DefaultRegistry(), scanCfg, &fixCfg)
}

// TestFixIntegration_GoldenWorkflow is the core golden workflow test:
// scan → fix → re-scan → verify the "privileged" finding is gone.
func TestFixIntegration_GoldenWorkflow(t *testing.T) {
	path := copyFixtureFile(t, "simple-deployment.yaml")
	ctx := context.Background()

	scanCfg := config.Default()
	scanCfg.Settings.IncludeSystemNamespaces = true
	scanner := engine.NewScanner(checker.DefaultRegistry(), scanCfg)

	// Step 1: Initial scan — should find "privileged" issue.
	result1, err := scanner.ScanManifest(ctx, path)
	require.NoError(t, err)

	hasPrivileged := false
	for _, f := range result1.Findings {
		if f.Checker == "privileged" {
			hasPrivileged = true
			break
		}
	}
	assert.True(t, hasPrivileged, "initial scan should find 'privileged' issue")

	// Step 2: Fix the file.
	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, summary, err := fixer.Fix(ctx, []string{path})
	require.NoError(t, err)
	assert.Greater(t, summary.Applied, 0, "should apply at least one fix")

	// Step 3: Re-scan — "privileged" finding should be gone.
	result2, err := scanner.ScanManifest(ctx, path)
	require.NoError(t, err)

	for _, f := range result2.Findings {
		if f.Checker == "privileged" {
			t.Errorf("'privileged' finding should be fixed, but found: %s", f.Message)
		}
	}
}

// TestFixIntegration_CommentPreservation verifies that YAML comments survive the fix pipeline.
func TestFixIntegration_CommentPreservation(t *testing.T) {
	path := copyFixtureFile(t, "commented-deployment.yaml")
	ctx := context.Background()

	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, _, err := fixer.Fix(ctx, []string{path})
	require.NoError(t, err)

	patched, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(patched)

	// Verify that key comments are preserved.
	comments := []string{
		"# This deployment runs the API backend service.",
		"# Team ownership label",
		"# Main API application",
		"# Scale based on load testing results",
		"# Port configuration",
		"# Init container for DB migrations",
	}
	for _, c := range comments {
		assert.Contains(t, content, c, "comment should be preserved: %s", c)
	}

	// The fix should still have been applied.
	assert.Contains(t, content, "privileged: false", "privileged should be set to false")
}

// TestFixIntegration_MultiDoc verifies that only the affected document in a multi-doc file is changed.
func TestFixIntegration_MultiDoc(t *testing.T) {
	path := copyFixtureFile(t, "multi-doc-mixed.yaml")
	ctx := context.Background()

	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, summary, err := fixer.Fix(ctx, []string{path})
	require.NoError(t, err)
	assert.Greater(t, summary.Applied, 0)

	patched, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(patched)

	// The Deployment should be patched.
	assert.Contains(t, content, "privileged: false")

	// The Service and ConfigMap should still be present and unchanged.
	assert.Contains(t, content, "kind: Service")
	assert.Contains(t, content, "kind: ConfigMap")
	assert.Contains(t, content, "app.conf:")
}

// TestFixIntegration_AlreadySecure verifies that a secure file produces no changes.
func TestFixIntegration_AlreadySecure(t *testing.T) {
	path := copyFixtureFile(t, "already-secure.yaml")
	original, err := os.ReadFile(path)
	require.NoError(t, err)

	ctx := context.Background()

	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
	})

	plan, err := fixer.Plan(ctx, []string{path})
	require.NoError(t, err)

	// Should have no diffs (nothing to fix at safe level for this file).
	assert.Empty(t, plan.Diffs, "already-secure file should produce no diffs")

	// File should be unchanged.
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(after))
}

// TestFixIntegration_MultiFinding verifies that multiple issues in one file are all fixed.
func TestFixIntegration_MultiFinding(t *testing.T) {
	path := copyFixtureFile(t, "multi-finding.yaml")
	ctx := context.Background()

	scanCfg := config.Default()
	scanCfg.Settings.IncludeSystemNamespaces = true
	scanner := engine.NewScanner(checker.DefaultRegistry(), scanCfg)

	// Initial scan — should find both privileged and privilege-escalation.
	result1, err := scanner.ScanManifest(ctx, path)
	require.NoError(t, err)

	checkerSet := make(map[string]bool)
	for _, f := range result1.Findings {
		checkerSet[f.Checker] = true
	}
	assert.True(t, checkerSet["privileged"], "should find 'privileged' issue")
	assert.True(t, checkerSet["privilege-escalation"], "should find 'privilege-escalation' issue")

	// Fix at safe level (both privileged and privilege-escalation are safe fixes).
	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, summary, err := fixer.Fix(ctx, []string{path})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, summary.Applied, 2, "should apply at least 2 fixes")

	// Re-scan — both issues should be resolved.
	result2, err := scanner.ScanManifest(ctx, path)
	require.NoError(t, err)

	for _, f := range result2.Findings {
		if f.Checker == "privileged" || f.Checker == "privilege-escalation" {
			t.Errorf("finding should be fixed: %s — %s", f.Checker, f.Message)
		}
	}

	// Verify the file content.
	patched, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(patched)
	assert.Contains(t, content, "privileged: false")
	assert.Contains(t, content, "allowPrivilegeEscalation: false")
}

// TestFixIntegration_SystemNamespaceBlock verifies system namespace protection works end-to-end.
func TestFixIntegration_SystemNamespaceBlock(t *testing.T) {
	path := copyFixtureFile(t, "system-namespace.yaml")
	original, err := os.ReadFile(path)
	require.NoError(t, err)

	ctx := context.Background()

	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelAggressive,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, summary, err := fixer.Fix(ctx, []string{path})
	require.NoError(t, err)

	// No fixes should be applied (system namespace protection).
	assert.Equal(t, 0, summary.Applied, "system namespace resources should not be fixed")

	// File should be unchanged.
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(after))
}

// TestFixIntegration_BackupCreated verifies that backups are created during apply.
func TestFixIntegration_BackupCreated(t *testing.T) {
	path := copyFixtureFile(t, "simple-deployment.yaml")
	backupDir := filepath.Join(t.TempDir(), "backup")
	ctx := context.Background()

	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
		Apply:     true,
		BackupDir: backupDir,
	})

	plan, _, err := fixer.Fix(ctx, []string{path})
	require.NoError(t, err)

	assert.Equal(t, backupDir, plan.Summary.BackupDir)

	// Backup directory should exist.
	_, statErr := os.Stat(backupDir)
	assert.NoError(t, statErr, "backup directory should exist")

	// RESTORE.md should exist.
	restorePath := filepath.Join(backupDir, "RESTORE.md")
	_, statErr = os.Stat(restorePath)
	assert.NoError(t, statErr, "RESTORE.md should exist in backup directory")

	// RESTORE.md should contain the file path.
	restoreContent, err := os.ReadFile(restorePath)
	require.NoError(t, err)
	assert.Contains(t, string(restoreContent), "simple-deployment.yaml")
}

// TestFixIntegration_DiffOutput verifies that the plan produces readable diffs.
func TestFixIntegration_DiffOutput(t *testing.T) {
	path := copyFixtureFile(t, "simple-deployment.yaml")
	ctx := context.Background()

	fixer := newFixer(t, fix.Config{
		RiskLevel: fix.RiskLevelSafe,
	})

	plan, err := fixer.Plan(ctx, []string{path})
	require.NoError(t, err)

	assert.NotEmpty(t, plan.Diffs, "should have diffs")

	for filePath, diff := range plan.Diffs {
		assert.Contains(t, diff, "---", "diff should have old file header")
		assert.Contains(t, diff, "+++", "diff should have new file header")
		assert.Contains(t, diff, "@@", "diff should have hunk header")
		// Diff headers should reference the file.
		assert.True(t, strings.Contains(diff, filepath.Base(filePath)),
			"diff should reference the filename")
	}
}
