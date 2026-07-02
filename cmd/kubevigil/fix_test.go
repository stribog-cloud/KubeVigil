package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/fix"
)

// insecureDeploymentYAML is a simple deployment with known security findings.
const insecureDeploymentYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
`

// secureDeploymentYAML has no fixable findings.
const secureDeploymentYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure
  template:
    metadata:
      labels:
        app: secure
    spec:
      automountServiceAccountToken: false
      containers:
      - name: app
        image: nginx:1.25@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
        imagePullPolicy: Always
        securityContext:
          privileged: false
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
        resources:
          limits:
            cpu: 500m
            memory: 256Mi
          requests:
            cpu: 100m
            memory: 128Mi
`

// systemNSDeploymentYAML has a resource in kube-system.
const systemNSDeploymentYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: system-component
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: system
  template:
    metadata:
      labels:
        app: system
    spec:
      containers:
      - name: main
        image: registry.k8s.io/system:v1.0
        securityContext:
          privileged: true
`

// writeFixture writes YAML content to a temporary directory and returns the path.
func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestFixCommand_DryRunDefault(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	// Run fix without --apply — should produce diff output, no file modification.
	fixCfg := fix.DefaultConfig()
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Should have planned fixes.
	assert.Greater(t, plan.Summary.Applied, 0, "should have planned fixes")
	assert.Greater(t, len(plan.Diffs), 0, "should have generated diffs")

	// File should NOT be modified (dry-run).
	original, err := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	require.NoError(t, err)
	assert.Equal(t, insecureDeploymentYAML, string(original), "file should not be modified in dry-run")
}

func TestFixCommand_ApplyModifiesFiles(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.Apply = true
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)
	assert.Greater(t, plan.Summary.Applied, 0)

	summary, err := fixer.Apply(t.Context(), plan)
	require.NoError(t, err)

	// File should be modified.
	modified, err := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	require.NoError(t, err)
	assert.NotEqual(t, insecureDeploymentYAML, string(modified), "file should be modified after apply")

	// Backup should exist.
	assert.NotEmpty(t, summary.BackupDir)
}

func TestFixCommand_RiskLevelSafe(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelSafe
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Only safe fixes should be applied; likely_safe and potentially_breaking should be skipped.
	for _, r := range plan.Summary.Results {
		if r.Applied {
			assert.Equal(t, checker.FixSafe, r.Safety, "only safe fixes should be applied at safe risk level")
		}
	}
	// Should have skipped some due to risk level.
	assert.Greater(t, plan.Summary.SkipReasons["risk_level"], 0, "should have skipped findings above safe")
}

func TestFixCommand_RiskLevelModerate(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelModerate
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Should have applied safe + likely_safe fixes.
	for _, r := range plan.Summary.Results {
		if r.Applied {
			assert.True(t, r.Safety == checker.FixSafe || r.Safety == checker.FixLikelySafe,
				"moderate should allow safe and likely_safe, got %s", r.Safety)
		}
	}
}

func TestFixCommand_RiskLevelAggressive(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelAggressive
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Should have applied safe + likely_safe + potentially_breaking fixes.
	assert.Greater(t, plan.Summary.Applied, 0)
	// No risk_level skips expected.
	assert.Equal(t, 0, plan.Summary.SkipReasons["risk_level"],
		"aggressive should not skip any for risk level")
}

func TestFixCommand_SystemNamespaceProtection(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "system.yaml", systemNSDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelAggressive // Even aggressive shouldn't fix system NS
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// All findings should be skipped due to system namespace.
	assert.Equal(t, 0, plan.Summary.Applied, "system NS resources should not be fixed")
	assert.Greater(t, plan.Summary.SkipReasons["system_namespace"], 0)
}

func TestFixCommand_SystemNamespaceWithOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "system.yaml", systemNSDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelAggressive
	fixCfg.AllowSystemNamespaces = true
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// With override, system NS resources should be fixed.
	assert.Greater(t, plan.Summary.Applied, 0, "should fix system NS with override flag")
}

func TestFixCommand_ChecksFilter(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.Checks = []string{"privileged"}
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Only privileged check should be applied.
	for _, r := range plan.Summary.Results {
		if r.Applied {
			assert.Equal(t, "privileged", r.CheckID, "only privileged check should be applied")
		}
	}
}

func TestFixCommand_SeverityFilter(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelAggressive
	fixCfg.Severities = []string{"critical"}
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Findings not matching the severity filter should be skipped.
	// At least some should be filtered for severity.
	assert.Greater(t, plan.Summary.SkipReasons["severity_not_selected"], 0,
		"should skip findings not matching severity filter")
}

func TestFixCommand_NamespaceFilter(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.Namespaces = []string{"staging"} // Only fix staging, not production
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// No fixes should be applied since the fixture is in "production".
	assert.Equal(t, 0, plan.Summary.Applied, "should not fix resources outside selected namespace")
}

func TestFixCommand_ExcludeNamespaceFilter(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.ExcludeNamespaces = []string{"production"}
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	assert.Equal(t, 0, plan.Summary.Applied, "should not fix excluded namespace")
	assert.Greater(t, plan.Summary.SkipReasons["namespace_excluded"], 0)
}

func TestFixCommand_NothingToFix(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "secure.yaml", secureDeploymentYAML)

	// Use safe risk level — the fixture is fully hardened at safe level.
	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = fix.RiskLevelSafe
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	for _, r := range plan.Summary.Results {
		if r.Applied {
			t.Logf("Unexpected applied fix: check=%s resource=%s safety=%s", r.CheckID, r.Resource, r.Safety)
		}
	}
	assert.Equal(t, 0, plan.Summary.Applied, "fully hardened deployment should have no safe-level fixes")
}

func TestFixCommand_VerifyFlag(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.Apply = true
	fixCfg.Verify = true
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	_, err = fixer.Apply(t.Context(), plan)
	require.NoError(t, err)

	// Verify should find no remaining safe-level fixable findings.
	verifyPlan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)
	assert.Equal(t, 0, verifyPlan.Summary.Applied, "verify should find no remaining safe fixes")
}

func TestFixCommand_CustomBackupDir(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	backupDir := filepath.Join(t.TempDir(), "custom-backup")
	fixCfg := fix.DefaultConfig()
	fixCfg.Apply = true
	fixCfg.BackupDir = backupDir
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	summary, err := fixer.Apply(t.Context(), plan)
	require.NoError(t, err)

	assert.Equal(t, backupDir, summary.BackupDir)
	// Verify backup dir exists.
	_, err = os.Stat(backupDir)
	assert.NoError(t, err, "custom backup directory should exist")
}

func TestFixCommand_PathRequired(t *testing.T) {
	// The Cobra command requires exactly 1 arg.
	cmd := fixCmd
	err := cmd.Args(cmd, nil)
	assert.Error(t, err, "fix command should require path argument")
}

func TestFixCommand_HelpIncludesAllFlags(t *testing.T) {
	var buf bytes.Buffer
	fixCmd.SetOut(&buf)
	fixCmd.SetErr(&buf)
	err := fixCmd.Usage()
	require.NoError(t, err)
	output := buf.String()

	expectedFlags := []string{
		"--apply", "--yes", "--verify",
		"--risk-level", "--i-understand-system-namespaces",
		"--checks", "--severity", "--namespace", "--exclude-namespace", "--exclude-infra",
		"--output", "--kustomize", "--report", "--backup-dir",
		"--git-pr",
	}
	for _, flag := range expectedFlags {
		assert.Contains(t, output, flag, "help should include %s flag", flag)
	}
}

// --- Exit code tests ---

func TestFixExitCodes(t *testing.T) {
	assert.Equal(t, 0, fix.ExitFixSuccess, "success exit code")
	assert.Equal(t, 1, fix.ExitFixVerifyFailed, "verify failed exit code")
	assert.Equal(t, 2, fix.ExitFixError, "fix error exit code")
	assert.Equal(t, 3, fix.ExitFixConfigError, "config error exit code")
	assert.Equal(t, 4, fix.ExitFixNothingToDo, "nothing to do exit code")
	assert.Equal(t, 5, fix.ExitFixPartialSuccess, "partial success exit code")
}

// --- CI mode tests ---

func TestIsInteractive_CIEnvVar(t *testing.T) {
	tests := []struct {
		name string
		env  string
		val  string
		want bool
	}{
		{"CI=true", "CI", "true", false},
		{"GITHUB_ACTIONS=true", "GITHUB_ACTIONS", "true", false},
		{"GITLAB_CI=true", "GITLAB_CI", "true", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, tt.val)
			assert.Equal(t, tt.want, isInteractive())
		})
	}
}

func TestIsInteractive_JenkinsURL(t *testing.T) {
	t.Setenv("JENKINS_URL", "http://jenkins.local")
	assert.False(t, isInteractive(), "JENKINS_URL set should not be interactive")
}

// --- Config integration tests ---

func TestBuildFixConfig_FromConfigFile(t *testing.T) {
	cfg := configForTest(t)

	fixCfg := buildFixConfig(cfg, fix.RiskLevelSafe)

	assert.Equal(t, fix.RiskLevelSafe, fixCfg.RiskLevel)
	assert.Equal(t, 20, fixCfg.BulkThreshold, "should use config file bulkThreshold")
	assert.Equal(t, "/tmp/backups/", fixCfg.BackupDir, "should use config file backupDir")
	assert.Contains(t, fixCfg.AdditionalSystemNamespaces, "custom-infra",
		"should include additional system namespaces from config")
}

func TestBuildFixConfig_CLIOverridesConfig(t *testing.T) {
	cfg := configForTest(t)

	// Set CLI flag override.
	origBackupDir := flagFixBackupDir
	defer func() { flagFixBackupDir = origBackupDir }()
	flagFixBackupDir = "/custom/backup"

	fixCfg := buildFixConfig(cfg, fix.RiskLevelModerate)

	assert.Equal(t, fix.RiskLevelModerate, fixCfg.RiskLevel)
	assert.Equal(t, "/custom/backup", fixCfg.BackupDir, "CLI flag should override config file")
}

func TestBuildFixConfig_AdditionalSystemNSAdditive(t *testing.T) {
	cfg := configForTest(t)

	fixCfg := fix.DefaultConfig()
	fixCfg.AdditionalSystemNamespaces = cfg.Fix.AdditionalSystemNamespaces

	classifier := fix.NewSafetyClassifier(fixCfg.AdditionalSystemNamespaces)

	// Built-in system namespace should still be protected.
	assert.True(t, classifier.IsSystemNamespace("kube-system"),
		"built-in system NS must remain protected")
	// Config-added namespace should also be protected.
	assert.True(t, classifier.IsSystemNamespace("custom-infra"),
		"config-added NS should be protected")
}

// --- Output mode tests ---

func TestPrintFixSummary(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  10,
		FilesModified: 3,
		TotalFindings: 5,
		Applied:       3,
		Skipped:       2,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe: 3,
		},
		SkipReasons: map[string]int{
			"risk_level": 2,
		},
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, false, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "KubeVigil Fix Summary")
	assert.Contains(t, output, "Files scanned:")
	assert.Contains(t, output, "Files to modify:")
	assert.Contains(t, output, "By risk classification:")
	assert.Contains(t, output, "Safe:")
}

func TestPrintKubectlPatches(t *testing.T) {
	plan := &fix.Plan{
		Summary: fix.Summary{
			Results: []fix.Result{
				{
					FilePath:    "/tmp/deploy.yaml",
					Resource:    "web-app",
					Namespace:   "production",
					Kind:        "Deployment",
					CheckID:     "privileged",
					Safety:      checker.FixSafe,
					Description: "Disables privileged mode.",
					Applied:     true,
				},
			},
		},
	}

	var buf bytes.Buffer
	printKubectlPatches(&buf, plan, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "KubeVigil kubectl patch commands")
	assert.Contains(t, output, "Risk level: safe")
	assert.Contains(t, output, "Namespace: production")
	assert.Contains(t, output, "kubectl patch deployment web-app")
}

func TestPrintDiffs_WithInlineWarnings(t *testing.T) {
	plan := &fix.Plan{
		Files: map[string]*fix.FilePlan{
			"deploy.yaml": {
				Path: "deploy.yaml",
				Fixes: []fix.PlannedFix{
					{
						Applied: true,
						Strategy: fix.Strategy{
							Safety:  checker.FixLikelySafe,
							Impact:  "Containers writing to filesystem will fail.",
							CheckID: "read-only-rootfs",
						},
					},
				},
			},
		},
		Diffs: map[string]string{
			"deploy.yaml": "--- a/deploy.yaml\n+++ b/deploy.yaml\n@@ -1,2 +1,3 @@\n spec:\n+  readOnlyRootFilesystem: true\n",
		},
	}

	var buf bytes.Buffer
	printDiffs(&buf, plan)
	output := buf.String()

	assert.Contains(t, output, "IMPACT (likely_safe)")
	assert.Contains(t, output, "Containers writing to filesystem will fail.")
}

func TestPrintDiffs_NoWarningForSafe(t *testing.T) {
	plan := &fix.Plan{
		Files: map[string]*fix.FilePlan{
			"deploy.yaml": {
				Path: "deploy.yaml",
				Fixes: []fix.PlannedFix{
					{
						Applied: true,
						Strategy: fix.Strategy{
							Safety:  checker.FixSafe,
							Impact:  "None.",
							CheckID: "privileged",
						},
					},
				},
			},
		},
		Diffs: map[string]string{
			"deploy.yaml": "--- a/deploy.yaml\n+++ b/deploy.yaml\n@@ -1,2 +1,3 @@\n spec:\n-  privileged: true\n+  privileged: false\n",
		},
	}

	var buf bytes.Buffer
	printDiffs(&buf, plan)
	output := buf.String()

	assert.NotContains(t, output, "IMPACT", "safe fixes should not have impact warnings in diff")
}

// --- Interactive confirmation tests ---

func TestConfirmBulkApply_YesResponse(t *testing.T) {
	plan := &fix.Plan{
		Summary: fix.Summary{
			FilesModified: 20,
			Applied:       15,
			Results: []fix.Result{
				{Namespace: "prod", Applied: true},
				{Namespace: "staging", Applied: true},
			},
		},
	}

	input := strings.NewReader("y\n")
	var output bytes.Buffer
	proceed, err := confirmBulkApply(input, &output, plan)
	require.NoError(t, err)
	assert.True(t, proceed)
}

func TestConfirmBulkApply_NoResponse(t *testing.T) {
	plan := &fix.Plan{
		Summary: fix.Summary{
			FilesModified: 20,
			Applied:       15,
			Results: []fix.Result{
				{Namespace: "prod", Applied: true},
			},
		},
	}

	input := strings.NewReader("n\n")
	var output bytes.Buffer
	proceed, err := confirmBulkApply(input, &output, plan)
	require.NoError(t, err)
	assert.False(t, proceed)
}

func TestConfirmBulkApply_DefaultNo(t *testing.T) {
	plan := &fix.Plan{
		Summary: fix.Summary{
			FilesModified: 20,
			Applied:       15,
			Results:       []fix.Result{{Namespace: "prod", Applied: true}},
		},
	}

	// EOF without response — should default to no.
	input := strings.NewReader("")
	var output bytes.Buffer
	proceed, err := confirmBulkApply(input, &output, plan)
	require.NoError(t, err)
	assert.False(t, proceed)
}

// --- Utility function tests ---

func TestSplitComma(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b , c", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", nil},
		{",,,", nil},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitComma(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseRiskLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    fix.RiskLevel
		wantErr bool
	}{
		{"safe", fix.RiskLevelSafe, false},
		{"moderate", fix.RiskLevelModerate, false},
		{"aggressive", fix.RiskLevelAggressive, false},
		{"Safe", fix.RiskLevelSafe, false},
		{"MODERATE", fix.RiskLevelModerate, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := fix.ParseRiskLevel(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestSkipReasonLabel(t *testing.T) {
	assert.Equal(t, "System namespaces", skipReasonLabel("system_namespace"))
	assert.Equal(t, "Risk > allowed", skipReasonLabel("risk_level"))
	assert.Equal(t, "Check filtered", skipReasonLabel("check_not_selected"))
	assert.Equal(t, "unknown_reason", skipReasonLabel("unknown_reason"))
}

// --- Partial failure tests ---

func TestFixCommand_PartialFailure(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "good.yaml", insecureDeploymentYAML)
	writeFixture(t, dir, "bad.yaml", "{{invalid yaml")

	fixCfg := fix.DefaultConfig()
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Should have processed the good file.
	assert.Greater(t, plan.Summary.Applied, 0, "good file should have fixes")
	// Should have recorded the bad file error.
	assert.Greater(t, plan.Summary.FilesFailed, 0, "bad file should be recorded as failed")
}

// --- Integration: scan → fix → verify ---

func TestFixCommand_ScanFixVerifyGoldenWorkflow(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixCfg.Apply = true
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)

	// Step 1: Plan.
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)
	assert.Greater(t, plan.Summary.Applied, 0, "should have planned fixes")

	// Step 2: Apply.
	_, err = fixer.Apply(t.Context(), plan)
	require.NoError(t, err)

	// Step 3: Re-scan (verify).
	verifyPlan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)
	assert.Equal(t, 0, verifyPlan.Summary.Applied,
		"re-scan after fix should find no remaining safe fixes")
}

// --- Config file integration ---

func TestConfigFixSection_Parsing(t *testing.T) {
	cfgYAML := `version: "1"
settings:
  fail_on: high
fix:
  additionalSystemNamespaces:
    - custom-infra
    - vault
  bulkThreshold: 20
  backupDir: /tmp/kubevigil-backups/
`
	dir := t.TempDir()
	path := filepath.Join(dir, ".kubevigil.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfgYAML), 0o644))

	orig := flagConfig
	defer func() { flagConfig = orig }()
	flagConfig = path

	cfg, err := loadConfig()
	require.NoError(t, err)

	assert.Equal(t, []string{"custom-infra", "vault"}, cfg.Fix.AdditionalSystemNamespaces)
	assert.Equal(t, 20, cfg.Fix.BulkThreshold)
	assert.Equal(t, "/tmp/kubevigil-backups/", cfg.Fix.BackupDir)
}

func TestConfigFixSection_EmptyFixConfig(t *testing.T) {
	cfgYAML := `version: "1"
settings:
  fail_on: high
`
	dir := t.TempDir()
	path := filepath.Join(dir, ".kubevigil.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfgYAML), 0o644))

	orig := flagConfig
	defer func() { flagConfig = orig }()
	flagConfig = path

	cfg, err := loadConfig()
	require.NoError(t, err)

	// Should have zero values for fix config.
	assert.Empty(t, cfg.Fix.AdditionalSystemNamespaces)
	assert.Equal(t, 0, cfg.Fix.BulkThreshold)
	assert.Empty(t, cfg.Fix.BackupDir)
}

// --- Diff output tests ---

func TestDiffOutput_ShowsChanges(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCfg := fix.DefaultConfig()
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()

	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)
	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)

	// Diffs should contain the file path and show changes.
	assert.Greater(t, len(plan.Diffs), 0)
	for _, diff := range plan.Diffs {
		assert.Contains(t, diff, "---")
		assert.Contains(t, diff, "+++")
		assert.Contains(t, diff, "@@")
	}
}

// --- Kubectl output tests ---

func TestKubectlOutput_DefaultNamespace(t *testing.T) {
	// Finding with empty namespace should use "default".
	plan := &fix.Plan{
		Summary: fix.Summary{
			Results: []fix.Result{
				{
					Resource:  "my-pod",
					Namespace: "",
					Kind:      "Pod",
					CheckID:   "privileged",
					Safety:    checker.FixSafe,
					Applied:   true,
				},
			},
		},
	}

	var buf bytes.Buffer
	printKubectlPatches(&buf, plan, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "Namespace: default")
}

// --- Ensure existing commands still work ---

func TestFixCommand_DoesNotBreakScanCommand(t *testing.T) {
	// Verify scan command is still registered.
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "scan" {
			found = true
			break
		}
	}
	assert.True(t, found, "scan command should still be registered")
}

func TestFixCommand_DoesNotBreakListCommand(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "list" {
			found = true
			break
		}
	}
	assert.True(t, found, "list command should still be registered")
}

func TestFixCommand_IsRegistered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "fix" {
			found = true
			break
		}
	}
	assert.True(t, found, "fix command should be registered")
}

// --- Helpers ---

// configForTest returns a config with fix settings populated for testing.
func configForTest(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Version: "1",
		Settings: config.Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
		},
		Fix: config.FixConfig{
			AdditionalSystemNamespaces: []string{"custom-infra", "vault"},
			BulkThreshold:              20,
			BackupDir:                  "/tmp/backups/",
		},
	}
}

// verifyFixesHelper is a test version of the fix verification flow.
func verifyFixesHelper(t *testing.T, dir string) bool {
	t.Helper()
	fixCfg := fix.DefaultConfig()
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()
	fixer := fix.NewFixer(fixReg, checkerReg, config.Default(), &fixCfg)

	plan, err := fixer.Plan(t.Context(), []string{dir})
	require.NoError(t, err)
	return plan.Summary.Applied > 0
}

// Suppress unused variable warning - verifyFixesHelper may be used in future tests.
var _ = verifyFixesHelper

// saveAndRestoreFlags saves all global fix-related flag state and registers
// a cleanup function to restore it when the test finishes.
func saveAndRestoreFlags(t *testing.T) {
	t.Helper()
	origApply := flagFixApply
	origYes := flagFixYes
	origVerify := flagFixVerify
	origRiskLevel := flagFixRiskLevel
	origOutput := flagFixOutput
	origChecks := flagFixChecks
	origSeverity := flagFixSeverity
	origNamespace := flagFixNamespace
	origExcludeNS := flagFixExcludeNamespace
	origExcludeInfra := flagFixExcludeInfra
	origKustomize := flagFixKustomize
	origReport := flagFixReport
	origBackupDir := flagFixBackupDir
	origFingerprint := flagFixFingerprint
	origGitPR := flagFixGitPR
	origSystemNS := flagFixSystemNS
	origNoColor := flagNoColor
	origConfig := flagConfig
	origVerbose := flagVerbose
	t.Cleanup(func() {
		flagFixApply = origApply
		flagFixYes = origYes
		flagFixVerify = origVerify
		flagFixRiskLevel = origRiskLevel
		flagFixOutput = origOutput
		flagFixChecks = origChecks
		flagFixSeverity = origSeverity
		flagFixNamespace = origNamespace
		flagFixExcludeNamespace = origExcludeNS
		flagFixExcludeInfra = origExcludeInfra
		flagFixKustomize = origKustomize
		flagFixReport = origReport
		flagFixBackupDir = origBackupDir
		flagFixFingerprint = origFingerprint
		flagFixGitPR = origGitPR
		flagFixSystemNS = origSystemNS
		flagNoColor = origNoColor
		flagConfig = origConfig
		flagVerbose = origVerbose
	})

	// Reset all flags to defaults.
	flagFixApply = false
	flagFixYes = false
	flagFixVerify = false
	flagFixRiskLevel = "safe"
	flagFixOutput = "diff"
	flagFixChecks = ""
	flagFixSeverity = ""
	flagFixNamespace = ""
	flagFixExcludeNamespace = ""
	flagFixExcludeInfra = false
	flagFixKustomize = ""
	flagFixReport = ""
	flagFixBackupDir = ""
	flagFixFingerprint = ""
	flagFixGitPR = false
	flagFixSystemNS = false
	flagNoColor = true
	flagConfig = ""
	flagVerbose = false
}

// --- runFix() tests via direct invocation ---

func TestRunFix_DryRun(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Dry-run with insecure deployment shows changes and succeeds.
	assert.NoError(t, err)
}

func TestRunFix_ApplyModifiesFiles(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	backupDir := filepath.Join(t.TempDir(), "backup")
	flagFixApply = true
	flagFixYes = true
	flagFixBackupDir = backupDir

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err)

	// File should have been modified.
	modified, readErr := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	require.NoError(t, readErr)
	assert.NotEqual(t, insecureDeploymentYAML, string(modified), "file should be modified after apply")

	// Backup directory should exist.
	_, statErr := os.Stat(backupDir)
	assert.NoError(t, statErr, "backup directory should exist")
}

func TestRunFix_NothingToFix(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "secure.yaml", secureDeploymentYAML)

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixNothingToDo, ee.code, "secure deployment should have nothing to do")
}

func TestRunFix_BadRiskLevel(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)
	flagFixRiskLevel = "invalid"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixConfigError, ee.code, "invalid risk level should return config error")
}

func TestRunFix_InvalidOutputMode(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)
	flagFixOutput = "invalid"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixConfigError, ee.code, "invalid output mode should return config error")
}

func TestRunFix_KubectlOutputMode(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)
	flagFixOutput = "kubectl"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err, "kubectl output mode should succeed")
}

func TestRunFix_HelmValuesOutputMode(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)
	flagFixOutput = "helm-values"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err, "helm-values output mode should succeed")
}

func TestRunFix_ApplyWithVerify_Aggressive(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	backupDir := filepath.Join(t.TempDir(), "backup-verify")
	flagFixApply = true
	flagFixVerify = true
	flagFixYes = true
	flagFixBackupDir = backupDir
	flagFixRiskLevel = "aggressive"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// At aggressive level, all auto-fixable findings should be resolved.
	// Verify may still find non-auto-fixable findings; either nil or verify-failed is acceptable.
	if err != nil {
		var ee *exitError
		require.ErrorAs(t, err, &ee)
		assert.Equal(t, fix.ExitFixVerifyFailed, ee.code,
			"if verify fails, it should be because of remaining non-auto-fixable findings")
	}
}

func TestRunFix_ApplyWithVerify_SafeLevel(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	backupDir := filepath.Join(t.TempDir(), "backup-verify-safe")
	flagFixApply = true
	flagFixVerify = true
	flagFixYes = true
	flagFixBackupDir = backupDir
	flagFixRiskLevel = "safe"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// At safe level, likely_safe and potentially_breaking fixes remain.
	// Verify finds remaining fixable findings and returns ExitFixVerifyFailed.
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixVerifyFailed, ee.code,
		"safe-level apply leaves likely_safe/potentially_breaking findings, verify should fail")
}

func TestRunFix_SystemNamespaceSkipped(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "system.yaml", systemNSDeploymentYAML)

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixNothingToDo, ee.code, "system NS resources should all be skipped")
}

func TestRunFix_RiskLevelModerate(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)
	flagFixRiskLevel = "moderate"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err, "moderate risk level dry-run should succeed")
}

// --- printVerifyResult() tests ---

func TestPrintVerifyResult_Clean(t *testing.T) {
	result := &fix.VerifyResult{
		TotalBefore:       5,
		TotalAfter:        0,
		Resolved:          5,
		Remaining:         0,
		Clean:             true,
		RemainingFindings: map[string][]string{},
	}
	var buf bytes.Buffer
	printVerifyResult(&buf, result)
	output := buf.String()

	assert.Contains(t, output, "Verification Results")
	assert.Contains(t, output, "All fixable findings resolved")
	assert.Contains(t, output, "Fixable before:")
	assert.Contains(t, output, "Fixable after:")
	assert.Contains(t, output, "Resolved:")
	assert.NotContains(t, output, "New:")
}

func TestPrintVerifyResult_NotClean(t *testing.T) {
	result := &fix.VerifyResult{
		TotalBefore: 10,
		TotalAfter:  3,
		Resolved:    7,
		Remaining:   3,
		Clean:       false,
		RemainingFindings: map[string][]string{
			"deploy.yaml": {"privileged", "read-only-rootfs"},
			"pod.yaml":    {"allow-privilege-escalation"},
		},
	}
	var buf bytes.Buffer
	printVerifyResult(&buf, result)
	output := buf.String()

	assert.Contains(t, output, "Verification Results")
	assert.Contains(t, output, "3 fixable findings remain")
	assert.Contains(t, output, "deploy.yaml")
	assert.Contains(t, output, "privileged")
	assert.Contains(t, output, "pod.yaml")
	assert.Contains(t, output, "allow-privilege-escalation")
	assert.NotContains(t, output, "All fixable findings resolved")
}

func TestPrintVerifyResult_WithNewFindings(t *testing.T) {
	result := &fix.VerifyResult{
		TotalBefore: 5,
		TotalAfter:  2,
		Resolved:    5,
		Remaining:   2,
		New:         2,
		Clean:       false,
		RemainingFindings: map[string][]string{
			"app.yaml": {"new-check-1", "new-check-2"},
		},
	}
	var buf bytes.Buffer
	printVerifyResult(&buf, result)
	output := buf.String()

	assert.Contains(t, output, "New:")
	assert.Contains(t, output, "2 fixable findings remain")
	assert.Contains(t, output, "app.yaml")
}

// --- isTerminalWriter() tests ---

func TestIsTerminalWriter_Buffer(t *testing.T) {
	var buf bytes.Buffer
	assert.False(t, isTerminalWriter(&buf), "bytes.Buffer is not a terminal")
}

func TestIsTerminalWriter_File(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer f.Close()
	// A regular file is NOT a terminal.
	assert.False(t, isTerminalWriter(f), "a regular file is not a terminal")
}

// --- skipReasonLabel() additional coverage ---

func TestSkipReasonLabel_AllCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"system_namespace", "System namespaces"},
		{"risk_level", "Risk > allowed"},
		{"check_not_selected", "Check filtered"},
		{"severity_not_selected", "Severity filtered"},
		{"namespace_not_selected", "NS filtered"},
		{"namespace_excluded", "NS excluded"},
		{"unknown_reason", "unknown_reason"},
		{"something_else", "something_else"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, skipReasonLabel(tt.input))
		})
	}
}

// --- printFixSummary() additional coverage ---

func TestPrintFixSummary_WithBackupDir(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  5,
		FilesModified: 2,
		TotalFindings: 3,
		Applied:       3,
		Skipped:       0,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe: 3,
		},
		SkipReasons: map[string]int{},
		BackupDir:   "/tmp/kubevigil-backup-12345",
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, true, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "Backup: /tmp/kubevigil-backup-12345")
	assert.Contains(t, output, "To restore:")
}

func TestPrintFixSummary_WithErrors(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  5,
		FilesModified: 1,
		FilesFailed:   1,
		TotalFindings: 3,
		Applied:       2,
		Skipped:       1,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe: 2,
		},
		SkipReasons: map[string]int{"risk_level": 1},
		Errors: []fix.FileError{
			{FilePath: "bad.yaml", Err: "parse error: invalid yaml"},
		},
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, true, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "Errors:")
	assert.Contains(t, output, "bad.yaml")
	assert.Contains(t, output, "parse error: invalid yaml")
}

func TestPrintFixSummary_AppliedTrue(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  3,
		FilesModified: 1,
		TotalFindings: 2,
		Applied:       2,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe: 2,
		},
		SkipReasons: map[string]int{},
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, true, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "applied", "applied=true should say 'applied'")
	assert.NotContains(t, output, "will be applied")
}

func TestPrintFixSummary_DryRunNotApplied(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  3,
		FilesModified: 1,
		TotalFindings: 2,
		Applied:       2,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe: 2,
		},
		SkipReasons: map[string]int{},
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, false, fix.RiskLevelSafe)
	output := buf.String()

	assert.Contains(t, output, "will be applied", "applied=false should say 'will be applied'")
}

func TestPrintFixSummary_ModerateRiskLevel(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  5,
		FilesModified: 2,
		TotalFindings: 6,
		Applied:       5,
		Skipped:       1,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe:       3,
			checker.FixLikelySafe: 2,
		},
		SkipReasons: map[string]int{"risk_level": 1},
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, true, fix.RiskLevelModerate)
	output := buf.String()

	// At moderate, Likely safe should show applied count with "applied" action.
	assert.Contains(t, output, "Likely safe:")
	// Potentially breaking should show "skipped".
	assert.Contains(t, output, "Potentially breaking:")
	assert.Contains(t, output, "skipped")
}

func TestPrintFixSummary_AggressiveRiskLevel(t *testing.T) {
	summary := &fix.Summary{
		FilesScanned:  5,
		FilesModified: 3,
		TotalFindings: 8,
		Applied:       8,
		ByRisk: map[checker.FixSafety]int{
			checker.FixSafe:                3,
			checker.FixLikelySafe:          3,
			checker.FixPotentiallyBreaking: 2,
		},
		SkipReasons: map[string]int{},
	}

	var buf bytes.Buffer
	printFixSummary(&buf, summary, true, fix.RiskLevelAggressive)
	output := buf.String()

	// All three categories should show "applied", none should show "skipped".
	assert.Contains(t, output, "Safe:")
	assert.Contains(t, output, "Likely safe:")
	assert.Contains(t, output, "Potentially breaking:")
	// Count the word "applied" — should appear for all three risk tiers.
	appliedCount := strings.Count(output, "applied")
	assert.GreaterOrEqual(t, appliedCount, 3, "all three risk tiers should show 'applied'")
}

const helmManagedDeploymentYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: helm-web
  namespace: production
  labels:
    app.kubernetes.io/managed-by: Helm
    helm.sh/chart: web-1.0.0
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
`

func TestRunFix_HelmManagedWarning(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", helmManagedDeploymentYAML)

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunFix_KustomizeDetectWarning(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("resources:\n- deploy.yaml\n"), 0o644))

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunFix_GitPRAfterApply(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixApply = true
	flagFixYes = true
	flagFixGitPR = true
	flagFixBackupDir = filepath.Join(t.TempDir(), "backup-gitpr")

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Apply succeeds; git-pr may fail without gh — error is logged, not returned.
	assert.NoError(t, err)
}

// --- isInteractive() additional coverage ---

func TestIsInteractive_CI_Value1(t *testing.T) {
	t.Setenv("CI", "1")
	assert.False(t, isInteractive(), "CI=1 should not be interactive")
}

// Suppress unused import warnings.
var _ = io.Discard
var _ = fmt.Sprintf
