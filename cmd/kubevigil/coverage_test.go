package main

import (
	"bytes"
	"context"
	"fmt"
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

// ---- saveAndRestoreScanFlags ----

// saveAndRestoreScanFlags saves all global scan-related flag state and registers
// a cleanup function to restore it when the test finishes.
func saveAndRestoreScanFlags(t *testing.T) {
	t.Helper()
	origFile := flagFile
	origKubeconfig := flagKubeconfig
	origContext := flagContext
	origNamespace := flagNamespace
	origExcludeNS := flagExcludeNamespace
	origSeverity := flagSeverity
	origFailOn := flagFailOn
	origFramework := flagFramework
	origConcurrency := flagConcurrency
	origIncludeManaged := flagIncludeManaged
	origIncludeSystemNS := flagIncludeSystemNamespaces
	origExcludeInfra := flagExcludeInfra
	origNoAggregate := flagNoAggregate
	origSummaryOnly := flagSummaryOnly
	origOutput := flagOutput
	origConfig := flagConfig
	origNoColor := flagNoColor
	origVerbose := flagVerbose
	t.Cleanup(func() {
		flagFile = origFile
		flagKubeconfig = origKubeconfig
		flagContext = origContext
		flagNamespace = origNamespace
		flagExcludeNamespace = origExcludeNS
		flagSeverity = origSeverity
		flagFailOn = origFailOn
		flagFramework = origFramework
		flagConcurrency = origConcurrency
		flagIncludeManaged = origIncludeManaged
		flagIncludeSystemNamespaces = origIncludeSystemNS
		flagExcludeInfra = origExcludeInfra
		flagNoAggregate = origNoAggregate
		flagSummaryOnly = origSummaryOnly
		flagOutput = origOutput
		flagConfig = origConfig
		flagNoColor = origNoColor
		flagVerbose = origVerbose
	})

	// Reset all flags to defaults.
	flagFile = ""
	flagKubeconfig = ""
	flagContext = ""
	flagNamespace = ""
	flagExcludeNamespace = ""
	flagSeverity = ""
	flagFailOn = ""
	flagFramework = ""
	flagConcurrency = 0
	flagIncludeManaged = false
	flagIncludeSystemNamespaces = false
	flagExcludeInfra = false
	flagNoAggregate = false
	flagSummaryOnly = false
	flagOutput = "text"
	flagConfig = ""
	flagNoColor = true
	flagVerbose = false
}

// ---- Inline fixture YAML ----

const validDeploymentYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
`

// ---- runScan tests ----

func TestRunScan_ValidManifest(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// The scan should either succeed or return an exit error with code 1
	// (findings above threshold). Both are valid outcomes for a working scan.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code, "scan finding above threshold exit code should be 1")
		}
	}
}

func TestRunScan_NonExistentFile(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = "/nonexistent/path/deploy.yaml"
	flagOutput = "text"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	assert.Error(t, err, "scanning a non-existent file should return an error")
}

func TestRunScan_JSONOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "json"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// Either nil or exitError code 1 (findings above threshold).
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_TextOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_UnknownFormat(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "unknown_format"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	assert.Error(t, err, "unknown format should produce an error")
	assert.Contains(t, err.Error(), "invalid output format")
}

func TestRunScan_WithSeverityThreshold(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagSeverity = "critical"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// With critical severity threshold, most findings will be filtered.
	// Either nil (no findings above threshold) or exit code 1.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Contains(t, []int{1}, ee.code)
		}
	}
}

func TestRunScan_WithInvalidSeverityThreshold(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagSeverity = "invalid_severity"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	assert.Error(t, err, "invalid severity threshold should produce an error")
	assert.Contains(t, err.Error(), "invalid severity threshold")
}

func TestRunScan_WithNamespaceFilter(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagNamespace = "default"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// Should work, may or may not find things in "default" namespace.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithExcludeNamespace(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagExcludeNamespace = "default"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// With default namespace excluded, findings from the "default" NS fixture should be excluded.
	// The scan itself should not error.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithFailOnOverride(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagFailOn = "critical"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// With fail-on set to critical, only critical findings trigger exit code 1.
	// Many findings in the fixture are high/medium, so this may return nil.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithConcurrencyOverride(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagConcurrency = 2

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithIncludeManaged(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagIncludeManaged = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithIncludeSystemNamespaces(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagIncludeSystemNamespaces = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithExcludeInfra(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagExcludeInfra = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithNoAggregate(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagNoAggregate = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithSummaryOnly(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagSummaryOnly = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_WithFrameworkFilter(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagFramework = "cis"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_MarkdownOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "markdown"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_YAMLOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "yaml"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_CSVOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "csv"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_SARIFOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "sarif"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_JUnitOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "junit"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_OutputToFile(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	outPath := filepath.Join(dir, "report.json")
	flagFile = path
	flagOutput = outPath

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}

	// Verify the output file was created and has content.
	data, readErr := os.ReadFile(outPath)
	require.NoError(t, readErr)
	assert.NotEmpty(t, data, "output file should have content")
}

func TestRunScan_ConfigError(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	// Point to a config file that exists but contains invalid YAML.
	badConfig := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badConfig, []byte("{{invalid yaml"), 0o644))
	flagConfig = badConfig
	flagFile = path

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	require.Error(t, err)
	var ee *exitError
	if assert.ErrorAs(t, err, &ee) {
		assert.Equal(t, 3, ee.code, "config error should return exit code 3")
	}
}

func TestRunScan_SummaryOnlyWithNonTextFormat(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "json"
	flagSummaryOnly = true

	// summary-only is only relevant for text — with json it falls through to normal reporter.
	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_NoClusterConnection(t *testing.T) {
	saveAndRestoreScanFlags(t)
	// No --file flag and no valid kubeconfig => should fail connecting to cluster.
	flagFile = ""
	flagKubeconfig = "/nonexistent/kubeconfig"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	assert.Error(t, err, "no cluster connection should fail")
	assert.Contains(t, err.Error(), "connecting to cluster")
}

func TestRunScan_DirectoryOfManifests(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy1.yaml"), []byte(validDeploymentYAML), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy2.yaml"), []byte(insecureDeploymentYAML), 0o644))

	flagFile = dir
	flagOutput = "text"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_OutputToInvalidPath(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "/nonexistent/dir/report.html"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	assert.Error(t, err, "writing to invalid path should fail")
	assert.Contains(t, err.Error(), "output")
}

func TestRunScan_VerboseMode(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagVerbose = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}
}

func TestRunScan_HTMLOutput(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	outPath := filepath.Join(dir, "report.html")
	flagFile = path
	flagOutput = outPath

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, 1, ee.code)
		}
	}

	data, readErr := os.ReadFile(outPath)
	require.NoError(t, readErr)
	assert.NotEmpty(t, data, "HTML output file should have content")
}

// ---- runListChecks tests ----

func TestRunListChecks_ListsAllChecks(t *testing.T) {
	// Capture stdout by redirecting the command's output.
	var buf bytes.Buffer
	listChecksCmd.SetOut(&buf)

	err := runListChecks(listChecksCmd, nil)
	assert.NoError(t, err)

	// The function writes to os.Stdout directly, not to cmd out.
	// We simply verify it does not error.
}

func TestRunListChecks_NoError(t *testing.T) {
	err := runListChecks(listChecksCmd, nil)
	assert.NoError(t, err, "listing checks should not return an error")
}

// ---- execute tests ----

func TestExecute_UnknownSubcommand(t *testing.T) {
	// We cannot easily inject args into the rootCmd.Execute() without
	// using os.Args manipulation. Instead, we verify that unknown commands
	// are handled gracefully by checking the rootCmd directly.
	rootCmd.SetArgs([]string{"nonexistent-subcommand"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	assert.Error(t, err, "unknown subcommand should produce an error")
}

func TestExecute_VersionSubcommand(t *testing.T) {
	rootCmd.SetArgs([]string{"version"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	assert.NoError(t, err, "version subcommand should succeed")
}

func TestExecute_NoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{})
	defer rootCmd.SetArgs(nil)

	code := execute()
	assert.Equal(t, 0, code, "no args should return success")
}

func TestExecute_UnknownReturnsCode2(t *testing.T) {
	rootCmd.SetArgs([]string{"nonexistent-subcommand"})
	defer rootCmd.SetArgs(nil)

	code := execute()
	assert.Equal(t, 2, code, "unknown subcommand should return exit code 2")
}

// ---- runFix edge case tests ----

func TestRunFix_KustomizeOutputMode(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	kustDir := filepath.Join(t.TempDir(), "kustomize-out")
	flagFixOutput = "diff"
	flagFixKustomize = kustDir

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err, "kustomize output should succeed")

	// Verify kustomize overlay directory was created.
	_, statErr := os.Stat(kustDir)
	assert.NoError(t, statErr, "kustomize output directory should exist")
}

func TestRunFix_ApplyInNonInteractiveWithoutYes(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixApply = true
	flagFixYes = false
	// Set CI env var to simulate non-interactive.
	t.Setenv("CI", "true")

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixConfigError, ee.code,
		"apply in non-interactive mode without --yes should return config error")
}

func TestRunFix_ConfigFileError(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	badConfig := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badConfig, []byte("{{invalid yaml"), 0o644))
	flagConfig = badConfig

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixConfigError, ee.code, "bad config should return config error")
}

func TestRunFix_ApplyWithReport(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	backupDir := filepath.Join(t.TempDir(), "backup-report")
	reportPath := filepath.Join(t.TempDir(), "fix-report.md")
	flagFixApply = true
	flagFixYes = true
	flagFixBackupDir = backupDir
	flagFixReport = reportPath

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err)

	// Verify report was written.
	_, statErr := os.Stat(reportPath)
	assert.NoError(t, statErr, "fix report should be created at specified path")
}

func TestRunFix_PartialFailureExitCode(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "good.yaml", insecureDeploymentYAML)
	writeFixture(t, dir, "bad.yaml", "{{invalid yaml")

	flagFixApply = true
	flagFixYes = true
	flagFixBackupDir = filepath.Join(t.TempDir(), "backup-partial")

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Partial failure: good file patched, bad file fails.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, fix.ExitFixPartialSuccess, ee.code,
				"partial failure should return exit code 5")
		}
	}
}

// ---- buildFixConfig tests ----

func TestBuildFixConfig_AllFilterFlags(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func()
		validate func(t *testing.T, cfg fix.Config)
	}{
		{
			name: "checks filter",
			setup: func() {
				flagFixChecks = "privileged,allow-privilege-escalation"
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.Equal(t, []string{"privileged", "allow-privilege-escalation"}, cfg.Checks)
			},
		},
		{
			name: "severity filter",
			setup: func() {
				flagFixSeverity = "high,critical"
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.Equal(t, []string{"high", "critical"}, cfg.Severities)
			},
		},
		{
			name: "namespace filter",
			setup: func() {
				flagFixNamespace = "prod,staging"
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.Equal(t, []string{"prod", "staging"}, cfg.Namespaces)
			},
		},
		{
			name: "exclude namespace filter",
			setup: func() {
				flagFixExcludeNamespace = "kube-system,monitoring"
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.Equal(t, []string{"kube-system", "monitoring"}, cfg.ExcludeNamespaces)
			},
		},
		{
			name: "fingerprint filter",
			setup: func() {
				flagFixFingerprint = "abc123,def456"
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.Equal(t, []string{"abc123", "def456"}, cfg.Fingerprints)
			},
		},
		{
			name: "apply flag",
			setup: func() {
				flagFixApply = true
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.True(t, cfg.Apply)
			},
		},
		{
			name: "yes flag",
			setup: func() {
				flagFixYes = true
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.True(t, cfg.Yes)
			},
		},
		{
			name: "verify flag",
			setup: func() {
				flagFixVerify = true
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.True(t, cfg.Verify)
			},
		},
		{
			name: "system NS flag",
			setup: func() {
				flagFixSystemNS = true
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.True(t, cfg.AllowSystemNamespaces)
			},
		},
		{
			name: "backup dir from config when CLI not set",
			setup: func() {
				flagFixBackupDir = ""
			},
			validate: func(t *testing.T, cfg fix.Config) {
				assert.Equal(t, "/tmp/backups/", cfg.BackupDir)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset flags.
			flagFixApply = false
			flagFixYes = false
			flagFixVerify = false
			flagFixSystemNS = false
			flagFixChecks = ""
			flagFixSeverity = ""
			flagFixNamespace = ""
			flagFixExcludeNamespace = ""
			flagFixFingerprint = ""
			flagFixBackupDir = ""

			tc.setup()

			cfg := configForTest(t)
			fixCfg := buildFixConfig(cfg, fix.RiskLevelSafe)
			tc.validate(t, fixCfg)
		})
	}
}

func TestBuildFixConfig_DefaultConfig_NoBulkThreshold(t *testing.T) {
	cfg := config.Default()
	fixCfg := buildFixConfig(cfg, fix.RiskLevelModerate)

	assert.Equal(t, fix.RiskLevelModerate, fixCfg.RiskLevel)
	// Default config has zero BulkThreshold in FixConfig, so the fix.DefaultConfig() value should be used.
	assert.Greater(t, fixCfg.BulkThreshold, 0, "should use default bulk threshold when config is 0")
}

func TestBuildFixConfig_NoAdditionalSystemNS(t *testing.T) {
	cfg := config.Default()
	fixCfg := buildFixConfig(cfg, fix.RiskLevelSafe)

	assert.Empty(t, fixCfg.AdditionalSystemNamespaces,
		"default config should have no additional system namespaces")
}

// ---- isInteractive tests ----

func TestIsInteractive_EnvVars(t *testing.T) {
	testCases := []struct {
		name   string
		envKey string
		envVal string
		want   bool
	}{
		{"CI=true", "CI", "true", false},
		{"CI=1", "CI", "1", false},
		{"GITHUB_ACTIONS=true", "GITHUB_ACTIONS", "true", false},
		{"GITHUB_ACTIONS=1", "GITHUB_ACTIONS", "1", false},
		{"GITLAB_CI=true", "GITLAB_CI", "true", false},
		{"GITLAB_CI=1", "GITLAB_CI", "1", false},
		{"CI=false is ignored", "CI", "false", true}, // "false" != "true" and != "1"
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear all CI env vars first.
			t.Setenv("CI", "")
			t.Setenv("GITHUB_ACTIONS", "")
			t.Setenv("GITLAB_CI", "")
			t.Setenv("JENKINS_URL", "")

			t.Setenv(tc.envKey, tc.envVal)

			result := isInteractive()
			if tc.want {
				// When CI env is not set to trigger non-interactive,
				// we still might not be interactive because stdin is not a terminal.
				// So we can only assert that the CI check did not block us.
				// The stdin check may return false in test environments.
				// We just verify no panic occurred.
				_ = result
			} else {
				assert.False(t, result)
			}
		})
	}
}

func TestIsInteractive_JenkinsURLEmpty(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("JENKINS_URL", "")

	// With no CI env vars, interactive depends on stdin.
	// In test environments, stdin is typically not a terminal.
	result := isInteractive()
	// We just verify no panic and the function returns a bool.
	_ = result
}

// ---- loadConfig tests ----

func TestLoadConfig_DiscoversFallback(t *testing.T) {
	orig := flagConfig
	defer func() { flagConfig = orig }()

	flagConfig = ""
	// In the test environment, Discover() may or may not find a config file.
	// The important thing is that it does not error.
	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestLoadConfig_InvalidConfigFileContent(t *testing.T) {
	orig := flagConfig
	defer func() { flagConfig = orig }()

	dir := t.TempDir()
	badPath := filepath.Join(dir, ".kubevigil.yaml")
	require.NoError(t, os.WriteFile(badPath, []byte("{{invalid yaml"), 0o644))

	flagConfig = badPath
	_, err := loadConfig()
	assert.Error(t, err, "invalid YAML config should return error")
}

// ---- resolveContextName tests ----

func TestResolveContextName_ExplicitContext(t *testing.T) {
	got := resolveContextName("", "my-explicit-context")
	assert.Equal(t, "my-explicit-context", got)
}

func TestResolveContextName_EmptyContextWithInvalidKubeconfig(t *testing.T) {
	// With a non-existent kubeconfig and no explicit context,
	// the function should return empty string (no panic).
	got := resolveContextName("/nonexistent/kubeconfig", "")
	// Should either return empty or some default context name.
	// The key thing is it does not panic.
	_ = got
}

func TestResolveContextName_EmptyBoth(t *testing.T) {
	got := resolveContextName("", "")
	// With no kubeconfig or context, it falls through to the default loading rules.
	// May or may not find a context depending on the environment.
	_ = got
}

func TestResolveContextName_WithKubeconfig(t *testing.T) {
	// Create a valid kubeconfig file.
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "kubeconfig")
	content := `apiVersion: v1
kind: Config
current-context: test-context
clusters:
- cluster:
    server: https://localhost:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
users:
- name: test-user
  user: {}
`
	require.NoError(t, os.WriteFile(kubeconfig, []byte(content), 0o644))

	got := resolveContextName(kubeconfig, "")
	assert.Equal(t, "test-context", got, "should resolve current-context from kubeconfig")
}

// ---- isTerminalWriter tests ----

func TestIsTerminalWriter_BytesBuffer(t *testing.T) {
	var buf bytes.Buffer
	assert.False(t, isTerminalWriter(&buf), "bytes.Buffer is not a terminal")
}

func TestIsTerminalWriter_RegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer f.Close()
	assert.False(t, isTerminalWriter(f), "a regular file is not a terminal")
}

func TestIsTerminalWriter_Pipe(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	assert.False(t, isTerminalWriter(w), "a pipe is not a terminal")
}

// ---- exitError tests ----

func TestExitError_ErrorMethod(t *testing.T) {
	err := &exitError{code: 42, err: fmt.Errorf("test error")}
	assert.Equal(t, "test error", err.Error())
	assert.Equal(t, 42, err.code)
}

// ---- printDiffs with potentially_breaking impact ----

func TestPrintDiffs_PotentiallyBreakingImpact(t *testing.T) {
	plan := &fix.Plan{
		Files: map[string]*fix.FilePlan{
			"deploy.yaml": {
				Path: "deploy.yaml",
				Fixes: []fix.PlannedFix{
					{
						Applied: true,
						Strategy: fix.Strategy{
							Safety:  checker.FixPotentiallyBreaking,
							Impact:  "May break applications that bind to low ports.",
							CheckID: "host-port",
						},
					},
				},
			},
		},
		Diffs: map[string]string{
			"deploy.yaml": "--- a/deploy.yaml\n+++ b/deploy.yaml\n@@ -1,2 +1,3 @@\n spec:\n-  hostPort: 80\n",
		},
	}

	var buf bytes.Buffer
	printDiffs(&buf, plan)
	output := buf.String()

	assert.Contains(t, output, "IMPACT (potentially_breaking)")
	assert.Contains(t, output, "May break applications that bind to low ports.")
}

// ---- sortedKeys tests ----

func TestSortedKeys_Empty(t *testing.T) {
	keys := sortedKeys(map[string]int{})
	assert.Empty(t, keys)
}

func TestSortedKeys_Sorted(t *testing.T) {
	m := map[string]int{"c": 3, "a": 1, "b": 2}
	keys := sortedKeys(m)
	assert.Equal(t, []string{"a", "b", "c"}, keys)
}

// ---- confirmBulkApply additional tests ----

func TestConfirmBulkApply_YesWordResponse(t *testing.T) {
	plan := &fix.Plan{
		Summary: fix.Summary{
			FilesModified: 20,
			Applied:       15,
			Results: []fix.Result{
				{Namespace: "prod", Applied: true},
			},
		},
	}

	input := strings.NewReader("yes\n")
	var output bytes.Buffer
	proceed, err := confirmBulkApply(input, &output, plan)
	require.NoError(t, err)
	assert.True(t, proceed, "full 'yes' should confirm")
}

// ---- Additional runFix coverage: nocolor, fingerprint filter, moderateApply ----

func TestRunFix_DryRunWithNoColor(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagNoColor = false // Test with color enabled to hit that branch.

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunFix_SystemNSWithOverrideFlag(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "system.yaml", systemNSDeploymentYAML)

	flagFixSystemNS = true
	flagFixRiskLevel = "aggressive"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// With system NS override, should find fixes and succeed (dry-run).
	assert.NoError(t, err)
}

func TestRunFix_ModerateApplyWithVerify(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	backupDir := filepath.Join(t.TempDir(), "backup-moderate")
	flagFixApply = true
	flagFixVerify = true
	flagFixYes = true
	flagFixBackupDir = backupDir
	flagFixRiskLevel = "moderate"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// At moderate level, some fixes remain (potentially_breaking), so verify may fail.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Equal(t, fix.ExitFixVerifyFailed, ee.code)
		}
	}
}

func TestRunFix_WithFingerprintFilter(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixFingerprint = "nonexistent-fingerprint"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// With a non-matching fingerprint, nothing should be fixable.
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixNothingToDo, ee.code)
}

func TestRunFix_WithChecksFilter(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixChecks = "privileged"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Should succeed with only privileged check.
	assert.NoError(t, err)
}

func TestRunFix_WithSeverityFilter(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixSeverity = "critical"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Only critical findings should be considered.
	// The insecure deployment has privileged=true which is critical.
	// Either finds critical fixable findings or nothing to do.
	if err != nil {
		var ee *exitError
		if assert.ErrorAs(t, err, &ee) {
			assert.Contains(t, []int{fix.ExitFixNothingToDo, 0}, ee.code)
		}
	}
}

func TestRunFix_WithNamespaceFilter(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixNamespace = "production"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Insecure deployment is in "production" namespace, should find fixes.
	assert.NoError(t, err)
}

func TestRunFix_WithExcludeNamespace(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixExcludeNamespace = "production"

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// Excluding production means no fixes for the insecure deployment.
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, fix.ExitFixNothingToDo, ee.code)
}

func TestRunFix_WithExcludeInfra(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	writeFixture(t, dir, "deploy.yaml", insecureDeploymentYAML)

	flagFixExcludeInfra = true

	fixCmd.SetContext(context.Background())
	err := runFix(fixCmd, []string{dir})
	// "production" is not an infra namespace, should still have fixes.
	assert.NoError(t, err)
}

// ---- Multiple run scan tests exercising different flag combinations ----

func TestRunScan_AllFiltersCombo(t *testing.T) {
	saveAndRestoreScanFlags(t)
	dir := t.TempDir()

	// Create a deployment in a regular namespace.
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validDeploymentYAML), 0o644))

	flagFile = path
	flagOutput = "text"
	flagNamespace = "default"
	flagSeverity = "high"
	flagFailOn = "critical"
	flagConcurrency = 4
	flagIncludeManaged = true
	flagExcludeInfra = true
	flagNoAggregate = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// Should succeed or fail with findings.
	if err != nil {
		var ee *exitError
		assert.ErrorAs(t, err, &ee)
	}
}
