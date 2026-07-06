package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

const validPolicyYAML = `version: v1
policies:
  - id: require-team-label
    name: Workloads must have a team label
    severity: medium
    category: workload
    message: missing team label
    remediation: add a team label
    expression: '!has(object.metadata.labels) || !("team" in object.metadata.labels)'
    match:
      kinds: [Deployment]
`

const invalidPolicyYAML = `version: v1
policies:
  - id: broken
    severity: low
    expression: 'object.spec.replicas <'
`

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

// ---- policy command ----

func TestRunPolicyValidate_Valid(t *testing.T) {
	path := writeTemp(t, "pol.yaml", validPolicyYAML)
	assert.NoError(t, runPolicyValidate(policyValidateCmd, []string{path}))
}

func TestRunPolicyValidate_InvalidCEL(t *testing.T) {
	path := writeTemp(t, "pol.yaml", invalidPolicyYAML)
	err := runPolicyValidate(policyValidateCmd, []string{path})
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code)
}

func TestRunPolicyValidate_MissingFile(t *testing.T) {
	err := runPolicyValidate(policyValidateCmd, []string{"/nonexistent/pol.yaml"})
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code)
}

func TestRunPolicyValidate_Directory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(validPolicyYAML), 0o644))
	assert.NoError(t, runPolicyValidate(policyValidateCmd, []string{dir}))
}

func TestRunPolicyList(t *testing.T) {
	path := writeTemp(t, "pol.yaml", validPolicyYAML)
	assert.NoError(t, runPolicyList(policyListCmd, []string{path}))
}

func TestRunPolicyList_Error(t *testing.T) {
	err := runPolicyList(policyListCmd, []string{"/nonexistent"})
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code)
}

// ---- scan --policy-file ----

func TestRunScan_WithPolicyFile(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagPolicyFile = writeTemp(t, "pol.yaml", validPolicyYAML)
	flagOutput = "json"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	// Findings exist (privileged fixture) → exit error code 1 is the success shape.
	if err != nil {
		var ee *exitError
		require.ErrorAs(t, err, &ee)
		assert.Equal(t, 1, ee.code)
	}
}

func TestRunScan_PolicyFileRepeatedScansDoNotCollide(t *testing.T) {
	// Regression: custom policies must never be registered into the shared
	// DefaultRegistry singleton — a second in-process scan with the same
	// policy file used to fail with a duplicate-registration error.
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagPolicyFile = writeTemp(t, "pol.yaml", validPolicyYAML)
	flagOutput = "json"

	for i := 0; i < 2; i++ {
		scanCmd.SetContext(context.Background())
		err := runScan(scanCmd, nil)
		if err != nil {
			var ee *exitError
			require.ErrorAs(t, err, &ee, "scan %d", i)
			require.Equal(t, 1, ee.code, "scan %d must not fail with a policy registration error", i)
		}
	}
	// And the shared registry must not have absorbed the custom policy.
	for _, c := range checker.DefaultRegistry().All() {
		require.NotEqual(t, "require-team-label", c.Name(), "custom policy leaked into DefaultRegistry")
	}
}

func TestRunScan_WithBadPolicyFile(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagPolicyFile = writeTemp(t, "pol.yaml", invalidPolicyYAML)

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code, "bad CEL policy is a config error")
}

func TestRunScan_PolicyFileMissing(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagPolicyFile = "/nonexistent/pol.yaml"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code)
}

// ---- baseline flags ----

func TestRunScan_SaveBaselineThenFailOnNew(t *testing.T) {
	saveAndRestoreScanFlags(t)
	manifest := writeTemp(t, "deploy.yaml", validDeploymentYAML)
	basePath := filepath.Join(t.TempDir(), "baseline.json")

	// 1. Save baseline: exits nil even though findings exist.
	flagFile = manifest
	flagSaveBaseline = basePath
	scanCmd.SetContext(context.Background())
	require.NoError(t, runScan(scanCmd, nil))
	require.FileExists(t, basePath)

	// 2. Rescan with baseline + fail-on-new: nothing new → nil.
	flagSaveBaseline = ""
	flagBaseline = basePath
	flagFailOnNew = true
	scanCmd.SetContext(context.Background())
	assert.NoError(t, runScan(scanCmd, nil))
}

func TestRunScan_FailOnNewDetectsNewFindings(t *testing.T) {
	saveAndRestoreScanFlags(t)
	// Baseline from an EMPTY manifest set, then scan a violating manifest:
	// every finding is new → exit 1.
	emptyDir := t.TempDir()
	basePath := filepath.Join(t.TempDir(), "baseline.json")

	flagFile = emptyDir
	flagSaveBaseline = basePath
	scanCmd.SetContext(context.Background())
	require.NoError(t, runScan(scanCmd, nil))

	flagSaveBaseline = ""
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagBaseline = basePath
	flagFailOnNew = true
	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 1, ee.code, "new findings vs baseline must exit 1")
}

func TestRunScan_SaveBaselineConflictsWithBaseline(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagSaveBaseline = filepath.Join(t.TempDir(), "b.json")
	flagBaseline = writeTemp(t, "existing.json", `{"version":"v1","fingerprints":[]}`)

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code, "--save-baseline + --baseline is a config error")
}

func TestRunScan_BadCustomPoliciesInConfigRejectedAtLoad(t *testing.T) {
	saveAndRestoreScanFlags(t)
	cfgPath := writeTemp(t, ".kubevigil.yaml", `version: "1"
customPolicies:
  - id: bad
    severity: not-a-severity
    expression: 'true'
`)
	flagConfig = cfgPath
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code, "bad customPolicies severity is a config-load error")
}

func TestRunScan_FailOnNewRequiresBaseline(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagFailOnNew = true

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code, "--fail-on-new without --baseline is a config error")
}

func TestRunScan_BaselineFileMissing(t *testing.T) {
	saveAndRestoreScanFlags(t)
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagBaseline = "/nonexistent/baseline.json"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	var ee *exitError
	require.ErrorAs(t, err, &ee)
	assert.Equal(t, 3, ee.code)
}

// ---- config customPolicies path ----

func TestRunScan_CustomPoliciesFromConfig(t *testing.T) {
	saveAndRestoreScanFlags(t)
	cfgPath := writeTemp(t, ".kubevigil.yaml", `version: "1"
customPolicies:
  - id: cfg-policy
    name: from config
    severity: low
    expression: 'true'
    match:
      kinds: [Deployment]
`)
	flagConfig = cfgPath
	flagFile = writeTemp(t, "deploy.yaml", validDeploymentYAML)
	flagOutput = "json"

	scanCmd.SetContext(context.Background())
	err := runScan(scanCmd, nil)
	if err != nil {
		var ee *exitError
		require.ErrorAs(t, err, &ee)
		assert.Equal(t, 1, ee.code)
	}
}
