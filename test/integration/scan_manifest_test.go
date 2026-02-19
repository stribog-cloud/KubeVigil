package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
)

func TestScanManifest_FullPipeline(t *testing.T) {
	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	// Should produce findings from the privileged fixtures.
	assert.NotEmpty(t, result.Findings, "should produce findings from privileged fixtures")

	// At least one finding should be from the "privileged" checker.
	var hasPrivileged bool
	for _, f := range result.Findings {
		if f.Checker == "privileged" {
			hasPrivileged = true
			break
		}
	}
	assert.True(t, hasPrivileged, "should have at least one 'privileged' finding")

	// Scan metadata should be populated.
	assert.Greater(t, result.ScanMeta.ChecksRun, 0, "should report checks run")
	assert.Equal(t, checker.ScanModeManifest, result.ScanMeta.ScanMode)
	assert.True(t, result.ScanMeta.Duration > 0, "duration should be positive")
}

func TestScanManifest_MultipleCheckFindings(t *testing.T) {
	// Create a temp YAML that triggers multiple checkers.
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
  namespace: default
spec:
  selector:
    matchLabels:
      app: insecure
  template:
    metadata:
      labels:
        app: insecure
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
`
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "insecure.yaml"), []byte(manifest), 0o644)
	require.NoError(t, err)

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	// Collect unique checker IDs from findings.
	checkerIDs := make(map[string]bool)
	for _, f := range result.Findings {
		checkerIDs[f.Checker] = true
	}

	// This insecure deployment should trigger multiple checkers.
	assert.True(t, checkerIDs["privileged"], "should detect privileged container")
	assert.True(t, checkerIDs["resource-limits-missing"], "should detect missing resource limits")
	assert.True(t, checkerIDs["resource-requests-missing"], "should detect missing resource requests")
	assert.True(t, checkerIDs["capabilities-not-dropped"], "should detect capabilities not dropped")
	assert.True(t, checkerIDs["read-only-rootfs"], "should detect missing readOnlyRootFilesystem")
	assert.True(t, checkerIDs["privilege-escalation"], "should detect missing allowPrivilegeEscalation: false")

	// Verify more than one unique checker triggered.
	assert.Greater(t, len(checkerIDs), 3, "should trigger findings from multiple checkers")
}

func TestScanManifest_SecureResource(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
        ephemeral-storage: "1Gi"
      requests:
        cpu: "50m"
        memory: "64Mi"
`
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "secure.yaml"), []byte(manifest), 0o644)
	require.NoError(t, err)

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	// Collect checker IDs from findings.
	checkerIDs := make(map[string]bool)
	for _, f := range result.Findings {
		checkerIDs[f.Checker] = true
	}

	// Critical/high security checks should NOT fire on this secure pod.
	assert.False(t, checkerIDs["privileged"], "secure pod should not trigger 'privileged'")
	assert.False(t, checkerIDs["run-as-root"], "secure pod should not trigger 'run-as-root'")
	assert.False(t, checkerIDs["capabilities-not-dropped"], "secure pod should not trigger 'capabilities-not-dropped'")
	assert.False(t, checkerIDs["resource-limits-missing"], "secure pod should not trigger 'resource-limits-missing'")
	assert.False(t, checkerIDs["resource-requests-missing"], "secure pod should not trigger 'resource-requests-missing'")
	assert.False(t, checkerIDs["read-only-rootfs"], "secure pod should not trigger 'read-only-rootfs'")
	assert.False(t, checkerIDs["privilege-escalation"], "secure pod should not trigger 'privilege-escalation'")
	assert.False(t, checkerIDs["seccomp-profile"], "secure pod should not trigger 'seccomp-profile'")
}

func TestScanManifest_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)
	assert.Empty(t, result.Findings, "empty directory should produce no findings")
}

func TestScanManifest_WithDisabledChecks(t *testing.T) {
	cfg := config.Default()
	cfg.Checks.Disabled = []string{"privileged"}
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "privileged", f.Checker, "disabled checker should not produce findings")
	}
	assert.Greater(t, result.ScanMeta.ChecksSkipped, 0, "should report skipped checks")
}

func TestScanManifest_WithSeverityOverride(t *testing.T) {
	cfg := config.Default()
	cfg.Checks.Overrides = map[string]config.CheckOverride{
		"privileged": {Severity: "low"},
	}
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	var foundPrivileged bool
	for _, f := range result.Findings {
		if f.Checker == "privileged" {
			foundPrivileged = true
			assert.Equal(t, checker.SeverityLow, f.Severity,
				"privileged severity should be overridden to low")
		}
	}
	assert.True(t, foundPrivileged, "should have at least one privileged finding to verify override")
}
