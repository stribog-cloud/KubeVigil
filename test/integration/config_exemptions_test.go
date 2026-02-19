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

func TestConfigExemptions_NamespaceExemption(t *testing.T) {
	cfg := config.Default()
	cfg.Exemptions = []config.Exemption{
		{
			Namespace: "default",
			Reason:    "test namespace exemption",
		},
	}
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	// The privileged fixtures have resources in "default" namespace.
	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "default", f.Namespace,
			"findings in exempted namespace should be filtered: checker=%s resource=%s", f.Checker, f.Resource)
	}
}

func TestConfigExemptions_AnnotationExemption(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: skip-all-pod
  namespace: default
  annotations:
    kubevigil.io/skip: "*"
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "annotated.yaml"), []byte(manifest), 0o644)
	require.NoError(t, err)

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	// The kubevigil.io/skip: "*" annotation should suppress all findings for this pod.
	for _, f := range result.Findings {
		assert.NotEqual(t, "skip-all-pod", f.Resource,
			"annotated pod should have all findings skipped: checker=%s", f.Checker)
	}
}

func TestConfigExemptions_AnnotationSpecificCheck(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: skip-privileged-pod
  namespace: default
  annotations:
    kubevigil.io/skip: "privileged"
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "annotated-specific.yaml"), []byte(manifest), 0o644)
	require.NoError(t, err)

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	var hasNonPrivilegedFinding bool
	for _, f := range result.Findings {
		if f.Resource == "skip-privileged-pod" {
			// The "privileged" check should be skipped.
			assert.NotEqual(t, "privileged", f.Checker,
				"'privileged' check should be skipped via annotation")
			hasNonPrivilegedFinding = true
		}
	}

	// Other checks (e.g., capabilities-not-dropped, resource-limits-missing) should still fire.
	assert.True(t, hasNonPrivilegedFinding,
		"other findings should still be present for the annotated pod")
}

func TestConfigExemptions_CheckDisable(t *testing.T) {
	cfg := config.Default()
	cfg.Checks.Disabled = []string{"privileged"}
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "privileged", f.Checker,
			"disabled check should not produce findings")
	}

	// Other checks should still run and produce findings.
	assert.NotEmpty(t, result.Findings,
		"other checks should still produce findings on the privileged fixtures")
}
