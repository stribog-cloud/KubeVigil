package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
	"github.com/stribog-cloud/kubevigil/internal/report"
)

func TestScanManifest_ImageChecks(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-image
  namespace: default
spec:
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
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(manifest), 0o644))

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	checkerIDs := collectCheckerIDs(result.Findings)
	assert.True(t, checkerIDs["image-tag-latest"], "should detect :latest tag")
	assert.True(t, checkerIDs["image-no-digest"], "should detect missing digest")
}

func TestScanManifest_RBACChecks(t *testing.T) {
	manifest := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "role.yaml"), []byte(manifest), 0o644))

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	checkerIDs := collectCheckerIDs(result.Findings)
	assert.True(t, checkerIDs["rbac-wildcard-verbs"], "should detect wildcard verbs")
	assert.True(t, checkerIDs["rbac-wildcard-resources"], "should detect wildcard resources")
	assert.True(t, checkerIDs["rbac-wildcard-apigroups"], "should detect wildcard API groups")
}

func TestScanManifest_NetworkChecks(t *testing.T) {
	manifest := `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: no-tls-ingress
  namespace: default
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web
            port:
              number: 80
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ingress.yaml"), []byte(manifest), 0o644))

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	checkerIDs := collectCheckerIDs(result.Findings)
	assert.True(t, checkerIDs["ingress-no-tls"], "should detect missing TLS on Ingress")
}

func TestScanManifest_CRDChecks(t *testing.T) {
	result, err := scanFixtureDir(t, "crd-validation-missing")
	require.NoError(t, err)

	checkerIDs := collectCheckerIDs(result.Findings)
	assert.True(t, checkerIDs["crd-validation-missing"], "should detect CRD without validation")
}

func TestScanManifest_FrameworksAttached(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: default
spec:
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
        image: nginx
        securityContext:
          privileged: true
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(manifest), 0o644))

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	// Framework attachment must work: a finding whose checker HAS a mapping
	// (privileged → CIS/MITRE/NSA) must carry those refs. Not every check maps
	// to a published control (e.g. Gateway API and ValidatingAdmissionPolicy
	// post-date the current CIS v1.8 / NSA reference versions), so we assert the
	// attachment mechanism on a mapped finding rather than demanding universal
	// coverage — fabricating control IDs to satisfy a blanket assertion would be
	// dishonest.
	var privileged *checker.Finding
	for i := range result.Findings {
		if result.Findings[i].Checker == "privileged" {
			privileged = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, privileged, "privileged finding should be present")
	assert.NotEmpty(t, privileged.Frameworks, "the privileged finding should have frameworks attached")
}

func TestScanManifest_FrameworkFilter(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: default
spec:
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
        image: nginx
        securityContext:
          privileged: true
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(manifest), 0o644))

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	// Filter by CIS.
	cisFindings := frameworks.FilterByFramework(result.Findings, "cis")
	assert.NotEmpty(t, cisFindings, "should have CIS-mapped findings")

	// All CIS findings should have at least one CIS ref.
	for i := range cisFindings {
		hasCIS := false
		for _, ref := range cisFindings[i].Frameworks {
			if ref.Framework == "cis" {
				hasCIS = true
				break
			}
		}
		assert.True(t, hasCIS, "CIS-filtered finding %q should have CIS ref", cisFindings[i].Checker)
	}
}

func TestScanManifest_AllReportFormats(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(manifest), 0o644))

	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)

	// Verify all report formats work with real scan data.
	for _, name := range report.Names() {
		t.Run(name, func(t *testing.T) {
			r, err := report.Get(name)
			require.NoError(t, err)
			var buf bytes.Buffer
			require.NoError(t, r.Generate(context.Background(), result, &buf))
			assert.NotEmpty(t, buf.String())
		})
	}
}

func collectCheckerIDs(findings []checker.Finding) map[string]bool {
	ids := make(map[string]bool)
	for i := range findings {
		ids[findings[i].Checker] = true
	}
	return ids
}

func scanFixtureDir(t *testing.T, fixtureDir string) (*checker.ScanResult, error) {
	t.Helper()
	cfg := config.Default()
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)
	path := filepath.Join("..", "..", "test", "fixtures", fixtureDir)
	return scanner.ScanManifest(context.Background(), path)
}
