package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/k8s"

	// Register all workload checkers.
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

func TestScanManifest_FixtureDir(t *testing.T) {
	cfg := config.Default()
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Findings, "should produce findings from privileged fixtures")
	assert.Equal(t, checker.ScanModeManifest, result.ScanMeta.ScanMode)
	assert.Greater(t, result.ScanMeta.ChecksRun, 0)
	assert.True(t, result.ScanMeta.Duration > 0)
}

func TestScanManifest_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), dir)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestScanManifest_BadPath(t *testing.T) {
	cfg := config.Default()
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	_, err := scanner.ScanManifest(context.Background(), "/nonexistent/path/xyz")
	require.Error(t, err)
}

func TestScanManifestWithinRoot_RejectsOutsideWorkspace(t *testing.T) {
	cfg := config.Default()
	scanner := NewScanner(checker.DefaultRegistry(), cfg)
	root := t.TempDir()

	_, err := scanner.ScanManifestWithinRoot(context.Background(), "/etc/passwd", root)
	require.Error(t, err)
}

func TestScanManifestWithinRoot_ScansInsideWorkspace(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pod.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: c
    image: nginx
    securityContext:
      privileged: true
`), 0o644))

	cfg := config.Default()
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifestWithinRoot(context.Background(), manifest, root)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Findings, "should produce findings from confined manifest")
	assert.Equal(t, checker.ScanModeManifest, result.ScanMeta.ScanMode)
}

func TestScanManifest_DisabledChecks(t *testing.T) {
	cfg := config.Default()
	cfg.Checks.Disabled = []string{"privileged"}
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "privileged", f.Checker, "disabled checker should not produce findings")
	}
	assert.Greater(t, result.ScanMeta.ChecksSkipped, 0, "should report skipped checks")
}

func TestScanManifest_SeverityOverride(t *testing.T) {
	cfg := config.Default()
	cfg.Checks.Overrides = map[string]config.CheckOverride{
		"privileged": {Severity: "low"},
	}
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	for _, f := range result.Findings {
		if f.Checker == "privileged" {
			assert.Equal(t, checker.SeverityLow, f.Severity, "severity should be overridden to low")
		}
	}
}

func TestScanManifest_NamespaceExemption(t *testing.T) {
	cfg := config.Default()
	cfg.Exemptions = []config.Exemption{
		{
			Namespace: "default",
			Reason:    "test exemption",
		},
	}
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanManifest(context.Background(), "../../test/fixtures/privileged")
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotEqual(t, "default", f.Namespace, "exempted namespace should have no findings")
	}
}

func TestScanManifest_AnnotationExemption(t *testing.T) {
	// Create a cache with an annotated resource.
	cache := checker.NewResourceCache()
	pod := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
			"annotations": map[string]interface{}{
				"kubevigil.io/skip": "*",
			},
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "test",
					"image": "nginx",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	}}
	cache.Add(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, *pod)

	// Build annotations map.
	annotations := collectAnnotations(cache)
	assert.NotEmpty(t, annotations, "should have annotation entries")

	// Create a finding that matches the pod.
	finding := checker.Finding{
		Checker:   "privileged",
		Resource:  "test-pod",
		Namespace: "default",
		Kind:      "Pod",
	}

	key := config.ExemptionKey("default", "Pod", "test-pod")
	assert.True(t, config.IsExempt(nil, &finding, annotations[key]), "annotated resource should be exempt")
}

func TestEnabledChecks_FiltersByMode(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{
		name:  "live-only",
		modes: []checker.ScanMode{checker.ScanModeLive},
	})
	reg.MustRegister(&fakeChecker{
		name:  "manifest-only",
		modes: []checker.ScanMode{checker.ScanModeManifest},
	})
	reg.MustRegister(&fakeChecker{
		name:  "both-modes",
		modes: []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest},
	})

	scanner := NewScanner(reg, config.Default())

	manifest := scanner.enabledChecks(checker.ScanModeManifest)
	names := checkerNames(manifest)
	assert.Contains(t, names, "manifest-only")
	assert.Contains(t, names, "both-modes")
	assert.NotContains(t, names, "live-only")

	live := scanner.enabledChecks(checker.ScanModeLive)
	names = checkerNames(live)
	assert.Contains(t, names, "live-only")
	assert.Contains(t, names, "both-modes")
	assert.NotContains(t, names, "manifest-only")
}

func TestCollectGVRs_Deduplication(t *testing.T) {
	podGVR := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	checks := []checker.Checker{
		&fakeChecker{name: "a", gvrs: []schema.GroupVersionResource{podGVR, deployGVR}},
		&fakeChecker{name: "b", gvrs: []schema.GroupVersionResource{podGVR}},
	}

	gvrs := collectGVRs(checks)
	assert.Len(t, gvrs, 2, "should deduplicate GVRs")
	assert.Contains(t, gvrs, podGVR)
	assert.Contains(t, gvrs, deployGVR)
}

func TestRunChecks_ConcurrentNoRace(t *testing.T) {
	reg := checker.NewRegistry()
	for i := 0; i < 10; i++ {
		reg.MustRegister(&fakeChecker{
			name:  fmt.Sprintf("check-%d", i),
			modes: []checker.ScanMode{checker.ScanModeManifest},
			findings: []checker.Finding{
				{Checker: fmt.Sprintf("check-%d", i), Message: "test"},
			},
		})
	}

	scanner := NewScanner(reg, config.Default())
	cache := checker.NewResourceCache()

	checks := scanner.enabledChecks(checker.ScanModeManifest)
	findings, errCount := scanner.runChecks(context.Background(), checks, cache)

	assert.Len(t, findings, 10)
	assert.Equal(t, 0, errCount)
}

func TestRunChecks_ErrorNonFatal(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{
		name:  "good",
		modes: []checker.ScanMode{checker.ScanModeManifest},
		findings: []checker.Finding{
			{Checker: "good", Message: "found"},
		},
	})
	reg.MustRegister(&fakeChecker{
		name:   "bad",
		modes:  []checker.ScanMode{checker.ScanModeManifest},
		runErr: errors.New("checker failed"),
	})

	scanner := NewScanner(reg, config.Default())
	cache := checker.NewResourceCache()

	checks := scanner.enabledChecks(checker.ScanModeManifest)
	findings, errCount := scanner.runChecks(context.Background(), checks, cache)

	assert.Len(t, findings, 1)
	assert.Equal(t, "good", findings[0].Checker)
	assert.Equal(t, 1, errCount)
}

func TestFilterByAvailableGVRs(t *testing.T) {
	podGVR := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	checks := []checker.Checker{
		&fakeChecker{name: "needs-pods", gvrs: []schema.GroupVersionResource{podGVR}},
		&fakeChecker{name: "needs-deploys", gvrs: []schema.GroupVersionResource{deployGVR}},
		&fakeChecker{name: "needs-both", gvrs: []schema.GroupVersionResource{podGVR, deployGVR}},
	}

	skipped := []k8s.SkippedResource{
		{GVR: deployGVR, Error: errors.New("forbidden")},
	}

	filtered, removed := filterByAvailableGVRs(checks, skipped)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "needs-pods", filtered[0].Name())
	assert.Equal(t, 2, removed)
}

func TestFilterByAvailableGVRs_NoSkipped(t *testing.T) {
	checks := []checker.Checker{
		&fakeChecker{name: "a"},
		&fakeChecker{name: "b"},
	}

	filtered, removed := filterByAvailableGVRs(checks, nil)
	assert.Len(t, filtered, 2)
	assert.Equal(t, 0, removed)
}

func TestCollectAnnotations(t *testing.T) {
	cache := checker.NewResourceCache()

	pod := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "annotated-pod",
			"namespace": "ns1",
			"annotations": map[string]interface{}{
				"kubevigil.io/skip": "privileged",
			},
		},
	}}
	cache.Add(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, pod)

	plain := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "plain-pod",
			"namespace": "ns1",
		},
	}}
	cache.Add(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, plain)

	annotations := collectAnnotations(cache)
	key := config.ExemptionKey("ns1", "Pod", "annotated-pod")
	assert.Contains(t, annotations, key)
	assert.Equal(t, "privileged", annotations[key]["kubevigil.io/skip"])

	plainKey := config.ExemptionKey("ns1", "Pod", "plain-pod")
	assert.NotContains(t, annotations, plainKey, "pods without annotations should not be in the map")
}

// --- Helpers ---

func checkerNames(checks []checker.Checker) []string {
	names := make([]string, len(checks))
	for i, c := range checks {
		names[i] = c.Name()
	}
	return names
}

// fakeChecker is a test double for the Checker interface.
type fakeChecker struct {
	name     string
	modes    []checker.ScanMode
	gvrs     []schema.GroupVersionResource
	findings []checker.Finding
	runErr   error
}

func (f *fakeChecker) Name() string        { return f.name }
func (f *fakeChecker) Description() string { return "fake " + f.name }
func (f *fakeChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}
func (f *fakeChecker) SupportedModes() []checker.ScanMode               { return f.modes }
func (f *fakeChecker) RequiredResources() []schema.GroupVersionResource { return f.gvrs }

func (f *fakeChecker) Run(ctx context.Context, _ *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.runErr != nil {
		return nil, f.runErr
	}
	return f.findings, nil
}
