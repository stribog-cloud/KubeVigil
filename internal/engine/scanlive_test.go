package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

var (
	livePodGVR    = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	liveDeployGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	liveNodeGVR   = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}
)

func newFakeDynamic(objects ...runtime.Object) *fakedynamic.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return fakedynamic.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{livePodGVR: "PodList", liveDeployGVR: "DeploymentList", liveNodeGVR: "NodeList"},
		objects...,
	)
}

func newFakeDiscovery(gitVersion string) *fakediscovery.FakeDiscovery {
	return &fakediscovery.FakeDiscovery{Fake: &kubetesting.Fake{}, FakedServerVersion: &version.Info{GitVersion: gitVersion}}
}

func TestScanLive_EmptyCluster(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "test-check", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR}})
	scanner := NewScanner(reg, config.Default())
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.30.0"))
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, checker.ScanModeLive, result.ScanMeta.ScanMode)
	assert.Equal(t, "v1.30.0", result.ClusterInfo.ServerVersion)
	assert.Equal(t, 0, result.ClusterInfo.NodeCount)
	assert.Empty(t, result.Findings)
	assert.Equal(t, 1, result.ScanMeta.ChecksRun)
}

func TestScanLive_WithFindings(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "live-checker", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "live-checker", Message: "insecure pod", Severity: checker.SeverityHigh, Kind: "Pod", Resource: "bad-pod", Namespace: "default"}}})
	scanner := NewScanner(reg, config.Default())
	pod := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]interface{}{"name": "bad-pod", "namespace": "default"}}}
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(pod), newFakeDiscovery("v1.29.0"))
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "live-checker", result.Findings[0].Checker)
	assert.Equal(t, "v1.29.0", result.ClusterInfo.ServerVersion)
	assert.True(t, result.ScanMeta.Duration > 0)
}

func TestScanLive_SkippedGVRFiltersCheckers(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "needs-pods", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "needs-pods", Message: "found"}}})
	reg.MustRegister(&fakeChecker{name: "needs-deploys", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{liveDeployGVR},
		findings: []checker.Finding{{Checker: "needs-deploys", Message: "found"}}})
	scanner := NewScanner(reg, config.Default())
	dynClient := newFakeDynamic()
	dynClient.PrependReactor("list", "deployments", func(action kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("forbidden: RBAC denied")
	})
	result, err := scanner.ScanLive(context.Background(), dynClient, newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.Equal(t, 1, result.ScanMeta.ChecksRun)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "needs-pods", result.Findings[0].Checker)
}

func TestScanLive_DisabledChecks(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "live-disabled", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "live-disabled", Message: "no"}}})
	reg.MustRegister(&fakeChecker{name: "live-enabled", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "live-enabled", Message: "yes"}}})
	cfg := config.Default()
	cfg.Checks.Disabled = []string{"live-disabled"}
	scanner := NewScanner(reg, cfg)
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.Equal(t, 1, result.ScanMeta.ChecksRun)
	assert.Equal(t, 1, result.ScanMeta.ChecksSkipped)
}

func TestScanLive_SeverityOverride(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "sev-check", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "sev-check", Severity: checker.SeverityHigh, Message: "test"}}})
	cfg := config.Default()
	cfg.Checks.Overrides = map[string]config.CheckOverride{"sev-check": {Severity: "low"}}
	scanner := NewScanner(reg, cfg)
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, checker.SeverityLow, result.Findings[0].Severity)
}

func TestScanLive_Exemptions(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "exempt-check", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "exempt-check", Namespace: "exempt-ns", Kind: "Pod", Resource: "test", Message: "test"}}})
	cfg := config.Default()
	cfg.Exemptions = []config.Exemption{{Namespace: "exempt-ns", Reason: "test"}}
	scanner := NewScanner(reg, cfg)
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestScanLive_VersionErrorNonFatal(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "ver-check", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR}})
	scanner := NewScanner(reg, config.Default())
	discClient := &fakediscovery.FakeDiscovery{Fake: &kubetesting.Fake{}}
	discClient.PrependReactor("*", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("connection refused")
	})
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), discClient)
	require.NoError(t, err)
	assert.Equal(t, "", result.ClusterInfo.ServerVersion)
}

func TestScanLive_WithNodes(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "node-aware", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{liveNodeGVR}})
	scanner := NewScanner(reg, config.Default())
	node1 := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Node", "metadata": map[string]interface{}{"name": "node-1"}}}
	node2 := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Node", "metadata": map[string]interface{}{"name": "node-2"}}}
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(node1, node2), newFakeDiscovery("v1.30.0"))
	require.NoError(t, err)
	assert.Equal(t, 2, result.ClusterInfo.NodeCount)
}

func TestScanLive_FilterManagedResources(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "pod-check", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR}})
	scanner := NewScanner(reg, config.Default())
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestScanLive_IncludeManagedTrue(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "pod-check-managed", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR}})
	cfg := config.Default()
	cfg.Settings.IncludeManaged = true
	scanner := NewScanner(reg, cfg)
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestScanLive_CheckerError(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "broken-live", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR}, runErr: errors.New("checker panic")})
	reg.MustRegister(&fakeChecker{name: "good-live", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "good-live", Message: "ok"}}})
	scanner := NewScanner(reg, config.Default())
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.Equal(t, 1, result.ScanMeta.ChecksErrored)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "good-live", result.Findings[0].Checker)
}

func TestScanLive_ManifestOnlyCheckerExcluded(t *testing.T) {
	reg := checker.NewRegistry()
	reg.MustRegister(&fakeChecker{name: "manifest-only-excl", modes: []checker.ScanMode{checker.ScanModeManifest}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "manifest-only-excl", Message: "no"}}})
	reg.MustRegister(&fakeChecker{name: "live-only-incl", modes: []checker.ScanMode{checker.ScanModeLive}, gvrs: []schema.GroupVersionResource{livePodGVR},
		findings: []checker.Finding{{Checker: "live-only-incl", Message: "yes"}}})
	scanner := NewScanner(reg, config.Default())
	result, err := scanner.ScanLive(context.Background(), newFakeDynamic(), newFakeDiscovery("v1.28.0"))
	require.NoError(t, err)
	assert.Equal(t, 1, result.ScanMeta.ChecksRun)
	for _, f := range result.Findings {
		assert.NotEqual(t, "manifest-only-excl", f.Checker)
	}
}
