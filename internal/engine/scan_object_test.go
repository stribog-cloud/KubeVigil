package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"

	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

func privilegedPod(name, ns string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":            "app",
				"image":           "nginx",
				"securityContext": map[string]any{"privileged": true},
			}},
		},
	}}
}

func TestScanObject_FlagsPrivilegedPod(t *testing.T) {
	scanner := NewScanner(checker.DefaultRegistry(), config.Default())
	result, err := scanner.ScanObject(context.Background(), privilegedPod("web", "default"))
	require.NoError(t, err)
	assert.NotEmpty(t, result.Findings, "privileged pod must produce findings")
	assert.Equal(t, checker.ScanModeManifest, result.ScanMeta.ScanMode)

	found := false
	for i := range result.Findings {
		if result.Findings[i].Checker == "privileged" {
			found = true
			assert.Equal(t, "web", result.Findings[i].Resource)
		}
	}
	assert.True(t, found, "privileged check should fire")
}

func TestScanObject_CleanPodNoFindings(t *testing.T) {
	scanner := NewScanner(checker.DefaultRegistry(), config.Default())
	clean := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "ok", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "app",
				"image": "nginx@sha256:abc",
				"securityContext": map[string]any{
					"privileged":               false,
					"allowPrivilegeEscalation": false,
					"runAsNonRoot":             true,
					"readOnlyRootFilesystem":   true,
					"capabilities":             map[string]any{"drop": []any{"ALL"}},
				},
			}},
		},
	}}
	result, err := scanner.ScanObject(context.Background(), clean)
	require.NoError(t, err)
	// A well-hardened pod may still trip a couple of checks, but privileged
	// must not be among them.
	for i := range result.Findings {
		assert.NotEqual(t, "privileged", result.Findings[i].Checker)
	}
}

func TestScanObject_RejectsObjectWithoutKind(t *testing.T) {
	scanner := NewScanner(checker.DefaultRegistry(), config.Default())
	_, err := scanner.ScanObject(context.Background(), unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "x"},
	}})
	require.Error(t, err)
}

func TestScanObject_RespectsExemptions(t *testing.T) {
	cfg := config.Default()
	cfg.Exemptions = []config.Exemption{{Namespace: "kube-system", Reason: "test"}}
	scanner := NewScanner(checker.DefaultRegistry(), cfg)

	result, err := scanner.ScanObject(context.Background(), privilegedPod("web", "kube-system"))
	require.NoError(t, err)
	for i := range result.Findings {
		assert.NotEqual(t, "kube-system", result.Findings[i].Namespace, "exempted namespace should be filtered")
	}
}
