package fix

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSafetyClassifier_DefaultNamespaces(t *testing.T) {
	sc := NewSafetyClassifier(nil)

	for _, ns := range DefaultSystemNamespaces {
		assert.True(t, sc.IsSystemNamespace(ns), "expected %q to be a system namespace", ns)
	}
}

func TestNewSafetyClassifier_AdditionalNamespaces(t *testing.T) {
	additional := []string{"custom-infra", "vault"}
	sc := NewSafetyClassifier(additional)

	// All defaults still present
	for _, ns := range DefaultSystemNamespaces {
		assert.True(t, sc.IsSystemNamespace(ns), "default namespace %q should be present", ns)
	}

	// Additional namespaces present
	for _, ns := range additional {
		assert.True(t, sc.IsSystemNamespace(ns), "additional namespace %q should be present", ns)
	}
}

func TestNewSafetyClassifier_AdditionalNeverReplacesDefaults(t *testing.T) {
	// Even with a completely unrelated additional list, all defaults must be present.
	additional := []string{"my-custom-ns"}
	sc := NewSafetyClassifier(additional)

	for _, ns := range DefaultSystemNamespaces {
		assert.True(t, sc.IsSystemNamespace(ns), "default namespace %q must not be removed by additional namespaces", ns)
	}
	assert.True(t, sc.IsSystemNamespace("my-custom-ns"))
}

func TestNewSafetyClassifier_EmptyStringIgnored(t *testing.T) {
	sc := NewSafetyClassifier([]string{""})

	// Empty string should not be added
	assert.False(t, sc.IsSystemNamespace(""))
}

func TestIsSystemNamespace(t *testing.T) {
	sc := NewSafetyClassifier([]string{"custom-ns"})

	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		{name: "kube-system", namespace: "kube-system", want: true},
		{name: "kube-public", namespace: "kube-public", want: true},
		{name: "kube-node-lease", namespace: "kube-node-lease", want: true},
		{name: "calico-system", namespace: "calico-system", want: true},
		{name: "cilium", namespace: "cilium", want: true},
		{name: "istio-system", namespace: "istio-system", want: true},
		{name: "cert-manager", namespace: "cert-manager", want: true},
		{name: "monitoring", namespace: "monitoring", want: true},
		{name: "metallb-system", namespace: "metallb-system", want: true},
		{name: "custom additional", namespace: "custom-ns", want: true},
		{name: "default is not system", namespace: "default", want: false},
		{name: "production is not system", namespace: "production", want: false},
		{name: "empty string", namespace: "", want: false},
		{name: "random namespace", namespace: "my-app", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sc.IsSystemNamespace(tt.namespace))
		})
	}
}

func TestSystemNamespaces_ReturnsSortedList(t *testing.T) {
	sc := NewSafetyClassifier([]string{"zzz-custom", "aaa-custom"})
	namespaces := sc.SystemNamespaces()

	require.NotEmpty(t, namespaces)
	assert.True(t, sort.StringsAreSorted(namespaces), "SystemNamespaces() should return a sorted list")

	// Verify all defaults are in the list
	nsSet := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		nsSet[ns] = true
	}
	for _, ns := range DefaultSystemNamespaces {
		assert.True(t, nsSet[ns], "expected default namespace %q in SystemNamespaces()", ns)
	}
	assert.True(t, nsSet["zzz-custom"])
	assert.True(t, nsSet["aaa-custom"])
}

func TestClassifyResource_SystemNamespace(t *testing.T) {
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("kube-system", "Deployment", []string{"my-app:latest"})
	assert.True(t, skip)
	assert.Equal(t, "system_namespace", reason)
}

func TestClassifyResource_KnownWorkload(t *testing.T) {
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("default", "DaemonSet", []string{"docker.io/calico/node:v3.27.0"})
	assert.True(t, skip)
	assert.Contains(t, reason, "CNI plugin")
}

func TestClassifyResource_NormalResource(t *testing.T) {
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("production", "Deployment", []string{"my-app:v1.2.3"})
	assert.False(t, skip)
	assert.Empty(t, reason)
}

func TestClassifyResource_EmptyNamespace(t *testing.T) {
	// Cluster-scoped resources have empty namespace — should not trigger system NS skip.
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("", "ClusterRole", nil)
	assert.False(t, skip)
	assert.Empty(t, reason)
}

func TestClassifyResource_SystemNamespaceTakesPrecedence(t *testing.T) {
	// If the resource is in a system namespace AND matches a known workload,
	// the system namespace reason should be returned (checked first).
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("kube-system", "DaemonSet", []string{"registry.k8s.io/kube-proxy:v1.30.0"})
	assert.True(t, skip)
	assert.Equal(t, "system_namespace", reason)
}

func TestClassifyResource_KnownWorkloadInNonSystemNamespace(t *testing.T) {
	// A known workload deployed in a non-system namespace should still be detected.
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("my-custom-ns", "DaemonSet", []string{"quay.io/cilium/cilium:v1.15.0"})
	assert.True(t, skip)
	assert.Contains(t, reason, "eBPF")
}

func TestClassifyResource_NoImages(t *testing.T) {
	sc := NewSafetyClassifier(nil)

	skip, reason := sc.ClassifyResource("production", "ConfigMap", nil)
	assert.False(t, skip)
	assert.Empty(t, reason)
}

func TestClassifyResource_AdditionalSystemNamespace(t *testing.T) {
	sc := NewSafetyClassifier([]string{"vault"})

	skip, reason := sc.ClassifyResource("vault", "StatefulSet", []string{"vault:1.15.0"})
	assert.True(t, skip)
	assert.Equal(t, "system_namespace", reason)
}
