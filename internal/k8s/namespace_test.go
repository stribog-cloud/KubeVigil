package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreSystemNamespaces_HasExactlyThreeEntries(t *testing.T) {
	assert.Len(t, CoreSystemNamespaces, 3, "CoreSystemNamespaces must have exactly 3 entries")
}

func TestCoreSystemNamespaces_ContainsExpectedEntries(t *testing.T) {
	expected := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, ns := range expected {
		assert.Contains(t, CoreSystemNamespaces, ns,
			"CoreSystemNamespaces must contain %q", ns)
	}
}

func TestInfrastructureNamespaces_ContainsExpectedEntries(t *testing.T) {
	expected := []string{
		"istio-system", "cert-manager", "monitoring",
		"calico-system", "cilium", "ingress-nginx",
		"metallb-system", "longhorn-system",
	}
	for _, ns := range expected {
		assert.Contains(t, InfrastructureNamespaces, ns,
			"InfrastructureNamespaces must contain %q", ns)
	}
}

func TestInfrastructureNamespaces_DoesNotContainCoreNamespaces(t *testing.T) {
	for _, ns := range CoreSystemNamespaces {
		assert.NotContains(t, InfrastructureNamespaces, ns,
			"InfrastructureNamespaces must NOT contain core namespace %q", ns)
	}
}

func TestAllProtectedNamespaces_ContainsAllCoreNamespaces(t *testing.T) {
	for _, ns := range CoreSystemNamespaces {
		assert.Contains(t, AllProtectedNamespaces, ns,
			"AllProtectedNamespaces must contain core namespace %q", ns)
	}
}

func TestAllProtectedNamespaces_ContainsAllInfrastructureNamespaces(t *testing.T) {
	for _, ns := range InfrastructureNamespaces {
		assert.Contains(t, AllProtectedNamespaces, ns,
			"AllProtectedNamespaces must contain infrastructure namespace %q", ns)
	}
}

func TestAllProtectedNamespaces_LengthMatchesCombined(t *testing.T) {
	expected := len(CoreSystemNamespaces) + len(InfrastructureNamespaces)
	require.Len(t, AllProtectedNamespaces, expected,
		"AllProtectedNamespaces length must equal CoreSystemNamespaces + InfrastructureNamespaces")
}

func TestAllProtectedNamespaces_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(AllProtectedNamespaces))
	for _, ns := range AllProtectedNamespaces {
		assert.False(t, seen[ns], "duplicate namespace in AllProtectedNamespaces: %q", ns)
		seen[ns] = true
	}
}
