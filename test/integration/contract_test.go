package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"

	// Import workload package to trigger init() registration.
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TestAllCheckersContract exercises the contract test against ALL registered checkers.
// This test imports all checker packages to ensure their init() functions run.
func TestAllCheckersContract(t *testing.T) {
	checkers := checker.DefaultRegistry().All()
	require.NotEmpty(t, checkers, "expected at least one checker to be registered")

	checker.RunCheckerContractTests(t, checkers)
}

// TestCheckerRegistration verifies ALL expected checkers are registered.
func TestCheckerRegistration(t *testing.T) {
	registry := checker.DefaultRegistry()

	expected := []string{
		"privileged",
		"capabilities-added",
		"capabilities-not-dropped",
		"run-as-root",
		"run-as-high-uid",
		"run-as-group",
		"read-only-rootfs",
		"resource-limits-missing",
		"resource-requests-missing",
		"resource-limits-ratio",
		"ephemeral-storage-limits",
		"host-pid",
		"host-ipc",
		"host-network",
		"host-ports",
		"host-path-volumes",
		"privilege-escalation",
		"seccomp-profile",
		"apparmor-profile",
		"selinux-options",
		"proc-mount",
		"unsafe-sysctls",
		"runtime-class",
		"share-process-namespace",
		"ephemeral-container-policy",
	}

	require.Equal(t, 25, registry.Len(), "expected exactly 25 checkers to be registered")

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			c, ok := registry.Get(name)
			require.True(t, ok, "checker %q should be registered", name)
			require.NotNil(t, c)
		})
	}
}
