package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	require.NotNil(t, r)
	assert.Equal(t, 0, r.Len(), "new registry should be empty")
	assert.Empty(t, r.All(), "new registry should have no strategies")
	assert.Empty(t, r.CheckIDs(), "new registry should have no check IDs")
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()

	strategy := Strategy{
		CheckID:      "privileged",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.privileged",
		DesiredValue: false,
		Description:  "Disables privileged mode.",
		Impact:       "None.",
	}

	err := r.Register(&strategy)
	require.NoError(t, err)

	got, ok := r.Get("privileged")
	require.True(t, ok, "should find registered strategy")
	assert.Equal(t, strategy, got)
}

func TestRegisterEmptyCheckIDReturnsError(t *testing.T) {
	r := NewRegistry()

	err := r.Register(&Strategy{
		CheckID:     "",
		Safety:      checker.FixSafe,
		Operation:   checker.FixOpSet,
		Description: "some fix",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestRegisterDuplicateCheckIDReturnsError(t *testing.T) {
	r := NewRegistry()

	strategy := Strategy{
		CheckID:      "privileged",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.privileged",
		DesiredValue: false,
		Description:  "Disables privileged mode.",
	}

	err := r.Register(&strategy)
	require.NoError(t, err)

	err = r.Register(&strategy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
	assert.Contains(t, err.Error(), "privileged")
}

func TestMustRegisterPanicsOnError(t *testing.T) {
	r := NewRegistry()

	// Register with empty CheckID should panic.
	assert.Panics(t, func() {
		r.MustRegister(&Strategy{
			CheckID:     "",
			Description: "bad strategy",
		})
	}, "MustRegister should panic on empty CheckID")

	// Register valid, then duplicate should panic.
	r.MustRegister(&Strategy{
		CheckID:     "host-pid",
		Safety:      checker.FixSafe,
		Operation:   checker.FixOpSet,
		Description: "Disables host PID.",
	})

	assert.Panics(t, func() {
		r.MustRegister(&Strategy{
			CheckID:     "host-pid",
			Safety:      checker.FixSafe,
			Operation:   checker.FixOpSet,
			Description: "Duplicate.",
		})
	}, "MustRegister should panic on duplicate CheckID")
}

func TestMustRegisterDoesNotPanicOnValid(t *testing.T) {
	r := NewRegistry()

	assert.NotPanics(t, func() {
		r.MustRegister(&Strategy{
			CheckID:      "host-ipc",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpSet,
			FieldPath:    "spec.hostIPC",
			DesiredValue: false,
			Description:  "Disables host IPC.",
		})
	})

	assert.Equal(t, 1, r.Len())
}

func TestGetUnknownCheckReturnsFalse(t *testing.T) {
	r := NewRegistry()

	got, ok := r.Get("nonexistent-check")
	assert.False(t, ok, "Get should return false for unknown check")
	assert.Equal(t, Strategy{}, got, "should return zero value for unknown check")
}

func TestHas(t *testing.T) {
	r := NewRegistry()

	r.MustRegister(&Strategy{
		CheckID:     "privileged",
		Safety:      checker.FixSafe,
		Operation:   checker.FixOpSet,
		Description: "Disables privileged mode.",
	})

	assert.True(t, r.Has("privileged"), "Has should return true for registered check")
	assert.False(t, r.Has("nonexistent"), "Has should return false for unregistered check")
}

func TestAll(t *testing.T) {
	r := NewRegistry()

	strategies := []Strategy{
		{CheckID: "privileged", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix 1."},
		{CheckID: "host-pid", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix 2."},
		{CheckID: "run-as-root", Safety: checker.FixLikelySafe, Operation: checker.FixOpSet, Description: "Fix 3."},
	}

	for _, s := range strategies {
		r.MustRegister(&s)
	}

	all := r.All()
	assert.Len(t, all, 3, "All should return all registered strategies")

	// Verify all strategies are present (order is not guaranteed from map iteration).
	ids := make(map[string]bool)
	for _, s := range all {
		ids[s.CheckID] = true
	}
	assert.True(t, ids["privileged"])
	assert.True(t, ids["host-pid"])
	assert.True(t, ids["run-as-root"])
}

func TestCheckIDsReturnsSorted(t *testing.T) {
	r := NewRegistry()

	// Register in non-alphabetical order.
	r.MustRegister(&Strategy{CheckID: "run-as-root", Safety: checker.FixLikelySafe, Operation: checker.FixOpSet, Description: "Fix."})
	r.MustRegister(&Strategy{CheckID: "host-pid", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix."})
	r.MustRegister(&Strategy{CheckID: "privileged", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix."})
	r.MustRegister(&Strategy{CheckID: "automount-token", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix."})

	ids := r.CheckIDs()
	expected := []string{"automount-token", "host-pid", "privileged", "run-as-root"}
	assert.Equal(t, expected, ids, "CheckIDs should return sorted order")
}

func TestLen(t *testing.T) {
	r := NewRegistry()
	assert.Equal(t, 0, r.Len())

	r.MustRegister(&Strategy{CheckID: "a", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix."})
	assert.Equal(t, 1, r.Len())

	r.MustRegister(&Strategy{CheckID: "b", Safety: checker.FixSafe, Operation: checker.FixOpSet, Description: "Fix."})
	assert.Equal(t, 2, r.Len())

	r.MustRegister(&Strategy{CheckID: "c", Safety: checker.FixLikelySafe, Operation: checker.FixOpSet, Description: "Fix."})
	assert.Equal(t, 3, r.Len())
}

// ---------------------------------------------------------------------------
// DefaultRegistry tests
// ---------------------------------------------------------------------------

func TestDefaultRegistryHasExpectedChecks(t *testing.T) {
	r := DefaultRegistry()

	expectedPresent := []string{
		// Safe workload checks
		"privileged",
		"privilege-escalation",
		"host-pid",
		"host-ipc",
		"proc-mount",
		"share-process-namespace",
		// Likely Safe workload checks
		"capabilities-added",
		"capabilities-not-dropped",
		"run-as-root",
		"read-only-rootfs",
		"host-network",
		"seccomp-profile",
		// Potentially Breaking workload checks
		"resource-limits-missing",
		"resource-requests-missing",
		"ephemeral-storage-limits",
		"host-ports",
		// Image checks
		"image-pull-policy",
		// RBAC checks
		"automount-token",
		// PSA checks
		"psa-labels-missing",
		"psa-mode-audit-only",
	}

	for _, checkID := range expectedPresent {
		assert.True(t, r.Has(checkID), "DefaultRegistry should contain strategy for %q", checkID)
	}
}

func TestDefaultRegistryDoesNotHaveManualOnlyChecks(t *testing.T) {
	r := DefaultRegistry()

	manualOnly := []string{
		// Workload — Manual Only
		"run-as-high-uid",
		"run-as-group",
		"resource-limits-ratio",
		"host-path-volumes",
		"apparmor-profile",
		"selinux-options",
		"unsafe-sysctls",
		"runtime-class",
		"ephemeral-container-policy",
		// Image — Manual Only
		"image-tag-latest",
		"image-tag-missing",
		"image-no-digest",
		"image-registry-allowlist",
		"image-registry-blocklist",
		"image-signature-verification",
		"image-sbom-attestation",
		"image-provenance",
		// RBAC — Manual Only
		"default-service-account",
		"token-projection-config",
		"rbac-wildcard-verbs",
		"rbac-wildcard-resources",
		"rbac-wildcard-apigroups",
		"rbac-escalation-verbs",
		"rbac-secret-access",
		"rbac-exec-access",
		"rbac-log-access",
		"rbac-cluster-admin",
		"rbac-unused-roles",
		"rbac-group-bindings",
		"rbac-subject-external",
		"cloud-iam-binding",
		// Secrets — Manual Only
		"secrets-in-env",
		"secrets-unencrypted",
		"secrets-in-configmap",
		"secrets-default-type",
		"secrets-stale",
		"secrets-hardcoded-manifests",
		"external-secrets-sync",
		// Network — all Manual Only
		"network-policy-missing",
		// PSA — Manual Only
		"psa-baseline-violations",
		"psa-restricted-violations",
		"psa-version-pinning",
		"psp-still-present",
	}

	for _, checkID := range manualOnly {
		assert.False(t, r.Has(checkID), "DefaultRegistry should NOT contain manual-only check %q", checkID)
	}
}

func TestDefaultRegistryAllStrategiesHaveRequiredFields(t *testing.T) {
	r := DefaultRegistry()

	for _, s := range r.All() {
		t.Run(s.CheckID, func(t *testing.T) {
			assert.NotEmpty(t, s.CheckID, "CheckID must not be empty")
			assert.NotEmpty(t, s.Description, "Description must not be empty for %s", s.CheckID)
			assert.NotEmpty(t, string(s.Safety), "Safety must not be empty for %s", s.CheckID)
			assert.NotEmpty(t, string(s.Operation), "Operation must not be empty for %s", s.CheckID)
		})
	}
}

func TestDefaultRegistryAllStrategiesHaveValidSafety(t *testing.T) {
	r := DefaultRegistry()

	validSafeties := map[checker.FixSafety]bool{
		checker.FixSafe:                true,
		checker.FixLikelySafe:          true,
		checker.FixPotentiallyBreaking: true,
	}

	for _, s := range r.All() {
		t.Run(s.CheckID, func(t *testing.T) {
			assert.True(t, validSafeties[s.Safety],
				"check %q has invalid safety %q (manual_only should not be in registry)", s.CheckID, s.Safety)
		})
	}
}

func TestDefaultRegistryAllStrategiesHaveValidOperation(t *testing.T) {
	r := DefaultRegistry()

	validOps := map[checker.FixOp]bool{
		checker.FixOpSet:    true,
		checker.FixOpAdd:    true,
		checker.FixOpRemove: true,
		checker.FixOpMerge:  true,
	}

	for _, s := range r.All() {
		t.Run(s.CheckID, func(t *testing.T) {
			assert.True(t, validOps[s.Operation],
				"check %q has invalid operation %q", s.CheckID, s.Operation)
		})
	}
}

func TestDefaultRegistryCount(t *testing.T) {
	r := DefaultRegistry()

	count := r.Len()
	assert.GreaterOrEqual(t, count, 20, "should have at least 20 auto-fixable strategies")
	assert.LessOrEqual(t, count, 35, "should have at most 35 strategies (not every check is auto-fixable)")
}

func TestDefaultRegistrySafetyClassifications(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		checkID  string
		expected checker.FixSafety
	}{
		// Safe checks
		{checkID: "privileged", expected: checker.FixSafe},
		{checkID: "privilege-escalation", expected: checker.FixSafe},
		{checkID: "host-pid", expected: checker.FixSafe},
		{checkID: "host-ipc", expected: checker.FixSafe},
		{checkID: "proc-mount", expected: checker.FixSafe},
		{checkID: "share-process-namespace", expected: checker.FixSafe},
		{checkID: "automount-token", expected: checker.FixSafe},

		// Likely Safe checks
		{checkID: "capabilities-added", expected: checker.FixLikelySafe},
		{checkID: "capabilities-not-dropped", expected: checker.FixLikelySafe},
		{checkID: "run-as-root", expected: checker.FixLikelySafe},
		{checkID: "read-only-rootfs", expected: checker.FixLikelySafe},
		{checkID: "host-network", expected: checker.FixLikelySafe},
		{checkID: "seccomp-profile", expected: checker.FixLikelySafe},
		{checkID: "image-pull-policy", expected: checker.FixLikelySafe},
		{checkID: "psa-labels-missing", expected: checker.FixLikelySafe},
		{checkID: "psa-mode-audit-only", expected: checker.FixLikelySafe},

		// Potentially Breaking checks
		{checkID: "resource-limits-missing", expected: checker.FixPotentiallyBreaking},
		{checkID: "resource-requests-missing", expected: checker.FixPotentiallyBreaking},
		{checkID: "ephemeral-storage-limits", expected: checker.FixPotentiallyBreaking},
		{checkID: "host-ports", expected: checker.FixPotentiallyBreaking},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			strategy, ok := r.Get(tt.checkID)
			require.True(t, ok, "check %q should be in registry", tt.checkID)
			assert.Equal(t, tt.expected, strategy.Safety,
				"check %q should have safety %q, got %q", tt.checkID, tt.expected, strategy.Safety)
		})
	}
}

func TestDefaultRegistryOperations(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		checkID  string
		expected checker.FixOp
	}{
		{checkID: "privileged", expected: checker.FixOpSet},
		{checkID: "capabilities-added", expected: checker.FixOpRemove},
		{checkID: "capabilities-not-dropped", expected: checker.FixOpSet},
		{checkID: "seccomp-profile", expected: checker.FixOpAdd},
		{checkID: "psa-labels-missing", expected: checker.FixOpMerge},
		{checkID: "host-ports", expected: checker.FixOpRemove},
		{checkID: "resource-limits-missing", expected: checker.FixOpSet},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			strategy, ok := r.Get(tt.checkID)
			require.True(t, ok)
			assert.Equal(t, tt.expected, strategy.Operation,
				"check %q should have operation %q, got %q", tt.checkID, tt.expected, strategy.Operation)
		})
	}
}

func TestDefaultRegistryFieldPaths(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		checkID      string
		expectedPath string
	}{
		{checkID: "privileged", expectedPath: "spec.containers[*].securityContext.privileged"},
		{checkID: "host-pid", expectedPath: "spec.hostPID"},
		{checkID: "host-ipc", expectedPath: "spec.hostIPC"},
		{checkID: "automount-token", expectedPath: "spec.automountServiceAccountToken"},
		{checkID: "image-pull-policy", expectedPath: "spec.containers[*].imagePullPolicy"},
		{checkID: "psa-labels-missing", expectedPath: "metadata.labels"},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			strategy, ok := r.Get(tt.checkID)
			require.True(t, ok)
			assert.Equal(t, tt.expectedPath, strategy.FieldPath)
		})
	}
}

func TestDefaultRegistryDesiredValues(t *testing.T) {
	r := DefaultRegistry()

	t.Run("privileged is false", func(t *testing.T) {
		s, ok := r.Get("privileged")
		require.True(t, ok)
		assert.Equal(t, false, s.DesiredValue)
	})

	t.Run("run-as-root is true", func(t *testing.T) {
		s, ok := r.Get("run-as-root")
		require.True(t, ok)
		assert.Equal(t, true, s.DesiredValue)
	})

	t.Run("capabilities-not-dropped is ALL", func(t *testing.T) {
		s, ok := r.Get("capabilities-not-dropped")
		require.True(t, ok)
		assert.Equal(t, []string{"ALL"}, s.DesiredValue)
	})

	t.Run("resource-limits-missing has cpu and memory", func(t *testing.T) {
		s, ok := r.Get("resource-limits-missing")
		require.True(t, ok)
		expected := map[string]string{"cpu": "500m", "memory": "256Mi"}
		assert.Equal(t, expected, s.DesiredValue)
	})

	t.Run("resource-requests-missing has cpu and memory", func(t *testing.T) {
		s, ok := r.Get("resource-requests-missing")
		require.True(t, ok)
		expected := map[string]string{"cpu": "100m", "memory": "128Mi"}
		assert.Equal(t, expected, s.DesiredValue)
	})

	t.Run("image-pull-policy is Always", func(t *testing.T) {
		s, ok := r.Get("image-pull-policy")
		require.True(t, ok)
		assert.Equal(t, "Always", s.DesiredValue)
	})

	t.Run("proc-mount is Default", func(t *testing.T) {
		s, ok := r.Get("proc-mount")
		require.True(t, ok)
		assert.Equal(t, "Default", s.DesiredValue)
	})

	t.Run("capabilities-added has nil desired value", func(t *testing.T) {
		s, ok := r.Get("capabilities-added")
		require.True(t, ok)
		assert.Nil(t, s.DesiredValue)
	})

	t.Run("host-ports has nil desired value for remove", func(t *testing.T) {
		s, ok := r.Get("host-ports")
		require.True(t, ok)
		assert.Nil(t, s.DesiredValue)
	})
}

func TestDefaultRegistryImpactMessages(t *testing.T) {
	r := DefaultRegistry()

	// Every strategy should have a non-empty Impact string.
	for _, s := range r.All() {
		t.Run(s.CheckID, func(t *testing.T) {
			assert.NotEmpty(t, s.Impact, "Impact must not be empty for %s", s.CheckID)
		})
	}
}

func TestDefaultRegistryNoManualOnlySafety(t *testing.T) {
	r := DefaultRegistry()

	for _, s := range r.All() {
		assert.NotEqual(t, checker.FixManualOnly, s.Safety,
			"check %q has manual_only safety and should not be in the registry", s.CheckID)
	}
}

func TestDefaultRegistryCheckIDsAreUnique(t *testing.T) {
	r := DefaultRegistry()

	ids := r.CheckIDs()
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		assert.False(t, seen[id], "duplicate check ID in registry: %s", id)
		seen[id] = true
	}
}

func TestDefaultRegistrySafetyBreakdown(t *testing.T) {
	r := DefaultRegistry()

	counts := map[checker.FixSafety]int{}
	for _, s := range r.All() {
		counts[s.Safety]++
	}

	assert.Greater(t, counts[checker.FixSafe], 0, "should have safe strategies")
	assert.Greater(t, counts[checker.FixLikelySafe], 0, "should have likely_safe strategies")
	assert.Greater(t, counts[checker.FixPotentiallyBreaking], 0, "should have potentially_breaking strategies")
	assert.Equal(t, 0, counts[checker.FixManualOnly], "should have zero manual_only strategies")

	// Safe should have 7 (privileged, privilege-escalation, host-pid, host-ipc,
	// proc-mount, share-process-namespace, automount-token).
	assert.Equal(t, 7, counts[checker.FixSafe], "expected 7 safe strategies")

	// Likely Safe should have 9 (capabilities-added, capabilities-not-dropped,
	// run-as-root, read-only-rootfs, host-network, seccomp-profile,
	// image-pull-policy, psa-labels-missing, psa-mode-audit-only).
	assert.Equal(t, 9, counts[checker.FixLikelySafe], "expected 9 likely_safe strategies")

	// Potentially Breaking should have 4 (resource-limits-missing,
	// resource-requests-missing, ephemeral-storage-limits, host-ports).
	assert.Equal(t, 4, counts[checker.FixPotentiallyBreaking], "expected 4 potentially_breaking strategies")
}

func TestDefaultRegistryAutomountTokenFieldPath(t *testing.T) {
	// The automount-token fix targets the pod spec level, not the container level.
	r := DefaultRegistry()

	s, ok := r.Get("automount-token")
	require.True(t, ok)
	assert.Equal(t, "spec.automountServiceAccountToken", s.FieldPath,
		"automount-token should target pod spec, not container spec")
	assert.NotContains(t, s.FieldPath, "containers[*]",
		"automount-token field path should not contain containers[*]")
}

func TestDefaultRegistryPodLevelFieldPaths(t *testing.T) {
	// Verify that pod-level checks do not have container-level field paths.
	r := DefaultRegistry()

	podLevelChecks := []string{
		"host-pid",
		"host-ipc",
		"host-network",
		"share-process-namespace",
		"automount-token",
	}

	for _, checkID := range podLevelChecks {
		t.Run(checkID, func(t *testing.T) {
			s, ok := r.Get(checkID)
			require.True(t, ok)
			assert.NotContains(t, s.FieldPath, "containers[*]",
				"pod-level check %q should not have containers[*] in field path", checkID)
		})
	}
}

func TestDefaultRegistryContainerLevelFieldPaths(t *testing.T) {
	// Verify that container-level checks have container-level field paths.
	r := DefaultRegistry()

	containerLevelChecks := []string{
		"privileged",
		"privilege-escalation",
		"capabilities-added",
		"capabilities-not-dropped",
		"run-as-root",
		"read-only-rootfs",
		"proc-mount",
		"seccomp-profile",
		"image-pull-policy",
		"resource-limits-missing",
		"resource-requests-missing",
		"ephemeral-storage-limits",
		"host-ports",
	}

	for _, checkID := range containerLevelChecks {
		t.Run(checkID, func(t *testing.T) {
			s, ok := r.Get(checkID)
			require.True(t, ok)
			assert.Contains(t, s.FieldPath, "containers[*]",
				"container-level check %q should have containers[*] in field path", checkID)
		})
	}
}
