package fix

import (
	"fmt"
	"sort"
	"sync"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// Strategy describes how to fix a specific check finding.
type Strategy struct {
	// CheckID is the kebab-case check identifier (e.g., "privileged").
	CheckID string
	// Safety classifies the risk level of this fix.
	Safety checker.FixSafety
	// Operation describes the type of YAML modification.
	Operation checker.FixOp
	// FieldPath is the YAML path template for the field to modify.
	// Uses [*] for container iteration (e.g., "spec.containers[*].securityContext.privileged").
	FieldPath string
	// DesiredValue is the value to set or add.
	DesiredValue any
	// Description explains what the fix does.
	Description string
	// Impact explains what could break.
	Impact string
}

// Registry maps check IDs to their fix strategies.
type Registry struct {
	mu         sync.RWMutex
	strategies map[string]Strategy
}

// NewRegistry creates an empty fix registry.
func NewRegistry() *Registry {
	return &Registry{
		strategies: make(map[string]Strategy),
	}
}

// Register adds a fix strategy to the registry.
// Returns an error if CheckID is empty or already registered.
func (r *Registry) Register(s *Strategy) error {
	if s.CheckID == "" {
		return fmt.Errorf("fix strategy CheckID must not be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.strategies[s.CheckID]; exists {
		return fmt.Errorf("fix strategy already registered for check %q", s.CheckID)
	}
	r.strategies[s.CheckID] = *s
	return nil
}

// MustRegister adds a fix strategy, panicking on error.
func (r *Registry) MustRegister(s *Strategy) {
	if err := r.Register(s); err != nil {
		panic(fmt.Sprintf("fix registry: %v", err))
	}
}

// Get retrieves a fix strategy by check ID.
// Returns the strategy and true if found, zero value and false otherwise.
func (r *Registry) Get(checkID string) (Strategy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s, ok := r.strategies[checkID]
	return s, ok
}

// Has returns true if a fix strategy exists for the check ID.
func (r *Registry) Has(checkID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.strategies[checkID]
	return ok
}

// All returns all registered fix strategies.
func (r *Registry) All() []Strategy {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Strategy, 0, len(r.strategies))
	for _, s := range r.strategies {
		result = append(result, s)
	}
	return result
}

// CheckIDs returns all registered check IDs in sorted order.
func (r *Registry) CheckIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.strategies))
	for id := range r.strategies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Len returns the number of registered strategies.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.strategies)
}

// DefaultRegistry returns a registry pre-populated with fix strategies
// for all auto-fixable checks. Only checks that can be safely automated are
// included — manual-only checks are not registered.
func DefaultRegistry() *Registry {
	r := NewRegistry()

	// -----------------------------------------------------------------------
	// Workload checks — Safe
	// -----------------------------------------------------------------------

	r.MustRegister(&Strategy{
		CheckID:      "privileged",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.privileged",
		DesiredValue: false,
		Description:  "Disables privileged mode.",
		Impact:       "None — containers should never run privileged unless they are known system components.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "privilege-escalation",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.allowPrivilegeEscalation",
		DesiredValue: false,
		Description:  "Disables privilege escalation.",
		Impact:       "None for standard workloads.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "host-pid",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.hostPID",
		DesiredValue: false,
		Description:  "Disables host PID namespace sharing.",
		Impact:       "None unless container specifically needs host PID visibility.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "host-ipc",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.hostIPC",
		DesiredValue: false,
		Description:  "Disables host IPC namespace sharing.",
		Impact:       "None unless container uses shared memory with host.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "proc-mount",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.procMount",
		DesiredValue: "Default",
		Description:  "Sets procMount to Default.",
		Impact:       "None — Default is the standard setting.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "share-process-namespace",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.shareProcessNamespace",
		DesiredValue: false,
		Description:  "Disables process namespace sharing between containers.",
		Impact:       "None unless containers need to share process visibility.",
	})

	// -----------------------------------------------------------------------
	// Workload checks — Likely Safe
	// -----------------------------------------------------------------------

	r.MustRegister(&Strategy{
		CheckID:      "capabilities-added",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpRemove,
		FieldPath:    "spec.containers[*].securityContext.capabilities.add",
		DesiredValue: nil,
		Description:  "Removes dangerous added capabilities.",
		Impact:       "Containers requiring specific capabilities will fail.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "capabilities-not-dropped",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.capabilities.drop",
		DesiredValue: []string{"ALL"},
		Description:  "Drops all capabilities.",
		Impact:       "Containers needing specific capabilities must explicitly add them back.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "run-as-root",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.runAsNonRoot",
		DesiredValue: true,
		Description:  "Sets runAsNonRoot to true.",
		Impact:       "Containers that require root will fail to start.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "read-only-rootfs",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].securityContext.readOnlyRootFilesystem",
		DesiredValue: true,
		Description:  "Sets readOnlyRootFilesystem to true.",
		Impact:       "Apps writing to container filesystem need emptyDir volumes.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "host-network",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.hostNetwork",
		DesiredValue: false,
		Description:  "Disables host network sharing.",
		Impact:       "Containers binding to host ports will lose network access.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "seccomp-profile",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpAdd,
		FieldPath:    "spec.containers[*].securityContext.seccompProfile",
		DesiredValue: map[string]string{"type": "RuntimeDefault"},
		Description:  "Adds RuntimeDefault seccomp profile.",
		Impact:       "Containers using uncommon syscalls may crash.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "image-pull-policy",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].imagePullPolicy",
		DesiredValue: "Always",
		Description:  "Sets imagePullPolicy to Always.",
		Impact:       "Slightly slower pod starts due to image verification.",
	})

	// -----------------------------------------------------------------------
	// Workload checks — Potentially Breaking
	// -----------------------------------------------------------------------

	r.MustRegister(&Strategy{
		CheckID:      "resource-limits-missing",
		Safety:       checker.FixPotentiallyBreaking,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].resources.limits",
		DesiredValue: map[string]string{"cpu": "500m", "memory": "256Mi"},
		Description:  "Adds default resource limits.",
		Impact:       "Applications exceeding limits will be throttled or OOMKilled.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "resource-requests-missing",
		Safety:       checker.FixPotentiallyBreaking,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].resources.requests",
		DesiredValue: map[string]string{"cpu": "100m", "memory": "128Mi"},
		Description:  "Adds default resource requests.",
		Impact:       "May affect scheduling if cluster resources are constrained.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "ephemeral-storage-limits",
		Safety:       checker.FixPotentiallyBreaking,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.containers[*].resources.limits.ephemeral-storage",
		DesiredValue: "1Gi",
		Description:  "Adds default ephemeral-storage limit.",
		Impact:       "Containers exceeding limit will be evicted.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "host-ports",
		Safety:       checker.FixPotentiallyBreaking,
		Operation:    checker.FixOpRemove,
		FieldPath:    "spec.containers[*].ports[*].hostPort",
		DesiredValue: nil,
		Description:  "Removes hostPort from container ports.",
		Impact:       "External traffic routing via host ports will stop working.",
	})

	// -----------------------------------------------------------------------
	// RBAC checks — Safe
	// -----------------------------------------------------------------------

	r.MustRegister(&Strategy{
		CheckID:      "automount-token",
		Safety:       checker.FixSafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "spec.automountServiceAccountToken",
		DesiredValue: false,
		Description:  "Disables automatic service account token mounting.",
		Impact:       "Pods that need API access will fail without token.",
	})

	// -----------------------------------------------------------------------
	// PSA checks — Likely Safe
	// -----------------------------------------------------------------------

	r.MustRegister(&Strategy{
		CheckID:   "psa-labels-missing",
		Safety:    checker.FixLikelySafe,
		Operation: checker.FixOpMerge,
		FieldPath: "metadata.labels",
		DesiredValue: map[string]string{
			"pod-security.kubernetes.io/enforce": "baseline",
		},
		Description: "Adds Pod Security Admission labels.",
		Impact:      "New pods violating baseline will be rejected.",
	})

	r.MustRegister(&Strategy{
		CheckID:      "psa-mode-audit-only",
		Safety:       checker.FixLikelySafe,
		Operation:    checker.FixOpSet,
		FieldPath:    "metadata.labels.pod-security.kubernetes.io/enforce",
		DesiredValue: "baseline",
		Description:  "Changes PSA mode from audit to enforce.",
		Impact:       "Pods violating PSA policy will be rejected.",
	})

	return r
}
