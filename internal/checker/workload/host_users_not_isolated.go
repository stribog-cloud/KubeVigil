package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostUsersNotIsolatedChecker detects pods that do not set hostUsers: false.
// Without an isolated user namespace, a container that escapes to the host
// (e.g., via a kernel vulnerability) runs with the same UID mapping as the
// host, making privilege escalation and lateral movement easier.
type HostUsersNotIsolatedChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostUsersNotIsolatedChecker) Name() string { return "host-users-not-isolated" }

// Description returns a human-readable description.
func (c *HostUsersNotIsolatedChecker) Description() string {
	return "Detects pods that do not set hostUsers: false, sharing the host's user namespace instead of an isolated one."
}

// Categories returns the check categories.
func (c *HostUsersNotIsolatedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostUsersNotIsolatedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostUsersNotIsolatedChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-users-not-isolated check against all workload resources in the cache.
func (c *HostUsersNotIsolatedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-users-not-isolated check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		if info.Spec.HostUsers != nil && !*info.Spec.HostUsers {
			continue // explicitly isolated
		}

		findings = append(findings, checker.Finding{
			Checker:   "host-users-not-isolated",
			Severity:  checker.SeverityLow,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Message:   fmt.Sprintf("%s %q does not isolate its user namespace (hostUsers is not set to false).", info.Kind, info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"When hostUsers is unset or true, the pod shares the host's user namespace: UID 0 inside the container maps to " +
				"UID 0 on the host. If an attacker escapes the container (e.g., via a kernel vulnerability), they land on the host " +
				"with the same privilege level rather than an unprivileged, remapped UID. User namespace isolation (hostUsers: false) " +
				"is a Kubernetes 1.25+ opt-in hardening feature (stable in 1.30) that gives every pod its own UID/GID mapping.\n\n" +
				"## How to Fix\n\n" +
				"Set hostUsers to false in the pod spec:\n\n" +
				"```yaml\nspec:\n  hostUsers: false\n```\n\n" +
				"Verify your container runtime and kernel support user namespaces (containerd 2.0+/CRI-O with a recent kernel). " +
				"Some workloads that rely on specific host UID mappings (e.g., NFS with UID-based permissions) may need adjustment.\n\n" +
				"## Learn More\n\n" +
				"This check aligns with MITRE ATT&CK T1611 (Escape to Host). See the Kubernetes documentation on user namespaces " +
				"for supported runtimes and known limitations.",
			FieldPath:    ".spec.hostUsers",
			CurrentValue: true,
			DesiredValue: false,
			FixHint: &checker.FixHint{
				Safety:      checker.FixLikelySafe,
				Description: "Sets hostUsers to false, isolating the pod's user namespace from the host.",
				Impact:      "Requires a container runtime and kernel with user namespace support; some host-UID-dependent workloads may need adjustment.",
				Operation:   checker.FixOpSet,
			},
		})
	}

	return findings, nil
}
