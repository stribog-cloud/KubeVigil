package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ShareProcessNamespaceChecker detects pods with shareProcessNamespace enabled.
// When enabled, all containers in the pod share the same PID namespace, allowing
// them to see and signal each other's processes. This can expose sensitive
// information and increase the blast radius of a container compromise.
type ShareProcessNamespaceChecker struct{}

// Name returns the kebab-case check ID.
func (c *ShareProcessNamespaceChecker) Name() string { return "share-process-namespace" }

// Description returns a human-readable description.
func (c *ShareProcessNamespaceChecker) Description() string {
	return "Detects pods with shareProcessNamespace enabled, which allows all containers to see each other's processes."
}

// Categories returns the check categories.
func (c *ShareProcessNamespaceChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ShareProcessNamespaceChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ShareProcessNamespaceChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the share-process-namespace check against all workload resources in the cache.
func (c *ShareProcessNamespaceChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("share-process-namespace check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		if info.Spec.ShareProcessNamespace == nil || !*info.Spec.ShareProcessNamespace {
			continue // not set or explicitly false
		}

		findings = append(findings, checker.Finding{
			Checker:   "share-process-namespace",
			Severity:  checker.SeverityMedium,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Message:   fmt.Sprintf("Pod %q has shareProcessNamespace enabled, allowing all containers to see each other's processes.", info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"When shareProcessNamespace is enabled, all containers in the pod share the same PID namespace and can see each " +
				"other's processes, access their /proc entries, and send signals. If one container is compromised, the attacker " +
				"can inspect environment variables, read memory via /proc/[pid]/mem, or kill processes in sibling containers.\n\n" +
				"## How to Fix\n\n" +
				"Disable process namespace sharing unless explicitly required:\n\n" +
				"```yaml\nspec:\n  shareProcessNamespace: false\n```\n\n" +
				"Legitimate use cases for shared PID namespaces include sidecar containers that need to monitor the main " +
				"application process, or debug containers that need process visibility. Evaluate whether your sidecar pattern " +
				"truly requires this access.\n\n" +
				"## Learn More\n\n" +
				"Shared PID namespaces also make PID 1 the pause container rather than your application, which changes " +
				"signal handling behavior. See the Kubernetes documentation on sharing process namespace between containers.",
			FieldPath: ".spec.shareProcessNamespace",
		})
	}

	return findings, nil
}
