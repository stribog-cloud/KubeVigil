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
			Checker:     "share-process-namespace",
			Severity:    checker.SeverityMedium,
			Resource:    info.ResourceName,
			Namespace:   info.Namespace,
			Kind:        info.Kind,
			Message:     fmt.Sprintf("Pod %q has shareProcessNamespace enabled, allowing all containers to see each other's processes.", info.ResourceName),
			Remediation: "Set shareProcessNamespace to false unless process sharing is explicitly required.",
			FieldPath:   ".spec.shareProcessNamespace",
		})
	}

	return findings, nil
}
