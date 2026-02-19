package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// LimitRangeMissingChecker detects namespaces without a LimitRange defined.
type LimitRangeMissingChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *LimitRangeMissingChecker) Name() string { return "limit-range-missing" }

// Description returns a human-readable summary of what this check detects.
func (c *LimitRangeMissingChecker) Description() string {
	return "Detects namespaces without LimitRange; a single container can request all node resources."
}

// Categories returns the security categories this check belongs to.
func (c *LimitRangeMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *LimitRangeMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *LimitRangeMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NamespaceGVR, LimitRangeGVR}
}

// Run executes the check against cached resources and returns any findings.
func (c *LimitRangeMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("limit-range-missing check: %w", err)
	}

	namespaces := resources.List(NamespaceGVR)
	var findings []checker.Finding

	for i := range namespaces {
		ns := &namespaces[i]
		name := ns.GetName()
		if isSystemNamespace(name) {
			continue
		}

		lrs := resources.ListNamespaced(LimitRangeGVR, name)
		if len(lrs) == 0 {
			findings = append(findings, checker.Finding{
				Checker:   "limit-range-missing",
				Severity:  checker.SeverityLow,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q has no LimitRange defined.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without a LimitRange, any container can be created without resource constraints. " +
					"A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.\n\n" +
					"## How to Fix\n\n" +
					"Create a LimitRange in the namespace to set default and maximum resource constraints:\n\n" +
					"```yaml\napiVersion: v1\nkind: LimitRange\nmetadata:\n  name: default-limits\n  namespace: my-app\nspec:\n  limits:\n    - type: Container\n      default:\n        cpu: 500m\n        memory: 256Mi\n      defaultRequest:\n        cpu: 100m\n        memory: 128Mi\n      max:\n        cpu: \"2\"\n        memory: 1Gi\n```\n\n" +
					"Containers that omit resource requests/limits will inherit these defaults automatically.\n\n" +
					"## Learn More\n\n" +
					"CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. " +
					"See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.",
			})
		}
	}

	return findings, nil
}
