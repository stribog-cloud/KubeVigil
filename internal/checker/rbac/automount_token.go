package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// AutomountTokenChecker detects workloads that auto-mount a ServiceAccount token.
// Most workloads do not call the Kubernetes API and should disable auto-mounting
// by setting spec.automountServiceAccountToken to false.
type AutomountTokenChecker struct{}

// Name returns the kebab-case check ID.
func (c *AutomountTokenChecker) Name() string { return "automount-token" }

// Description returns a human-readable description.
func (c *AutomountTokenChecker) Description() string {
	return "Detects workloads that auto-mount a ServiceAccount token without explicitly disabling it."
}

// Categories returns the check categories.
func (c *AutomountTokenChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *AutomountTokenChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *AutomountTokenChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the automount-token check against all workload resources in the cache.
func (c *AutomountTokenChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("automount-token check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		// Flag if automountServiceAccountToken is nil (defaults to true) or explicitly true.
		if info.Spec.AutomountServiceAccountToken == nil || *info.Spec.AutomountServiceAccountToken {
			findings = append(findings, checker.Finding{
				Checker:   "automount-token",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. " +
					"If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access " +
					"to enumerate resources, read secrets, or escalate privileges.\n\n" +
					"## How to Fix\n\n" +
					"Disable auto-mounting at the pod spec level for workloads that do not need API access:\n\n" +
					"```yaml\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\nspec:\n  template:\n    spec:\n      automountServiceAccountToken: false\n      containers:\n        - name: app\n          image: my-app:latest\n```\n\n" +
					"For workloads that do require API access, use projected tokens with bounded lifetime " +
					"and audience restrictions instead of the default long-lived token.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes documentation on configuring service accounts for pods and " +
					"CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.",
				FieldPath:    ".spec.automountServiceAccountToken",
				CurrentValue: info.Spec.AutomountServiceAccountToken,
				DesiredValue: false,
				FixHint: &checker.FixHint{
					Safety:      checker.FixSafe,
					Description: "Disables automatic service account token mounting.",
					Impact:      "Pods that need API access will fail without token.",
					Operation:   checker.FixOpSet,
				},
			})
		}
	}

	return findings, nil
}
