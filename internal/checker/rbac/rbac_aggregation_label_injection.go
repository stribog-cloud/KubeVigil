package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// aggregationLabelKeys are the well-known ClusterRole aggregation selector labels used by the
// built-in admin/edit/view ClusterRoles to pull in rules from other ClusterRoles.
var aggregationLabelKeys = []string{
	"rbac.authorization.k8s.io/aggregate-to-admin",
	"rbac.authorization.k8s.io/aggregate-to-edit",
	"rbac.authorization.k8s.io/aggregate-to-view",
}

// bootstrapClusterRoles are the built-in ClusterRoles exempt from this check — they are the
// aggregation targets themselves, not injected roles.
var bootstrapClusterRoles = map[string]bool{
	"admin":         true,
	"edit":          true,
	"view":          true,
	"cluster-admin": true,
}

// AggregationLabelInjectionChecker detects custom ClusterRoles labeled with a built-in
// aggregation selector (rbac.authorization.k8s.io/aggregate-to-{admin,edit,view}: "true"),
// letting a subject with only "create ClusterRole" permission inject arbitrary rules into
// cluster-admin-aggregated roles by labeling their own ClusterRole to match the selector.
type AggregationLabelInjectionChecker struct{}

// Name returns the kebab-case check ID.
func (c *AggregationLabelInjectionChecker) Name() string { return "rbac-aggregation-label-injection" }

// Description returns a human-readable description.
func (c *AggregationLabelInjectionChecker) Description() string {
	return "Detects custom ClusterRoles labeled to aggregate into the built-in admin/edit/view ClusterRoles."
}

// Categories returns the check categories.
func (c *AggregationLabelInjectionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *AggregationLabelInjectionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *AggregationLabelInjectionChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ClusterRoleGVR}
}

// Run executes the aggregation label injection check against all ClusterRoles in the cache.
func (c *AggregationLabelInjectionChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-aggregation-label-injection check: %w", err)
	}

	var findings []checker.Finding

	for _, obj := range resources.List(ClusterRoleGVR) {
		name := obj.GetName()
		if bootstrapClusterRoles[name] {
			continue // built-in bootstrap roles are exempt
		}

		labels := obj.GetLabels()
		if len(labels) == 0 {
			continue
		}

		for _, key := range aggregationLabelKeys {
			if labels[key] != "true" {
				continue
			}
			findings = append(findings, checker.Finding{
				Checker:   "rbac-aggregation-label-injection",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: "",
				Kind:      "ClusterRole",
				Message:   fmt.Sprintf("ClusterRole %q carries the %q aggregation label, injecting its rules into a built-in aggregated ClusterRole.", name, key),
				Remediation: "## Why This Matters\n\n" +
					"The built-in `admin`, `edit`, and `view` ClusterRoles are aggregated: Kubernetes automatically " +
					"merges the rules of any ClusterRole labeled `rbac.authorization.k8s.io/aggregate-to-<role>: \"true\"` " +
					"into them. A subject who can only create ClusterRole objects (not modify `admin`/`edit`/`view` " +
					"directly) can still inject arbitrary rules into those aggregated roles simply by applying this " +
					"label to their own ClusterRole — a documented Kubernetes RBAC privilege-escalation technique.\n\n" +
					"## How to Fix\n\n" +
					"Remove the aggregation label unless the ClusterRole is intentionally designed to extend a " +
					"built-in role, and restrict who can create ClusterRoles carrying these labels:\n\n" +
					"```yaml\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: my-custom-role\n  # Remove aggregation labels unless intentional:\n  # labels:\n  #   rbac.authorization.k8s.io/aggregate-to-admin: \"true\"\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\"]\n```\n\n" +
					"Restrict `create`/`update` on ClusterRole objects to trusted cluster administrators, and audit " +
					"any ClusterRole carrying an `aggregate-to-*` label as part of regular RBAC hygiene.\n\n" +
					"## Learn More\n\n" +
					"See MITRE ATT&CK technique T1068 (Exploitation for Privilege Escalation), CIS Kubernetes " +
					"Benchmark 5.1.1 on cluster-admin usage restriction, and the Kubernetes RBAC documentation on " +
					"ClusterRole aggregation.",
				FieldPath: fmt.Sprintf(".metadata.labels[%s]", key),
			})
			break // one finding per ClusterRole, even if multiple aggregation labels present
		}
	}

	return findings, nil
}
