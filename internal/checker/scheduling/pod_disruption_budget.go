package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// PodDisruptionBudgetChecker detects Deployments and StatefulSets with replicas > 1
// that are missing a PodDisruptionBudget. Without a PDB, all replicas can be evicted
// simultaneously during node drain.
type PodDisruptionBudgetChecker struct{}

// Name returns the kebab-case check ID.
func (c *PodDisruptionBudgetChecker) Name() string { return "pod-disruption-budget" }

// Description returns a human-readable description.
func (c *PodDisruptionBudgetChecker) Description() string {
	return "Detects Deployments/StatefulSets with replicas > 1 missing a PodDisruptionBudget."
}

// Categories returns the check categories.
func (c *PodDisruptionBudgetChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *PodDisruptionBudgetChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PodDisruptionBudgetChecker) RequiredResources() []schema.GroupVersionResource {
	gvrs := workload.GVRs()
	return append(gvrs, PodDisruptionBudgetGVR)
}

// scalableGVRs are the workload kinds that support replicas and benefit from PDBs.
var scalableGVRs = []schema.GroupVersionResource{
	{Group: "apps", Version: "v1", Resource: "deployments"},
	{Group: "apps", Version: "v1", Resource: "statefulsets"},
}

// Run executes the pod-disruption-budget check.
func (c *PodDisruptionBudgetChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("pod-disruption-budget check: %w", err)
	}

	// Build a set of PDB-covered workload names per namespace.
	pdbCoverage := buildPDBCoverage(resources)

	var findings []checker.Finding

	for _, gvr := range scalableGVRs {
		objs := resources.List(gvr)
		kind := kindForScalableGVR(gvr)

		for i := range objs {
			obj := &objs[i]
			replicas := getReplicas(obj)
			if replicas <= 1 {
				continue
			}

			ns := obj.GetNamespace()
			name := obj.GetName()

			if isPDBCovered(pdbCoverage, ns, obj) {
				continue
			}

			findings = append(findings, checker.Finding{
				Checker:   "pod-disruption-budget",
				Severity:  checker.SeverityLow,
				Resource:  name,
				Namespace: ns,
				Kind:      kind,
				Message:   fmt.Sprintf("%s %q has %d replicas but no matching PodDisruptionBudget; all replicas can be evicted simultaneously.", kind, name, replicas),
				Remediation: "## Why This Matters\n\n" +
					"Without a PodDisruptionBudget, Kubernetes can evict all replicas of your workload simultaneously " +
					"during voluntary disruptions like node drains, cluster upgrades, or autoscaler scale-downs. " +
					"This causes complete service downtime even though you have multiple replicas.\n\n" +
					"## How to Fix\n\n" +
					"Create a PodDisruptionBudget that matches your workload's pod labels:\n\n" +
					"```yaml\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: my-app-pdb\nspec:\n  minAvailable: 1              # Or use maxUnavailable: 1\n  selector:\n    matchLabels:\n      app: my-app              # Must match your Deployment/StatefulSet pod labels\n```\n\n" +
					"Use `minAvailable` to guarantee a minimum number of running pods, or `maxUnavailable` to limit how many can be down at once.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes PodDisruptionBudget documentation for details on voluntary disruption handling. " +
					"PDBs are essential for production workloads that need high availability during cluster maintenance.",
			})
		}
	}

	return findings, nil
}

// buildPDBCoverage returns a map of namespace → list of PDB matchLabels selectors.
func buildPDBCoverage(resources *checker.ResourceCache) map[string][]map[string]string {
	coverage := make(map[string][]map[string]string)
	pdbs := resources.List(PodDisruptionBudgetGVR)

	for i := range pdbs {
		pdb := &pdbs[i]
		ns := pdb.GetNamespace()

		labels, found, err := unstructured.NestedStringMap(pdb.Object, "spec", "selector", "matchLabels")
		if err != nil || !found || len(labels) == 0 {
			continue
		}
		coverage[ns] = append(coverage[ns], labels)
	}
	return coverage
}

// isPDBCovered checks if a workload's pod template labels match any PDB selector in its namespace.
func isPDBCovered(pdbCoverage map[string][]map[string]string, ns string, obj *unstructured.Unstructured) bool {
	selectors := pdbCoverage[ns]
	if len(selectors) == 0 {
		return false
	}

	// Get the workload's pod template labels.
	templateLabels, found, err := unstructured.NestedStringMap(obj.Object, "spec", "template", "metadata", "labels")
	if err != nil || !found {
		return false
	}

	for _, selector := range selectors {
		if labelsMatch(selector, templateLabels) {
			return true
		}
	}
	return false
}

// labelsMatch returns true if all selector labels exist with matching values in the target labels.
func labelsMatch(selector, target map[string]string) bool {
	for k, v := range selector {
		if target[k] != v {
			return false
		}
	}
	return true
}

// kindForScalableGVR maps a scalable GVR to its Kind string.
func kindForScalableGVR(gvr schema.GroupVersionResource) string {
	switch gvr.Resource {
	case "deployments":
		return "Deployment"
	case "statefulsets":
		return "StatefulSet"
	default:
		return gvr.Resource
	}
}
