package scheduling

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// defaultUntrustedLabelPatterns are node label patterns that may indicate untrusted nodes.
var defaultUntrustedLabelPatterns = []string{
	"spot",
	"preemptible",
	"ephemeral",
}

// NodeAffinityUntrustedChecker detects workloads with nodeAffinity or nodeSelector
// targeting nodes with labels that may indicate untrusted or ephemeral nodes.
type NodeAffinityUntrustedChecker struct{}

// Name returns the kebab-case check ID.
func (c *NodeAffinityUntrustedChecker) Name() string { return "node-affinity-untrusted" }

// Description returns a human-readable description.
func (c *NodeAffinityUntrustedChecker) Description() string {
	return "Detects workloads with nodeAffinity or nodeSelector targeting potentially untrusted or ephemeral nodes."
}

// Categories returns the check categories.
func (c *NodeAffinityUntrustedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *NodeAffinityUntrustedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *NodeAffinityUntrustedChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the node-affinity-untrusted check.
func (c *NodeAffinityUntrustedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("node-affinity-untrusted check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		// Check nodeSelector for untrusted labels.
		for key, val := range info.Spec.NodeSelector {
			if matchesUntrusted(key) || matchesUntrusted(val) {
				findings = append(findings, checker.Finding{
					Checker:   "node-affinity-untrusted",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Message:   fmt.Sprintf("%s %q has nodeSelector targeting potentially untrusted nodes: %s=%s", info.Kind, info.ResourceName, key, val),
					Remediation: "## Why This Matters\n\n" +
						"Spot, preemptible, and ephemeral nodes can be reclaimed by the cloud provider at any time with minimal notice. " +
						"Running security-sensitive workloads on these nodes risks sudden termination and potential data loss. " +
						"Shared ephemeral infrastructure may also have weaker isolation guarantees.\n\n" +
						"## How to Fix\n\n" +
						"Target trusted, dedicated node pools for sensitive workloads:\n\n" +
						"```yaml\nspec:\n  nodeSelector:\n    node-pool: trusted-dedicated\n    # Avoid labels like:\n    # cloud.google.com/gke-spot: \"true\"\n    # kubernetes.azure.com/scalesetpriority: spot\n```\n\n" +
						"Reserve spot and preemptible nodes for fault-tolerant batch workloads that can handle sudden termination.\n\n" +
						"## Learn More\n\n" +
						"See your cloud provider's documentation on spot/preemptible node management. The Kubernetes scheduling " +
						"documentation covers nodeSelector and nodeAffinity best practices for workload placement.",
					FieldPath: ".spec.nodeSelector",
				})
				break
			}
		}

		// Check nodeAffinity for untrusted labels.
		if info.Spec.Affinity != nil && info.Spec.Affinity.NodeAffinity != nil {
			na := info.Spec.Affinity.NodeAffinity
			if na.RequiredDuringSchedulingIgnoredDuringExecution != nil {
				for _, term := range na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
					for _, expr := range term.MatchExpressions {
						if matchesUntrusted(expr.Key) || matchesUntrustedValues(expr.Values) {
							findings = append(findings, checker.Finding{
								Checker:   "node-affinity-untrusted",
								Severity:  checker.SeverityMedium,
								Resource:  info.ResourceName,
								Namespace: info.Namespace,
								Kind:      info.Kind,
								Message:   fmt.Sprintf("%s %q has nodeAffinity targeting potentially untrusted nodes via label key %q.", info.Kind, info.ResourceName, expr.Key),
								Remediation: "## Why This Matters\n\n" +
									"Node affinity rules targeting spot, preemptible, or ephemeral nodes direct sensitive workloads to infrastructure " +
									"that can be terminated without notice. This puts availability at risk and may violate data residency requirements " +
									"if workloads are moved unexpectedly.\n\n" +
									"## How to Fix\n\n" +
									"Update the nodeAffinity to target trusted, stable node pools:\n\n" +
									"```yaml\nspec:\n  affinity:\n    nodeAffinity:\n      requiredDuringSchedulingIgnoredDuringExecution:\n        nodeSelectorTerms:\n          - matchExpressions:\n              - key: node-pool\n                operator: In\n                values: [trusted-dedicated]\n```\n\n" +
									"Use preferredDuringScheduling for cost optimization of non-critical workloads on spot nodes.\n\n" +
									"## Learn More\n\n" +
									"See the Kubernetes node affinity documentation and your cloud provider's guidance on spot instance best practices. " +
									"The CIS Benchmark recommends explicit node targeting for security-sensitive workloads.",
								FieldPath: ".spec.affinity.nodeAffinity",
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// matchesUntrusted checks if a string contains any untrusted label pattern.
func matchesUntrusted(s string) bool {
	lower := strings.ToLower(s)
	for _, pattern := range defaultUntrustedLabelPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// matchesUntrustedValues checks if any value in the slice matches untrusted patterns.
func matchesUntrustedValues(values []string) bool {
	for _, v := range values {
		if matchesUntrusted(v) {
			return true
		}
	}
	return false
}
