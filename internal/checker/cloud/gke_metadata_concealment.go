package cloud

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// GKEMetadataConcealmentChecker detects GKE clusters without Workload Identity
// or metadata concealment configured, exposing pods to metadata server access.
type GKEMetadataConcealmentChecker struct{}

// Name returns the check ID.
func (c *GKEMetadataConcealmentChecker) Name() string { return "gke-metadata-concealment" }

// Description returns a human-readable description.
func (c *GKEMetadataConcealmentChecker) Description() string {
	return "Detects GKE nodes without Workload Identity or metadata concealment, enabling pod access to node service account."
}

// Categories returns the check categories.
func (c *GKEMetadataConcealmentChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCloudProvider}
}

// SupportedModes returns which scan modes this check supports.
func (c *GKEMetadataConcealmentChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *GKEMetadataConcealmentChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NodeGVR}
}

// Run executes the GKE metadata concealment check.
func (c *GKEMetadataConcealmentChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gke-metadata-concealment check: %w", err)
	}

	nodes := resources.List(NodeGVR)
	if detectProvider(nodes) != ProviderGKE {
		return nil, nil
	}

	for _, node := range nodes {
		labels := node.GetLabels()
		if labels == nil {
			continue
		}

		// Check for Workload Identity — indicated by iam.gke.io/gke-metadata-server-enabled label.
		if labels["iam.gke.io/gke-metadata-server-enabled"] == "true" {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "gke-metadata-concealment",
			Severity: checker.SeverityHigh,
			Resource: node.GetName(),
			Kind:     "Node",
			Message:  fmt.Sprintf("GKE node %q does not have Workload Identity (GKE Metadata Server) enabled.", node.GetName()),
			Remediation: "## Why This Matters\n\n" +
				"Without Workload Identity, pods can access the GCE metadata server at 169.254.169.254 and retrieve the node's " +
				"service account token. This grants every pod on the node the full IAM permissions of that service account, enabling cloud privilege escalation.\n\n" +
				"## How to Fix\n\n" +
				"Enable GKE Workload Identity on the cluster and node pools:\n\n" +
				"```yaml\n# Enable Workload Identity on the cluster:\n# gcloud container clusters update CLUSTER \\\n#   --workload-pool=PROJECT_ID.svc.id.goog\n\n# Enable on node pool:\n# gcloud container node-pools update POOL \\\n#   --cluster CLUSTER \\\n#   --workload-metadata=GKE_METADATA\n```\n\n" +
				"Then annotate Kubernetes service accounts to bind them to specific GCP service accounts with least-privilege IAM roles.\n\n" +
				"## Learn More\n\n" +
				"See https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity for setup instructions and migration from node-level service accounts.",
		})
	}

	return findings, nil
}
