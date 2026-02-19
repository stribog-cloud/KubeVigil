package cluster

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)`)

// ComponentVersionsChecker detects version skew between control plane and kubelets.
type ComponentVersionsChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *ComponentVersionsChecker) Name() string { return "component-versions" }

// Description returns a human-readable summary of what this check detects.
func (c *ComponentVersionsChecker) Description() string {
	return "Detects kubelet version skew exceeding the supported range relative to other nodes."
}

// Categories returns the security categories this check belongs to.
func (c *ComponentVersionsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *ComponentVersionsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *ComponentVersionsChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NodeGVR}
}

// Run executes the check against cached resources and returns any findings.
func (c *ComponentVersionsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("component-versions check: %w", err)
	}

	nodes := resources.List(NodeGVR)
	var findings []checker.Finding

	// Collect kubelet versions.
	var maxMinor int
	type nodeVersion struct {
		name  string
		minor int
	}
	var nodeVersions []nodeVersion

	for i := range nodes {
		node := &nodes[i]
		kubeletVer, _, _ := unstructured.NestedString(node.Object, "status", "nodeInfo", "kubeletVersion")
		if kubeletVer == "" {
			continue
		}
		matches := versionRe.FindStringSubmatch(kubeletVer)
		if len(matches) < 3 {
			continue
		}
		minor, err := strconv.Atoi(matches[2])
		if err != nil {
			continue
		}
		nodeVersions = append(nodeVersions, nodeVersion{name: node.GetName(), minor: minor})
		if minor > maxMinor {
			maxMinor = minor
		}
	}

	// Flag nodes more than 2 minor versions behind the newest.
	for _, nv := range nodeVersions {
		if maxMinor-nv.minor > 2 {
			findings = append(findings, checker.Finding{
				Checker:  "component-versions",
				Severity: checker.SeverityMedium,
				Resource: nv.name,
				Kind:     "Node",
				Message:  fmt.Sprintf("Node %q kubelet minor version is %d versions behind the newest node (1.%d vs 1.%d).", nv.name, maxMinor-nv.minor, nv.minor, maxMinor),
				Remediation: "## Why This Matters\n\n" +
					"Kubernetes supports kubelets within 2 minor versions of the API server. Nodes running older versions miss security patches, " +
					"bug fixes, and may exhibit inconsistent behavior with newer API features. Version skew can also cause workload scheduling failures.\n\n" +
					"## How to Fix\n\n" +
					"Upgrade the kubelet on outdated nodes to match the cluster version:\n\n" +
					"```yaml\n# For self-managed nodes:\n# apt-get update && apt-get install -y \\\n#   kubelet=1.XX.Y-00 kubectl=1.XX.Y-00\n# systemctl daemon-reload && systemctl restart kubelet\n\n# For managed node pools (EKS/GKE/AKS):\n# Update the node group/pool version in your cloud console\n```\n\n" +
					"Upgrade nodes in a rolling fashion, draining each node before upgrading to avoid workload disruption.\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/releases/version-skew-policy/ for the official version skew policy between control plane and kubelet components.",
			})
		}
	}

	return findings, nil
}
