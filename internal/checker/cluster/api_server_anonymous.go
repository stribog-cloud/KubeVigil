package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// APIServerAnonymousChecker detects anonymous authentication on the API server
// by checking for ConfigMaps or Pods in kube-system with API server args.
type APIServerAnonymousChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *APIServerAnonymousChecker) Name() string { return "api-server-anonymous" }

// Description returns a human-readable summary of what this check detects.
func (c *APIServerAnonymousChecker) Description() string {
	return "Detects API server with anonymous authentication enabled."
}

// Categories returns the security categories this check belongs to.
func (c *APIServerAnonymousChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *APIServerAnonymousChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *APIServerAnonymousChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ConfigMapGVR}
}

// Run executes the check against cached resources and returns any findings.
func (c *APIServerAnonymousChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("api-server-anonymous check: %w", err)
	}

	// Look for kube-apiserver ConfigMaps or kubeadm-config that expose API server flags.
	cms := resources.ListNamespaced(ConfigMapGVR, "kube-system")
	var findings []checker.Finding

	for i := range cms {
		cm := &cms[i]
		name := cm.GetName()
		if name != "kubeadm-config" && name != "kube-apiserver" {
			continue
		}

		data, found, _ := unstructured.NestedStringMap(cm.Object, "data")
		if !found {
			continue
		}

		for _, v := range data {
			if containsFlag(v, "--anonymous-auth=true") {
				findings = append(findings, checker.Finding{
					Checker:   "api-server-anonymous",
					Severity:  checker.SeverityHigh,
					Resource:  name,
					Namespace: "kube-system",
					Kind:      "ConfigMap",
					Message:   "API server has anonymous authentication enabled (--anonymous-auth=true).",
					Remediation: "## Why This Matters\n\n" +
						"Anonymous authentication allows any unauthenticated user to make API server requests. " +
						"Attackers can enumerate cluster resources, discover services, and exploit misconfigured RBAC rules that grant permissions to system:anonymous or system:unauthenticated.\n\n" +
						"## How to Fix\n\n" +
						"Disable anonymous authentication on the API server:\n\n" +
						"```yaml\n# In kube-apiserver manifest or configuration:\napiVersion: v1\nkind: Pod\nmetadata:\n  name: kube-apiserver\nspec:\n  containers:\n    - command:\n        - kube-apiserver\n        - --anonymous-auth=false\n```\n\n" +
						"On managed clusters (EKS, GKE, AKS), anonymous auth is typically disabled by default. Verify with your provider's documentation.\n\n" +
						"## Learn More\n\n" +
						"CIS Kubernetes Benchmark 1.2.1 requires anonymous authentication to be disabled. " +
						"See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests for details.",
				})
				return findings, nil
			}
		}
	}

	return findings, nil
}

// containsFlag checks if a config string contains the specified flag.
func containsFlag(config, flag string) bool {
	return config != "" && contains(config, flag)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
