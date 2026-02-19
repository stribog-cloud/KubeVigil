package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// AuditLoggingChecker detects when API server audit logging is not configured.
type AuditLoggingChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *AuditLoggingChecker) Name() string { return "audit-logging" }

// Description returns a human-readable summary of what this check detects.
func (c *AuditLoggingChecker) Description() string {
	return "Detects API server audit logging not configured or misconfigured."
}

// Categories returns the security categories this check belongs to.
func (c *AuditLoggingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *AuditLoggingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *AuditLoggingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ConfigMapGVR}
}

// Run executes the check against cached resources and returns any findings.
func (c *AuditLoggingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("audit-logging check: %w", err)
	}

	// Look for audit policy in kube-system ConfigMaps.
	cms := resources.ListNamespaced(ConfigMapGVR, "kube-system")
	var findings []checker.Finding

	auditPolicyFound := false
	for i := range cms {
		cm := &cms[i]
		name := cm.GetName()

		// Check for audit policy ConfigMap or kubeadm-config with audit flags.
		if name == "audit-policy" || name == "kube-apiserver-audit-policy" {
			auditPolicyFound = true
			break
		}

		if name == "kubeadm-config" || name == "kube-apiserver" {
			data, found, _ := unstructured.NestedStringMap(cm.Object, "data")
			if found {
				for _, v := range data {
					if containsFlag(v, "--audit-policy-file") || containsFlag(v, "--audit-log-path") {
						auditPolicyFound = true
						break
					}
				}
			}
		}
	}

	if len(cms) > 0 && !auditPolicyFound {
		findings = append(findings, checker.Finding{
			Checker:   "audit-logging",
			Severity:  checker.SeverityHigh,
			Resource:  "kube-apiserver",
			Namespace: "kube-system",
			Kind:      "ConfigMap",
			Message:   "No audit policy configuration found; API server audit logging may not be enabled.",
			Remediation: "## Why This Matters\n\n" +
				"Without audit logging, there is no record of who accessed the API server, what they changed, or when. " +
				"This makes it impossible to detect unauthorized access, investigate security incidents, or satisfy compliance requirements.\n\n" +
				"## How to Fix\n\n" +
				"Configure API server audit logging with a policy file and log backend:\n\n" +
				"```yaml\n# kube-apiserver flags:\n# --audit-policy-file=/etc/kubernetes/audit-policy.yaml\n# --audit-log-path=/var/log/kubernetes/audit.log\n# --audit-log-maxage=30\n# --audit-log-maxbackup=10\n# --audit-log-maxsize=100\n```\n\n" +
				"On managed clusters, enable audit logging through the cloud provider console (e.g., EKS Control Plane Logging, GKE Admin Activity logs).\n\n" +
				"## Learn More\n\n" +
				"CIS Kubernetes Benchmark 3.2.1 requires audit logging to be enabled. " +
				"See https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/ for audit policy configuration and webhook backends.",
		})
	}

	return findings, nil
}
