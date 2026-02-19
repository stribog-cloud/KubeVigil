package cloud

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// EKSIMDSAccessChecker detects pods on EKS that can access the EC2 Instance
// Metadata Service (IMDS) at 169.254.169.254. Without blocking, any pod can
// steal the node's IAM role credentials.
type EKSIMDSAccessChecker struct{}

// Name returns the check ID.
func (c *EKSIMDSAccessChecker) Name() string { return "eks-imds-access" }

// Description returns a human-readable description.
func (c *EKSIMDSAccessChecker) Description() string {
	return "Detects EKS pods that can access EC2 Instance Metadata Service (IMDS), enabling IAM credential theft."
}

// Categories returns the check categories.
func (c *EKSIMDSAccessChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCloudProvider}
}

// SupportedModes returns which scan modes this check supports.
func (c *EKSIMDSAccessChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EKSIMDSAccessChecker) RequiredResources() []schema.GroupVersionResource {
	gvrs := workload.GVRs()
	return append(gvrs, NodeGVR, NetworkPolicyGVR)
}

// Run executes the EKS IMDS access check.
func (c *EKSIMDSAccessChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("eks-imds-access check: %w", err)
	}

	// Only run on EKS clusters.
	nodes := resources.List(NodeGVR)
	if detectProvider(nodes) != ProviderEKS {
		return nil, nil
	}

	// Check if there are NetworkPolicies blocking IMDS IP (169.254.169.254).
	hasIMDSBlock := hasNetworkPolicyBlockingIMDS(resources.List(NetworkPolicyGVR))

	specs := workload.ExtractPodSpecs(resources)
	for i := range specs {
		info := &specs[i]
		// Pods with hostNetwork can always access IMDS.
		if info.Spec.HostNetwork {
			findings = append(findings, checker.Finding{
				Checker:   "eks-imds-access",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("Pod %q uses hostNetwork and can access IMDS at 169.254.169.254 to steal IAM credentials.", info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"Pods with hostNetwork share the node's network stack and can reach the EC2 Instance Metadata Service (169.254.169.254). " +
					"This allows any container to steal the node's IAM role credentials and escalate privileges across your AWS account.\n\n" +
					"## How to Fix\n\n" +
					"Disable hostNetwork unless absolutely required, and enforce IMDSv2 with hop limit 1:\n\n" +
					"```yaml\nspec:\n  hostNetwork: false    # Remove host network access\n---\n# On EC2 instances, enforce IMDSv2 with hop limit 1:\n# aws ec2 modify-instance-metadata-options \\\n#   --instance-id i-xxx \\\n#   --http-tokens required \\\n#   --http-put-response-hop-limit 1\n```\n\n" +
					"Use IRSA (IAM Roles for Service Accounts) to grant pod-level AWS permissions instead of relying on node IAM roles.\n\n" +
					"## Learn More\n\n" +
					"See https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html for IRSA setup and IMDS hardening best practices.",
				FieldPath: ".spec.hostNetwork",
			})
		} else if !hasIMDSBlock {
			findings = append(findings, checker.Finding{
				Checker:   "eks-imds-access",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("Pod %q in namespace %q has no NetworkPolicy blocking IMDS access (169.254.169.254).", info.ResourceName, info.Namespace),
				Remediation: "## Why This Matters\n\n" +
					"Without a NetworkPolicy blocking the IMDS endpoint (169.254.169.254), any pod can query the metadata service to obtain " +
					"the node's IAM role credentials. Attackers who compromise a container can immediately escalate to cloud-level access.\n\n" +
					"## How to Fix\n\n" +
					"Deploy a NetworkPolicy in each namespace to block egress to the IMDS IP:\n\n" +
					"```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: block-imds\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n            except: [169.254.169.254/32]\n```\n\n" +
					"Also enforce IMDSv2 with hop limit 1 on all EC2 instances and use IRSA for pod-level IAM permissions.\n\n" +
					"## Learn More\n\n" +
					"See https://docs.aws.amazon.com/eks/latest/best-practices/iam.html for EKS IAM security best practices and IMDS restriction patterns.",
			})
		}
	}

	return findings, nil
}

// hasNetworkPolicyBlockingIMDS checks if any NetworkPolicy blocks the IMDS IP.
func hasNetworkPolicyBlockingIMDS(policies []unstructured.Unstructured) bool {
	for _, policy := range policies {
		policyTypes, _, _ := unstructured.NestedStringSlice(policy.Object, "spec", "policyTypes")
		for _, pt := range policyTypes {
			if pt == "Egress" {
				// If there's an egress policy, it might be blocking IMDS.
				// A default-deny egress or specific CIDR block would work.
				egress, _, _ := unstructured.NestedSlice(policy.Object, "spec", "egress")
				if len(egress) == 0 {
					// Empty egress = default deny all egress.
					return true
				}
			}
		}
	}
	return false
}
