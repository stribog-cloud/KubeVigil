package rbac

import (
	"context"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// cloudIAMAnnotations maps cloud IAM binding annotations to their provider name.
var cloudIAMAnnotations = map[string]string{
	"eks.amazonaws.com/role-arn":        "AWS IRSA",
	"iam.gke.io/gcp-service-account":    "GCP Workload Identity",
	"azure.workload.identity/client-id": "Azure Workload Identity",
}

// sortedCloudAnnotationKeys returns the annotation keys in sorted order
// for deterministic output.
func sortedCloudAnnotationKeys() []string {
	keys := make([]string, 0, len(cloudIAMAnnotations))
	for k := range cloudIAMAnnotations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CloudIAMBindingChecker detects ServiceAccounts with cloud IAM bindings
// (AWS IRSA, GCP Workload Identity, Azure Workload Identity).
// Cloud IAM bindings grant the pod access to cloud provider APIs and should
// be reviewed to ensure the associated IAM role follows least-privilege.
type CloudIAMBindingChecker struct{}

// Name returns the kebab-case check ID.
func (c *CloudIAMBindingChecker) Name() string { return "cloud-iam-binding" }

// Description returns a human-readable description.
func (c *CloudIAMBindingChecker) Description() string {
	return "Detects ServiceAccounts with cloud IAM bindings (AWS IRSA, GCP Workload Identity, Azure Workload Identity) for review."
}

// Categories returns the check categories.
func (c *CloudIAMBindingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *CloudIAMBindingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CloudIAMBindingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{serviceAccountGVR}
}

// Run executes the cloud-iam-binding check against all ServiceAccount resources in the cache.
func (c *CloudIAMBindingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cloud-iam-binding check: %w", err)
	}

	var findings []checker.Finding
	sortedKeys := sortedCloudAnnotationKeys()

	for _, obj := range resources.List(serviceAccountGVR) {
		annotations := obj.GetAnnotations()
		if len(annotations) == 0 {
			continue
		}

		for _, ann := range sortedKeys {
			provider := cloudIAMAnnotations[ann]
			val, ok := annotations[ann]
			if !ok {
				continue
			}
			findings = append(findings, checker.Finding{
				Checker:   "cloud-iam-binding",
				Severity:  checker.SeverityMedium,
				Resource:  obj.GetName(),
				Namespace: obj.GetNamespace(),
				Kind:      "ServiceAccount",
				Message:   fmt.Sprintf("ServiceAccount %q has %s binding (%s=%s). Verify the cloud IAM role follows least-privilege.", obj.GetName(), provider, ann, val),
				Remediation: "## Why This Matters\n\n" +
					"Cloud IAM bindings (AWS IRSA, GCP Workload Identity, Azure Workload Identity) grant pods " +
					"direct access to cloud provider APIs such as S3, BigQuery, or Key Vault. If the associated " +
					"cloud IAM role has overly broad permissions, a compromised pod can access, modify, or delete " +
					"cloud resources far beyond what the workload requires.\n\n" +
					"## How to Fix\n\n" +
					"Audit the referenced cloud IAM role and apply least-privilege:\n\n" +
					"```yaml\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: my-app\n  annotations:\n    # AWS — use a role scoped to specific resources:\n    eks.amazonaws.com/role-arn: arn:aws:iam::123:role/my-app-minimal\n    # GCP — use a service account with only needed permissions:\n    iam.gke.io/gcp-service-account: my-app@project.iam.gserviceaccount.com\n```\n\n" +
					"Ensure the cloud IAM role/policy has no wildcard actions or resources. " +
					"Use condition keys to restrict access by namespace or service account where supported.\n\n" +
					"## Learn More\n\n" +
					"See the AWS IRSA, GCP Workload Identity, or Azure Workload Identity documentation for " +
					"provider-specific guidance on scoping cloud IAM permissions for Kubernetes workloads.",
				FieldPath: fmt.Sprintf(".metadata.annotations[%s]", ann),
			})
		}
	}

	return findings, nil
}
