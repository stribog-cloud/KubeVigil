package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ExternalSecretsSyncChecker checks for sync failures, missing SecretStore references,
// or stale externally-managed secrets when the ExternalSecrets operator is present.
type ExternalSecretsSyncChecker struct{}

// Name returns the kebab-case check ID.
func (c *ExternalSecretsSyncChecker) Name() string { return "external-secrets-sync" }

// Description returns a human-readable description.
func (c *ExternalSecretsSyncChecker) Description() string {
	return "When the ExternalSecrets operator is present, checks for sync failures, missing SecretStore references, or stale externally-managed secrets."
}

// Categories returns the check categories.
func (c *ExternalSecretsSyncChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
// This check is live-only since ExternalSecret status is only available at runtime.
func (c *ExternalSecretsSyncChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ExternalSecretsSyncChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ExternalSecretGVR, SecretStoreGVR, ClusterSecretStoreGVR}
}

// Run executes the external-secrets-sync check against ExternalSecret resources in the cache.
func (c *ExternalSecretsSyncChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("external-secrets-sync check: %w", err)
	}

	externalSecrets := cache.List(ExternalSecretGVR)
	if len(externalSecrets) == 0 {
		return nil, nil
	}

	// Build lookup sets for SecretStore and ClusterSecretStore resources.
	secretStores := buildStoreIndex(cache.List(SecretStoreGVR))
	clusterSecretStores := buildStoreNameSet(cache.List(ClusterSecretStoreGVR))

	var findings []checker.Finding

	for i := range externalSecrets {
		es := &externalSecrets[i]
		name := es.GetName()
		namespace := es.GetNamespace()

		// Check sync status via conditions.
		findings = append(findings, checkSyncStatus(es, name, namespace)...)

		// Check SecretStore reference existence.
		findings = append(findings, checkStoreRef(es, name, namespace, secretStores, clusterSecretStores)...)
	}

	return findings, nil
}

// checkSyncStatus checks the Ready condition on an ExternalSecret.
func checkSyncStatus(es *unstructured.Unstructured, name, namespace string) []checker.Finding {
	conditions, found, err := unstructured.NestedSlice(es.Object, "status", "conditions")
	if err != nil || !found || len(conditions) == 0 {
		// No status conditions — sync status unknown, flag it.
		return []checker.Finding{
			{
				Checker:   "external-secrets-sync",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: namespace,
				Kind:      "ExternalSecret",
				Message:   fmt.Sprintf("ExternalSecret %q in namespace %q has no status conditions — sync status is unknown", name, namespace),
				Remediation: "## Why This Matters\n\n" +
					"An ExternalSecret without status conditions suggests the External Secrets operator " +
					"has not processed it. The target Secret may be missing or contain stale data, " +
					"leaving your workloads without valid credentials.\n\n" +
					"## How to Fix\n\n" +
					"Verify the ExternalSecret spec and ensure the operator is running:\n\n" +
					"```yaml\napiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: " + name + "\nspec:\n  refreshInterval: 1h\n  secretStoreRef:\n    name: my-store\n    kind: SecretStore\n  target:\n    name: " + name + "\n```\n\n" +
					fmt.Sprintf("Run `kubectl describe externalsecret %s -n %s` and check operator pod logs ", name, namespace) +
					"to diagnose the issue.\n\n" +
					"## Learn More\n\n" +
					"See the External Secrets Operator troubleshooting guide for common sync issues.",
				FieldPath: ".status.conditions",
			},
		}
	}

	var findings []checker.Finding
	for _, cond := range conditions {
		condMap, ok := cond.(map[string]interface{})
		if !ok {
			continue
		}
		condType, _ := condMap["type"].(string)
		condStatus, _ := condMap["status"].(string)

		if condType == "Ready" && condStatus != "True" {
			findings = append(findings, checker.Finding{
				Checker:   "external-secrets-sync",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: namespace,
				Kind:      "ExternalSecret",
				Message:   fmt.Sprintf("ExternalSecret %q in namespace %q has sync failure: condition Ready is %s", name, namespace, condStatus),
				Remediation: "## Why This Matters\n\n" +
					"A sync failure means the target Kubernetes Secret is not being updated from " +
					"the external secret provider. Your workloads may be using expired or revoked " +
					"credentials, leading to authentication failures or security gaps.\n\n" +
					"## How to Fix\n\n" +
					"Check the SecretStore connectivity, credentials, and provider configuration:\n\n" +
					"```yaml\napiVersion: external-secrets.io/v1beta1\nkind: SecretStore\nmetadata:\n  name: my-store\nspec:\n  provider:\n    aws:\n      service: SecretsManager\n      region: us-east-1\n```\n\n" +
					fmt.Sprintf("Run `kubectl describe externalsecret %s -n %s` to see the failure reason ", name, namespace) +
					"and verify the provider credentials are still valid.\n\n" +
					"## Learn More\n\n" +
					"See the External Secrets Operator documentation for provider-specific " +
					"troubleshooting guides and SecretStore configuration examples.",
				FieldPath: ".status.conditions",
			})
		}
	}
	return findings
}

// checkStoreRef verifies that the referenced SecretStore or ClusterSecretStore exists.
func checkStoreRef(es *unstructured.Unstructured, name, namespace string, secretStores map[string]map[string]bool, clusterSecretStores map[string]bool) []checker.Finding {
	storeRefName, _, _ := unstructured.NestedString(es.Object, "spec", "secretStoreRef", "name")
	storeRefKind, _, _ := unstructured.NestedString(es.Object, "spec", "secretStoreRef", "kind")

	if storeRefName == "" {
		return nil
	}

	// Default kind is "SecretStore" if not specified.
	if storeRefKind == "" {
		storeRefKind = "SecretStore"
	}

	switch storeRefKind {
	case "ClusterSecretStore":
		if !clusterSecretStores[storeRefName] {
			return []checker.Finding{
				{
					Checker:   "external-secrets-sync",
					Severity:  checker.SeverityMedium,
					Resource:  name,
					Namespace: namespace,
					Kind:      "ExternalSecret",
					Message:   fmt.Sprintf("ExternalSecret %q references ClusterSecretStore %q which does not exist", name, storeRefName),
					Remediation: "## Why This Matters\n\n" +
						"The ExternalSecret references a ClusterSecretStore that does not exist. " +
						"Without a valid store, the operator cannot connect to the external secret " +
						"provider, so the target Secret will never be created or updated.\n\n" +
						"## How to Fix\n\n" +
						"Create the missing ClusterSecretStore, or update the ExternalSecret to " +
						"reference an existing one:\n\n" +
						"```yaml\napiVersion: external-secrets.io/v1beta1\nkind: ClusterSecretStore\nmetadata:\n  name: " + storeRefName + "\nspec:\n  provider:\n    aws:\n      service: SecretsManager\n      region: us-east-1\n```\n\n" +
						"Verify the store is ready: `kubectl get clustersecretstore " + storeRefName + "`\n\n" +
						"## Learn More\n\n" +
						"See the External Secrets Operator ClusterSecretStore documentation for " +
						"provider setup guides covering AWS, GCP, Azure, Vault, and more.",
					FieldPath: ".spec.secretStoreRef",
				},
			}
		}
	default: // "SecretStore"
		nsStores := secretStores[namespace]
		if !nsStores[storeRefName] {
			return []checker.Finding{
				{
					Checker:   "external-secrets-sync",
					Severity:  checker.SeverityMedium,
					Resource:  name,
					Namespace: namespace,
					Kind:      "ExternalSecret",
					Message:   fmt.Sprintf("ExternalSecret %q references SecretStore %q which does not exist", name, storeRefName),
					Remediation: "## Why This Matters\n\n" +
						"The ExternalSecret references a SecretStore that does not exist in this " +
						"namespace. Without a valid store, the operator cannot connect to the " +
						"external secret provider, so the target Secret will never be populated.\n\n" +
						"## How to Fix\n\n" +
						"Create the missing SecretStore, or update the ExternalSecret to reference " +
						"an existing one:\n\n" +
						"```yaml\napiVersion: external-secrets.io/v1beta1\nkind: SecretStore\nmetadata:\n  name: " + storeRefName + "\n  namespace: " + namespace + "\nspec:\n  provider:\n    aws:\n      service: SecretsManager\n      region: us-east-1\n```\n\n" +
						"Verify the store is ready: `kubectl get secretstore " + storeRefName + " -n " + namespace + "`\n\n" +
						"## Learn More\n\n" +
						"See the External Secrets Operator SecretStore documentation for " +
						"provider setup guides covering AWS, GCP, Azure, Vault, and more.",
					FieldPath: ".spec.secretStoreRef",
				},
			}
		}
	}

	return nil
}

// buildStoreIndex builds a map of namespace -> set of store names for namespaced SecretStores.
func buildStoreIndex(stores []unstructured.Unstructured) map[string]map[string]bool {
	index := make(map[string]map[string]bool)
	for i := range stores {
		s := &stores[i]
		ns := s.GetNamespace()
		name := s.GetName()
		if index[ns] == nil {
			index[ns] = make(map[string]bool)
		}
		index[ns][name] = true
	}
	return index
}

// buildStoreNameSet builds a set of store names for cluster-scoped ClusterSecretStores.
func buildStoreNameSet(stores []unstructured.Unstructured) map[string]bool {
	set := make(map[string]bool)
	for i := range stores {
		set[stores[i].GetName()] = true
	}
	return set
}
