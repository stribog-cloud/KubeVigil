package secrets

import (
	"context"
	"encoding/base64"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HardcodedManifestsChecker detects hardcoded secret values in Kubernetes Secret manifests.
// When secrets are committed to version control with real values, they become available
// to anyone with repository access. External secret management tools should be used instead.
type HardcodedManifestsChecker struct{}

// Name returns the kebab-case check ID.
func (c *HardcodedManifestsChecker) Name() string { return "secrets-hardcoded-manifests" }

// Description returns a human-readable description.
func (c *HardcodedManifestsChecker) Description() string {
	return "Detects hardcoded secret values in Kubernetes Secret manifests that appear to be real credentials."
}

// Categories returns the check categories.
func (c *HardcodedManifestsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
// Manifest only — in live mode, values are already stored; this check targets source manifests.
func (c *HardcodedManifestsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HardcodedManifestsChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{SecretGVR}
}

// Run executes the secrets-hardcoded-manifests check against all Secrets in the cache.
func (c *HardcodedManifestsChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-hardcoded-manifests check: %w", err)
	}

	entropyThreshold := DefaultEntropyThreshold
	if p := cache.Policies(); p != nil && p.Secrets.EntropyThreshold > 0 {
		entropyThreshold = p.Secrets.EntropyThreshold
	}

	secrets := cache.List(SecretGVR)
	var findings []checker.Finding

	for i := range secrets {
		obj := &secrets[i]

		// Check .data map (base64-encoded values).
		if dataFindings := checkDataMap(obj, entropyThreshold); len(dataFindings) > 0 {
			findings = append(findings, dataFindings...)
		}

		// Check .stringData map (plaintext values).
		if sdFindings := checkStringDataMap(obj, entropyThreshold); len(sdFindings) > 0 {
			findings = append(findings, sdFindings...)
		}
	}

	return findings, nil
}

// checkDataMap analyzes base64-encoded .data values for hardcoded secrets.
func checkDataMap(obj *unstructured.Unstructured, entropyThreshold float64) []checker.Finding {
	dataRaw, found := obj.Object["data"]
	if !found {
		return nil
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	var findings []checker.Finding
	for key, val := range dataMap {
		encoded, ok := val.(string)
		if !ok || encoded == "" {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue // invalid base64, skip gracefully
		}

		decodedStr := string(decoded)
		if len(decodedStr) < 4 {
			continue // too short to be a meaningful secret
		}

		if !looksLikeSecret(decodedStr, entropyThreshold) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "secrets-hardcoded-manifests",
			Severity:  checker.SeverityHigh,
			Resource:  obj.GetName(),
			Namespace: obj.GetNamespace(),
			Kind:      obj.GetKind(),
			Message:   fmt.Sprintf("Secret %q contains hardcoded value in key %q that appears to be a real secret.", obj.GetName(), key),
			Remediation: "## Why This Matters\n\n" +
				"Hardcoded secrets in manifest files end up in version control history, CI logs, " +
				"and backup systems. Even if later removed, they persist in git history and can " +
				"be extracted by anyone with repository read access, past or present.\n\n" +
				"## How to Fix\n\n" +
				"Replace hardcoded values with an external secret management solution:\n\n" +
				"```yaml\napiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: my-secret\nspec:\n  refreshInterval: 1h\n  secretStoreRef:\n    name: vault-backend\n    kind: SecretStore\n  target:\n    name: my-secret\n```\n\n" +
				"Rotate any credential that was previously committed. Consider Sealed Secrets, " +
				"SOPS, Vault Agent, or cloud-native secret managers as alternatives.\n\n" +
				"## Learn More\n\n" +
				"CIS Kubernetes Benchmark 5.4.2 forbids hardcoded secrets in manifests. " +
				"See the External Secrets Operator documentation for integration guides.",
			FieldPath: fmt.Sprintf(".data.%s", key),
		})
	}

	return findings
}

// checkStringDataMap analyzes plaintext .stringData values for hardcoded secrets.
func checkStringDataMap(obj *unstructured.Unstructured, entropyThreshold float64) []checker.Finding {
	sdRaw, found := obj.Object["stringData"]
	if !found {
		return nil
	}
	sdMap, ok := sdRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	var findings []checker.Finding
	for key, val := range sdMap {
		plaintext, ok := val.(string)
		if !ok || len(plaintext) < 4 {
			continue
		}

		if !looksLikeSecret(plaintext, entropyThreshold) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "secrets-hardcoded-manifests",
			Severity:  checker.SeverityHigh,
			Resource:  obj.GetName(),
			Namespace: obj.GetNamespace(),
			Kind:      obj.GetKind(),
			Message:   fmt.Sprintf("Secret %q contains hardcoded value in key %q that appears to be a real secret.", obj.GetName(), key),
			Remediation: "## Why This Matters\n\n" +
				"Hardcoded secrets in manifest files end up in version control history, CI logs, " +
				"and backup systems. Even if later removed, they persist in git history and can " +
				"be extracted by anyone with repository read access, past or present.\n\n" +
				"## How to Fix\n\n" +
				"Replace hardcoded values with an external secret management solution:\n\n" +
				"```yaml\napiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: my-secret\nspec:\n  refreshInterval: 1h\n  secretStoreRef:\n    name: vault-backend\n    kind: SecretStore\n  target:\n    name: my-secret\n```\n\n" +
				"Rotate any credential that was previously committed. Consider Sealed Secrets, " +
				"SOPS, Vault Agent, or cloud-native secret managers as alternatives.\n\n" +
				"## Learn More\n\n" +
				"CIS Kubernetes Benchmark 5.4.2 forbids hardcoded secrets in manifests. " +
				"See the External Secrets Operator documentation for integration guides.",
			FieldPath: fmt.Sprintf(".stringData.%s", key),
		})
	}

	return findings
}

// looksLikeSecret returns true if the value matches a known secret pattern OR has high entropy.
func looksLikeSecret(value string, entropyThreshold float64) bool {
	return HasKnownSecretPattern(value) || IsLikelySecret(value, entropyThreshold)
}
