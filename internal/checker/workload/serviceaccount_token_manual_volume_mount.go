package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// serviceAccountTokenSecretType is the deprecated Secret type Kubernetes used
// to auto-create for every ServiceAccount before 1.24. Secrets of this type
// hold long-lived, non-expiring tokens.
const serviceAccountTokenSecretType = "kubernetes.io/service-account-token" //nolint:gosec // Not a credential; Kubernetes Secret type constant.

// secretGVR is the GroupVersionResource for core/v1 Secret objects, needed by
// ServiceAccountTokenManualVolumeMountChecker to resolve the type of a
// Secret referenced by a pod's volumes.
var secretGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}

// ServiceAccountTokenManualVolumeMountChecker detects pods that manually mount
// a Secret volume whose referenced Secret is of type
// kubernetes.io/service-account-token (the legacy long-lived token pattern),
// instead of relying on the automatic projected-volume token.
type ServiceAccountTokenManualVolumeMountChecker struct{}

// Name returns the kebab-case check ID.
func (c *ServiceAccountTokenManualVolumeMountChecker) Name() string {
	return "serviceaccount-token-manual-volume-mount"
}

// Description returns a human-readable description.
func (c *ServiceAccountTokenManualVolumeMountChecker) Description() string {
	return "Detects pods that manually mount a legacy service-account-token Secret via a volume."
}

// Categories returns the check categories.
func (c *ServiceAccountTokenManualVolumeMountChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ServiceAccountTokenManualVolumeMountChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ServiceAccountTokenManualVolumeMountChecker) RequiredResources() []schema.GroupVersionResource {
	return append(GVRs(), secretGVR)
}

// Run executes the serviceaccount-token-manual-volume-mount check against all workload resources in the cache.
func (c *ServiceAccountTokenManualVolumeMountChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("serviceaccount-token-manual-volume-mount check: %w", err)
	}

	secretTypes := secretTypesByNamespacedName(resources)

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		for volIdx := range info.Spec.Volumes {
			vol := &info.Spec.Volumes[volIdx]
			if vol.Secret == nil || vol.Secret.SecretName == "" {
				continue
			}

			key := info.Namespace + "/" + vol.Secret.SecretName
			if secretTypes[key] != serviceAccountTokenSecretType {
				continue
			}

			findings = append(findings, checker.Finding{
				Checker:   "serviceaccount-token-manual-volume-mount",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message: fmt.Sprintf(
					"%s %q manually mounts Secret %q, a legacy service-account-token Secret, via volume %q.",
					info.Kind, info.ResourceName, vol.Secret.SecretName, vol.Name,
				),
				Remediation: "## Why This Matters\n\n" +
					"Secrets of type kubernetes.io/service-account-token hold long-lived, non-expiring tokens — the legacy " +
					"pre-1.24 pattern for ServiceAccount credentials. Manually mounting one via a volume bypasses the modern " +
					"bound, auto-rotating, audience-scoped projected service-account-token volume that Kubernetes mounts by " +
					"default. A leaked legacy token remains valid indefinitely, unlike a projected token which expires and is " +
					"scoped to a specific audience.\n\n" +
					"## How to Fix\n\n" +
					"Remove the manual volume mount and rely on the automatically projected service-account-token volume, or " +
					"configure explicit token projection with an expiry and audience:\n\n" +
					"```yaml\nspec:\n  containers:\n    - name: app\n      volumeMounts:\n        - name: kube-api-access\n" +
					"          mountPath: /var/run/secrets/kubernetes.io/serviceaccount\n          readOnly: true\n" +
					"  volumes:\n    - name: kube-api-access\n      projected:\n        sources:\n          - serviceAccountToken:\n" +
					"              expirationSeconds: 3600\n              path: token\n```\n\n" +
					"## Learn More\n\n" +
					"This check aligns with NSA/CISA Kubernetes Hardening Guidance 3.1 (RBAC policies) and MITRE ATT&CK T1528 " +
					"(Steal Application Access Token). See the Kubernetes documentation on service account token volume " +
					"projection.",
				FieldPath: fmt.Sprintf(".spec.volumes[%d].secret", volIdx),
			})
		}
	}

	return findings, nil
}

// secretTypesByNamespacedName builds a lookup of "namespace/name" -> Secret
// type for every Secret in the cache, so pod volume references can be
// resolved without repeated linear scans.
func secretTypesByNamespacedName(resources *checker.ResourceCache) map[string]string {
	secrets := resources.List(secretGVR)
	types := make(map[string]string, len(secrets))

	for i := range secrets {
		obj := &secrets[i]
		key := obj.GetNamespace() + "/" + obj.GetName()
		types[key] = secretType(obj)
	}

	return types
}

// secretType extracts the "type" field from an unstructured Secret object.
func secretType(obj *unstructured.Unstructured) string {
	val, found, err := unstructured.NestedString(obj.Object, "type")
	if err != nil || !found {
		return ""
	}
	return val
}
