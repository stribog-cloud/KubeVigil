package psa

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// VersionPinningChecker detects namespaces where PSA version labels are pinned
// to a specific Kubernetes version (e.g., "v1.25") rather than "latest". Pinned
// versions don't automatically pick up new security restrictions when the cluster
// is upgraded, potentially leaving workloads exposed to newly-identified risks.
type VersionPinningChecker struct{}

// Name returns the kebab-case check ID.
func (c *VersionPinningChecker) Name() string { return "psa-version-pinning" }

// Description returns a human-readable description.
func (c *VersionPinningChecker) Description() string {
	return "Detects namespaces with PSA version labels pinned to a specific version instead of 'latest'."
}

// Categories returns the check categories.
func (c *VersionPinningChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryPSS}
}

// SupportedModes returns which scan modes this check supports.
func (c *VersionPinningChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *VersionPinningChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NamespaceGVR}
}

// psaVersionLabels lists the PSA version label keys to check for pinning.
var psaVersionLabels = []string{psaEnforceVer, psaAuditVer, psaWarnVer}

// Run executes the PSA version pinning check against all namespaces in the cache.
func (c *VersionPinningChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("psa-version-pinning check: %w", err)
	}

	namespaces := resources.List(NamespaceGVR)
	var findings []checker.Finding

	for i := range namespaces {
		ns := &namespaces[i]
		name := ns.GetName()

		if isSystemNamespace(name) {
			continue
		}

		labels := ns.GetLabels()

		for _, versionLabel := range psaVersionLabels {
			val, ok := labels[versionLabel]
			if !ok {
				continue
			}
			if val != "latest" {
				findings = append(findings, checker.Finding{
					Checker:   "psa-version-pinning",
					Severity:  checker.SeverityLow,
					Resource:  name,
					Namespace: "",
					Kind:      "Namespace",
					Message:   fmt.Sprintf("Namespace %q has PSA version label %s pinned to %q instead of \"latest\"; new restrictions won't apply on upgrade.", name, versionLabel, val),
					Remediation: fmt.Sprintf(
						"## Why This Matters\n\n"+
							"When a PSA version label is pinned to a specific Kubernetes version, the namespace will not automatically benefit from new security restrictions added in later versions. "+
							"After a cluster upgrade, workloads may be allowed to run configurations that the newer Pod Security Standards would otherwise block.\n\n"+
							"## How to Fix\n\n"+
							"Set the version label to \"latest\" so it always uses the security standards matching the current cluster version:\n\n"+
							"```yaml\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: my-namespace\n  labels:\n    %s: \"latest\"\n```\n\n"+
							"If pinning is intentional (e.g., for compatibility testing), document the reason and plan to update after validation.\n\n"+
							"## Learn More\n\n"+
							"See the Kubernetes Pod Security Admission documentation on version labels. "+
							"Using \"latest\" ensures your namespaces always apply the most up-to-date Pod Security Standards for the cluster version.", versionLabel),
					FieldPath: ".metadata.labels[" + versionLabel + "]",
				})
			}
		}
	}

	return findings, nil
}
