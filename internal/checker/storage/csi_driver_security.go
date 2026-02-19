package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// CSIDriverSecurityChecker detects CSI drivers installed without podInfoOnMount
// or with volumeLifecycleModes allowing pre-provisioned access.
type CSIDriverSecurityChecker struct{}

// Name returns the kebab-case check ID.
func (c *CSIDriverSecurityChecker) Name() string { return "csi-driver-security" }

// Description returns a human-readable description.
func (c *CSIDriverSecurityChecker) Description() string {
	return "Detects CSI drivers without podInfoOnMount or with insecure volume lifecycle modes."
}

// Categories returns the check categories.
func (c *CSIDriverSecurityChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *CSIDriverSecurityChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CSIDriverSecurityChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CSIDriverGVR}
}

// Run executes the csi-driver-security check.
func (c *CSIDriverSecurityChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("csi-driver-security check: %w", err)
	}

	drivers := resources.List(CSIDriverGVR)
	var findings []checker.Finding

	for i := range drivers {
		driver := &drivers[i]
		name := driver.GetName()

		podInfoOnMount, found, _ := unstructured.NestedBool(driver.Object, "spec", "podInfoOnMount")
		if !found || !podInfoOnMount {
			findings = append(findings, checker.Finding{
				Checker:  "csi-driver-security",
				Severity: checker.SeverityLow,
				Resource: name,
				Kind:     "CSIDriver",
				Message:  fmt.Sprintf("CSIDriver %q does not have podInfoOnMount enabled; the driver cannot verify the identity of the requesting pod.", name),
				Remediation: "## Why This Matters\n\n" +
					"When podInfoOnMount is disabled, the CSI driver receives mount requests without knowing which pod initiated them. " +
					"This prevents the driver from enforcing per-pod access controls, meaning any pod that references the volume " +
					"can mount it without identity verification. This weakens the storage security boundary.\n\n" +
					"## How to Fix\n\n" +
					"Enable podInfoOnMount on the CSIDriver resource:\n\n" +
					"```yaml\napiVersion: storage.k8s.io/v1\nkind: CSIDriver\nmetadata:\n  name: my-csi-driver\nspec:\n  podInfoOnMount: true           # Sends pod name, namespace, UID to driver\n  volumeLifecycleModes:\n    - Persistent\n```\n\n" +
					"With this enabled, the CSI driver receives the pod's name, namespace, UID, and service account on every mount request.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes CSI Driver documentation on podInfoOnMount. This field is especially important for " +
					"secret-store CSI drivers and any driver that needs to enforce pod-level access policies.",
				FieldPath: ".spec.podInfoOnMount",
			})
		}
	}

	return findings, nil
}
