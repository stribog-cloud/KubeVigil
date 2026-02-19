package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// ProvenanceChecker flags container images that are not pinned by digest
// when provenance verification is required. Digest pinning is a prerequisite for
// verifying image provenance. This check is a NO-OP when RequireProvenance is false.
type ProvenanceChecker struct{}

// Name returns the kebab-case check ID.
func (c *ProvenanceChecker) Name() string { return "image-provenance" }

// Description returns a human-readable description.
func (c *ProvenanceChecker) Description() string {
	return "Flags container images not pinned by digest when provenance verification is required."
}

// Categories returns the check categories.
func (c *ProvenanceChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *ProvenanceChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ProvenanceChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-provenance check against all workload resources in the cache.
func (c *ProvenanceChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-provenance check: %w", err)
	}

	policies := resources.Policies()
	if policies == nil || !policies.Images.RequireProvenance {
		return nil, nil // NO-OP when provenance verification not required
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		if img.Ref.HasDigest() {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-provenance",
			Severity:  checker.SeverityLow,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q image is not pinned by digest (image: %s), preventing provenance verification.", img.ContainerName, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"Build provenance records where, when, and how a container image was built. " +
				"Without digest pinning, provenance attestations cannot be tied to a specific " +
				"image, so you cannot verify that the image came from your trusted CI/CD pipeline " +
				"rather than an attacker's workstation.\n\n" +
				"## How to Fix\n\n" +
				"Pin the image by digest so its SLSA provenance can be verified:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: myapp@sha256:abcdef1234567890\n```\n\n" +
				"Generate provenance in CI (e.g., GitHub Actions SLSA generator) and verify:\n" +
				"`cosign verify-attestation --type slsaprovenance myapp@sha256:...`\n\n" +
				"## Learn More\n\n" +
				"SLSA (Supply-chain Levels for Software Artifacts) defines four levels of " +
				"provenance assurance. See slsa.dev for framework details and implementation guides.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
