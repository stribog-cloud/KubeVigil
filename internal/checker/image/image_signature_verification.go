package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// SignatureVerificationChecker flags container images that are not pinned by digest
// when signature verification is required. Digest pinning is a prerequisite for
// verifying image signatures. This check is a NO-OP when RequireSignatures is false.
type SignatureVerificationChecker struct{}

// Name returns the kebab-case check ID.
func (c *SignatureVerificationChecker) Name() string { return "image-signature-verification" }

// Description returns a human-readable description.
func (c *SignatureVerificationChecker) Description() string {
	return "Flags container images not pinned by digest when signature verification is required."
}

// Categories returns the check categories.
func (c *SignatureVerificationChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *SignatureVerificationChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SignatureVerificationChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-signature-verification check against all workload resources in the cache.
func (c *SignatureVerificationChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-signature-verification check: %w", err)
	}

	policies := resources.Policies()
	if policies == nil || !policies.Images.RequireSignatures {
		return nil, nil // NO-OP when signature verification not required
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		if img.Ref.HasDigest() {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-signature-verification",
			Severity:  checker.SeverityMedium,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q image is not pinned by digest (image: %s), preventing signature verification.", img.ContainerName, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"Image signatures provide cryptographic proof that an image was built by a trusted " +
				"party and has not been tampered with. Without digest pinning, signature verification " +
				"is impossible because the tag can be mutated after signing, breaking the trust chain.\n\n" +
				"## How to Fix\n\n" +
				"Pin the image by digest so its signature can be verified against the exact content:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: myapp@sha256:abcdef1234567890\n```\n\n" +
				"Sign images in CI with cosign: `cosign sign --key cosign.key myapp@sha256:...`\n" +
				"Verify at admission time: `cosign verify --key cosign.pub myapp@sha256:...`\n\n" +
				"## Learn More\n\n" +
				"See the Sigstore cosign documentation for signing workflows. " +
				"SLSA Level 2+ requires verified provenance, which depends on digest-pinned images.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
