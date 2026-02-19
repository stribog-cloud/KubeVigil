package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// NoDigestChecker detects containers whose image is not pinned by digest.
// Without a digest, an image tag can be mutated to point at a different image,
// allowing tag mutation attacks and making deployments non-immutable.
type NoDigestChecker struct{}

// Name returns the kebab-case check ID.
func (c *NoDigestChecker) Name() string { return "image-no-digest" }

// Description returns a human-readable description.
func (c *NoDigestChecker) Description() string {
	return "Detects containers whose image is not pinned by digest, allowing tag mutation."
}

// Categories returns the check categories.
func (c *NoDigestChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *NoDigestChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *NoDigestChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-no-digest check against all workload resources in the cache.
func (c *NoDigestChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-no-digest check: %w", err)
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		if img.Ref.HasDigest() {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-no-digest",
			Severity:  checker.SeverityLow,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q image is not pinned by digest (image: %s), allowing tag mutation.", img.ContainerName, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"Image tags are mutable pointers -- a registry administrator or attacker can " +
				"re-push a different image under the same tag. Without a digest, you have no " +
				"cryptographic guarantee that the image you deploy is the one you tested.\n\n" +
				"## How to Fix\n\n" +
				"Pin images by their SHA-256 content digest for a fully immutable reference:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable\n```\n\n" +
				"Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its " +
				"digest during CI/CD, then commit the pinned reference.\n\n" +
				"## Learn More\n\n" +
				"SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply " +
				"chain integrity. See the Kubernetes images documentation for details.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
