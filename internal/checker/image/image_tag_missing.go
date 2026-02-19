package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TagMissingChecker detects containers where the image has no tag and no digest.
// An image with no version identifier at all (e.g., "nginx") is completely
// non-deterministic — the resolved image can change between pulls.
type TagMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *TagMissingChecker) Name() string { return "image-tag-missing" }

// Description returns a human-readable description.
func (c *TagMissingChecker) Description() string {
	return "Detects containers with no image tag or digest, making deployments completely non-deterministic."
}

// Categories returns the check categories.
func (c *TagMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *TagMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TagMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-tag-missing check against all workload resources in the cache.
func (c *TagMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-tag-missing check: %w", err)
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		// Only flag when there is truly no version identifier at all (no tag, no digest).
		// "nginx:latest" has a tag — it triggers image-tag-latest but NOT image-tag-missing.
		if img.Ref.HasTag() || img.Ref.HasDigest() {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-tag-missing",
			Severity:  checker.SeverityMedium,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q has no image tag or digest (image: %s), making deployments completely non-deterministic.", img.ContainerName, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"An image reference with no tag and no digest implicitly resolves to :latest, " +
				"which is mutable. Every pod restart could pull a completely different image, " +
				"breaking reproducibility and opening the door to supply chain attacks.\n\n" +
				"## How to Fix\n\n" +
				"Always specify an explicit version tag or content-addressable digest:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: nginx:1.25.3              # Explicit version tag\n" +
				"    # Or for critical workloads, pin by digest:\n" +
				"    # image: nginx@sha256:a8281ce42034\n```\n\n" +
				"Integrate image tag linting into your CI pipeline to catch missing tags before " +
				"manifests reach the cluster.\n\n" +
				"## Learn More\n\n" +
				"Kubernetes documentation recommends always specifying an image tag. " +
				"See CIS Kubernetes Benchmark 5.4.1 for image versioning requirements.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
