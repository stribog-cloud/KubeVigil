package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TagLatestChecker detects containers using the :latest tag or implicit latest.
// Using :latest (or omitting a tag entirely) can lead to unpredictable deployments
// because the underlying image can change without any manifest change.
type TagLatestChecker struct{}

// Name returns the kebab-case check ID.
func (c *TagLatestChecker) Name() string { return "image-tag-latest" }

// Description returns a human-readable description.
func (c *TagLatestChecker) Description() string {
	return "Detects containers using the :latest image tag, which can lead to unpredictable deployments."
}

// Categories returns the check categories.
func (c *TagLatestChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *TagLatestChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TagLatestChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-tag-latest check against all workload resources in the cache.
func (c *TagLatestChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-tag-latest check: %w", err)
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		if !img.Ref.IsLatest() {
			continue
		}

		msg := fmt.Sprintf("Container %q uses the :latest tag (image: %s), which can lead to unpredictable deployments.", img.ContainerName, img.Ref.Raw)
		if !img.Ref.HasTag() {
			msg = fmt.Sprintf("Container %q has no image tag (image: %s), which defaults to :latest.", img.ContainerName, img.Ref.Raw)
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-tag-latest",
			Severity:  checker.SeverityMedium,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   msg,
			Remediation: "## Why This Matters\n\n" +
				"The :latest tag is mutable and can resolve to a different image at any time. " +
				"Deployments become non-reproducible, rollbacks break silently, and attackers " +
				"can poison the tag to inject malicious code without changing your manifests.\n\n" +
				"## How to Fix\n\n" +
				"Pin every container image to a specific, immutable version tag:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: nginx:1.25.3          # Pinned version tag\n" +
				"    # Or pin by digest for maximum immutability:\n" +
				"    # image: nginx@sha256:a8281ce42034\n```\n\n" +
				"Adopt a CI/CD practice of updating image tags via automated PRs so manifests always " +
				"reflect the exact version deployed.\n\n" +
				"## Learn More\n\n" +
				"The CIS Kubernetes Benchmark 5.4.1 recommends pinning image versions. " +
				"See the Kubernetes documentation on container images for tag best practices.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
