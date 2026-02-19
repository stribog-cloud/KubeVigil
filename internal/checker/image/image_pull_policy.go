package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// PullPolicyChecker detects containers with a mutable image reference
// and a pull policy that does not enforce pulling the latest version.
// Without imagePullPolicy: Always, a node may use a cached (potentially stale)
// version of a mutable tag.
type PullPolicyChecker struct{}

// Name returns the kebab-case check ID.
func (c *PullPolicyChecker) Name() string { return "image-pull-policy" }

// Description returns a human-readable description.
func (c *PullPolicyChecker) Description() string {
	return "Detects containers with mutable image tags and non-Always pull policy, risking stale images."
}

// Categories returns the check categories.
func (c *PullPolicyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *PullPolicyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PullPolicyChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-pull-policy check against all workload resources in the cache.
func (c *PullPolicyChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-pull-policy check: %w", err)
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]

		// Skip if image is pinned by digest — immutable, pullPolicy is irrelevant for security.
		if img.Ref.HasDigest() {
			continue
		}

		// Determine the effective pull policy, accounting for Kubernetes defaults.
		effectivePolicy := img.PullPolicy
		if effectivePolicy == "" {
			if img.Ref.IsLatest() {
				effectivePolicy = "Always" // K8s default for :latest or no tag
			} else {
				effectivePolicy = "IfNotPresent" // K8s default for other tags
			}
		}

		// If the effective policy is Already, the image will always be freshly pulled.
		if effectivePolicy == "Always" {
			continue
		}

		// Flag: mutable tag with non-Always pull policy.
		findings = append(findings, checker.Finding{
			Checker:   "image-pull-policy",
			Severity:  checker.SeverityMedium,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q uses a mutable image tag with pullPolicy %q (image: %s), risking stale images.", img.ContainerName, effectivePolicy, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes " +
				"may serve a cached version of the image from the node. If the tag has been " +
				"updated in the registry (with a security patch or -- worse -- a compromised layer), " +
				"the running container will not reflect those changes.\n\n" +
				"## How to Fix\n\n" +
				"Set `imagePullPolicy: Always` for any container using a mutable tag:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: nginx:1.25.3\n    imagePullPolicy: Always   # Forces fresh pull each time\n```\n\n" +
				"Alternatively, pin images by digest (`image@sha256:...`), which makes " +
				"the pull policy irrelevant because the content is immutable.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes documentation on image pull policies and " +
				"CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.",
			FieldPath:    containerFieldPath(img.ContainerType, img.ContainerIdx, "imagePullPolicy"),
			CurrentValue: effectivePolicy,
			DesiredValue: "Always",
			FixHint: &checker.FixHint{
				Safety:      checker.FixLikelySafe,
				Description: "Sets imagePullPolicy to Always.",
				Impact:      "Slightly slower pod starts due to image verification.",
				Operation:   checker.FixOpSet,
			},
		})
	}

	return findings, nil
}
