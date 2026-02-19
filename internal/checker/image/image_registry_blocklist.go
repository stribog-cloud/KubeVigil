package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// RegistryBlocklistChecker flags containers using images from blocked registries.
// This check is a NO-OP when no blocked registries policy is configured.
type RegistryBlocklistChecker struct{}

// Name returns the kebab-case check ID.
func (c *RegistryBlocklistChecker) Name() string { return "image-registry-blocklist" }

// Description returns a human-readable description.
func (c *RegistryBlocklistChecker) Description() string {
	return "Flags container images from blocked registries."
}

// Categories returns the check categories.
func (c *RegistryBlocklistChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *RegistryBlocklistChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RegistryBlocklistChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-registry-blocklist check against all workload resources in the cache.
func (c *RegistryBlocklistChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-registry-blocklist check: %w", err)
	}

	policies := resources.Policies()
	if !policies.HasBlockedRegistries() {
		return nil, nil // NO-OP when no blocklist configured
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		effectiveReg := img.Ref.EffectiveRegistry()

		blocked := false
		for _, r := range policies.Images.BlockedRegistries {
			if registryMatches(effectiveReg, r) {
				blocked = true
				break
			}
		}
		if !blocked {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-registry-blocklist",
			Severity:  checker.SeverityCritical,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q uses image from blocked registry %q (image: %s).", img.ContainerName, effectiveReg, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"Your organization has explicitly prohibited this registry because it is known " +
				"to be insecure, unmaintained, or non-compliant. Running images from blocked " +
				"registries violates security policy and may expose your cluster to unvetted code.\n\n" +
				"## How to Fix\n\n" +
				"Replace the image with an equivalent from an approved registry:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: registry.company.com/app:v1.0   # Approved alternative\n```\n\n" +
				"Mirror needed images into your internal registry using `crane copy` or `skopeo copy`, " +
				"then update manifests to reference the mirrored location.\n\n" +
				"## Learn More\n\n" +
				"Define blocked registries in `.kubevigil.yaml` under `policies.images.blockedRegistries`. " +
				"Enforce registry restrictions at the admission layer with OPA Gatekeeper or Kyverno.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
