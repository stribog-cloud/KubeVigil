package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// RegistryAllowlistChecker flags containers using images from registries
// not in the configured allowed registries list. This check is a NO-OP when
// no allowed registries policy is configured.
type RegistryAllowlistChecker struct{}

// Name returns the kebab-case check ID.
func (c *RegistryAllowlistChecker) Name() string { return "image-registry-allowlist" }

// Description returns a human-readable description.
func (c *RegistryAllowlistChecker) Description() string {
	return "Flags container images from registries not in the allowed registries list."
}

// Categories returns the check categories.
func (c *RegistryAllowlistChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *RegistryAllowlistChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RegistryAllowlistChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-registry-allowlist check against all workload resources in the cache.
func (c *RegistryAllowlistChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-registry-allowlist check: %w", err)
	}

	policies := resources.Policies()
	if !policies.HasAllowedRegistries() {
		return nil, nil // NO-OP when no allowlist configured
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		effectiveReg := img.Ref.EffectiveRegistry()

		allowed := false
		for _, r := range policies.Images.AllowedRegistries {
			if registryMatches(effectiveReg, r) {
				allowed = true
				break
			}
		}
		if allowed {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-registry-allowlist",
			Severity:  checker.SeverityHigh,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q uses image from non-allowed registry %q (image: %s).", img.ContainerName, effectiveReg, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"Pulling images from unapproved registries bypasses your organization's security " +
				"scanning, vulnerability management, and supply chain controls. Untrusted registries " +
				"may serve images containing malware, known CVEs, or backdoors.\n\n" +
				"## How to Fix\n\n" +
				"Switch the container image to one hosted on an approved internal registry:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: registry.company.com/app:v1.0   # Approved registry\n```\n\n" +
				"Define your approved registries in `.kubevigil.yaml`:\n\n" +
				"```yaml\npolicies:\n  images:\n    allowedRegistries:\n      - registry.company.com\n      - gcr.io/my-project\n```\n\n" +
				"## Learn More\n\n" +
				"CIS Kubernetes Benchmark 5.4.1 recommends restricting image sources. " +
				"Use admission controllers like OPA Gatekeeper or Kyverno to enforce registry policies at deploy time.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
