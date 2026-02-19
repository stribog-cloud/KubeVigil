package image

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// SBOMAttestationChecker flags container images that are not pinned by digest
// when SBOM attestation is required. Digest pinning is a prerequisite for
// verifying SBOM attestations. This check is a NO-OP when RequireSBOM is false.
type SBOMAttestationChecker struct{}

// Name returns the kebab-case check ID.
func (c *SBOMAttestationChecker) Name() string { return "image-sbom-attestation" }

// Description returns a human-readable description.
func (c *SBOMAttestationChecker) Description() string {
	return "Flags container images not pinned by digest when SBOM attestation is required."
}

// Categories returns the check categories.
func (c *SBOMAttestationChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryImage}
}

// SupportedModes returns which scan modes this check supports.
func (c *SBOMAttestationChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SBOMAttestationChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the image-sbom-attestation check against all workload resources in the cache.
func (c *SBOMAttestationChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-sbom-attestation check: %w", err)
	}

	policies := resources.Policies()
	if policies == nil || !policies.Images.RequireSBOM {
		return nil, nil // NO-OP when SBOM attestation not required
	}

	images := ExtractContainerImages(resources)
	var findings []checker.Finding

	for i := range images {
		img := &images[i]
		if img.Ref.HasDigest() {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "image-sbom-attestation",
			Severity:  checker.SeverityLow,
			Resource:  img.ResourceName,
			Namespace: img.Namespace,
			Kind:      img.Kind,
			Container: img.ContainerName,
			Message:   fmt.Sprintf("Container %q image is not pinned by digest (image: %s), preventing SBOM attestation verification.", img.ContainerName, img.Ref.Raw),
			Remediation: "## Why This Matters\n\n" +
				"A Software Bill of Materials (SBOM) lists every dependency inside a container image. " +
				"Without digest pinning, SBOM attestations cannot be matched to a specific image build, " +
				"so you lose visibility into which libraries and CVEs are present at runtime.\n\n" +
				"## How to Fix\n\n" +
				"Pin the image by digest so its SBOM attestation can be verified:\n\n" +
				"```yaml\ncontainers:\n  - name: app\n    image: myapp@sha256:abcdef1234567890\n```\n\n" +
				"Generate and attach SBOMs in CI:\n" +
				"`syft myapp@sha256:... -o spdx-json > sbom.json`\n" +
				"`cosign attest --predicate sbom.json --type spdxjson myapp@sha256:...`\n\n" +
				"## Learn More\n\n" +
				"NIST Executive Order 14028 requires SBOMs for federal software. " +
				"See the SPDX and CycloneDX specifications for SBOM format standards.",
			FieldPath: containerFieldPath(img.ContainerType, img.ContainerIdx, "image"),
		})
	}

	return findings, nil
}
