package supply_chain

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

const (
	// defaultMaxImageAgeDays is the default threshold for flagging stale images.
	defaultMaxImageAgeDays = 180
	// imageAgeAnnotation is the annotation key for image build/push timestamps.
	imageAgeAnnotation = "kubevigil.io/image-created"
)

// ImageAgeChecker detects container images older than a configurable threshold.
// It relies on the annotation "kubevigil.io/image-created" (RFC3339 timestamp)
// to determine image age, since registry API access is not available during
// manifest scanning.
type ImageAgeChecker struct{}

// Name returns the check ID.
func (c *ImageAgeChecker) Name() string { return "image-age" }

// Description returns a human-readable description.
func (c *ImageAgeChecker) Description() string {
	return "Detects container images older than the configured threshold (default: 180 days). Stale images likely have unpatched vulnerabilities."
}

// Categories returns the check categories.
func (c *ImageAgeChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySupplyChain}
}

// SupportedModes returns which scan modes this check supports.
func (c *ImageAgeChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ImageAgeChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the image age check.
func (c *ImageAgeChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image-age check: %w", err)
	}

	now := time.Now()
	maxAge := time.Duration(defaultMaxImageAgeDays) * 24 * time.Hour

	for _, gvr := range workload.GVRs() {
		for _, obj := range resources.List(gvr) {
			annotations := obj.GetAnnotations()
			if annotations == nil {
				continue
			}

			created, ok := annotations[imageAgeAnnotation]
			if !ok {
				continue
			}

			ts, parseErr := time.Parse(time.RFC3339, created)
			if parseErr != nil {
				continue
			}

			age := now.Sub(ts)
			if age <= maxAge {
				continue
			}

			name := obj.GetName()
			ns := obj.GetNamespace()
			kind := obj.GetKind()

			// Report one finding per container in the workload.
			specs := workload.ExtractPodSpecs(resources)
			for si := range specs {
				info := &specs[si]
				if info.ResourceName != name || info.Namespace != ns {
					continue
				}
				workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
					if ct == workload.ContainerTypeInit {
						return
					}
					findings = append(findings, checker.Finding{
						Checker:   "image-age",
						Severity:  checker.SeverityLow,
						Resource:  name,
						Namespace: ns,
						Kind:      kind,
						Container: container.Name,
						Message:   fmt.Sprintf("Container %q image is %d days old (threshold: %d days).", container.Name, int(age.Hours()/24), defaultMaxImageAgeDays),
						Remediation: "## Why This Matters\n\n" +
							"Container images that have not been rebuilt in a long time accumulate unpatched CVEs in their base " +
							"image, OS packages, and application dependencies. Attackers actively scan for known vulnerabilities, " +
							"so stale images significantly increase your exposure to exploitation.\n\n" +
							"## How to Fix\n\n" +
							"Rebuild the container image with an up-to-date base image and push a new version:\n\n" +
							"```dockerfile\n# Update the base image to a recent, patched version:\nFROM nginx:1.27-alpine\n# Rebuild and push:\n# docker build -t myapp:v2.1 .\n# docker push myapp:v2.1\n```\n\n" +
							"Set up automated CI/CD pipelines that rebuild images when base images are updated or on a regular schedule (e.g., weekly).\n\n" +
							"## Learn More\n\n" +
							"See the NIST Container Security Guide (SP 800-190) for image lifecycle best practices. " +
							"Integrating vulnerability scanning (Trivy, Grype) into CI/CD pipelines catches known CVEs before deployment.",
						FieldPath: containerFieldPath(ct, idx, "image"),
					})
				})
			}
		}
	}

	return findings, nil
}
