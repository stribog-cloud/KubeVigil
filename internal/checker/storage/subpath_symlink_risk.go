package storage

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// SubPathSymlinkRiskChecker detects volumeMounts using subPath or subPathExpr.
// This is a defense-in-depth flag tied to the historical subPath symlink-race
// container-escape vulnerability class (CVE-2021-25741 and related).
type SubPathSymlinkRiskChecker struct{}

// Name returns the kebab-case check ID.
func (c *SubPathSymlinkRiskChecker) Name() string { return "subpath-symlink-risk" }

// Description returns a human-readable description.
func (c *SubPathSymlinkRiskChecker) Description() string {
	return "Detects volumeMounts using subPath/subPathExpr, a historical symlink-race container-escape risk."
}

// Categories returns the check categories.
func (c *SubPathSymlinkRiskChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *SubPathSymlinkRiskChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SubPathSymlinkRiskChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the subpath-symlink-risk check against all workload resources in the cache.
func (c *SubPathSymlinkRiskChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("subpath-symlink-risk check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			for k := range container.VolumeMounts {
				vm := &container.VolumeMounts[k]

				field := ""
				value := ""
				switch {
				case vm.SubPath != "":
					field = "subPath"
					value = vm.SubPath
				case vm.SubPathExpr != "":
					field = "subPathExpr"
					value = vm.SubPathExpr
				default:
					continue
				}

				findings = append(findings, checker.Finding{
					Checker:   "subpath-symlink-risk",
					Severity:  checker.SeverityLow,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q mounts volume %q using %s %q, a historical symlink-race container-escape vector.", container.Name, vm.Name, field, value),
					Remediation: "## Why This Matters\n\n" +
						"The subPath and subPathExpr volumeMount fields mount a single file or subdirectory from within a volume " +
						"rather than the whole volume. Older kubelet versions (fixed in CVE-2021-25741) and some third-party CSI " +
						"drivers resolve the subPath after the container starts, creating a race window where a malicious container " +
						"can swap the subPath target for a symlink pointing at the host filesystem, escaping the volume boundary.\n\n" +
						"## How to Fix\n\n" +
						"Avoid subPath where possible — mount the whole volume and have the application read the specific file, " +
						"or use an initContainer to lay out files at the expected paths instead:\n\n" +
						"```yaml\nvolumeMounts:\n  - name: data\n    mountPath: /app/conf           # Mount the whole volume\n# Instead of:\n#  - name: data\n#    mountPath: /app/conf/conf.yaml\n#    subPath: conf.yaml\n```\n\n" +
						"If subPath is unavoidable, ensure kubelet and the CSI driver are patched against CVE-2021-25741 and restrict " +
						"which images can be scheduled with subPath mounts via admission control.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK T1611 (Escape to Host) and the Kubernetes security advisory for CVE-2021-25741. " +
						"This check is defense-in-depth; most modern, patched clusters are not vulnerable, but the risk surface " +
						"remains for older kubelets and less-maintained CSI drivers.",
					FieldPath: containerFieldPath(ct, idx, fmt.Sprintf("volumeMounts[%d].%s", k, field)),
				})
			}
		})
	}

	return findings, nil
}
