package supply_chain

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// ContainerRuntimeSocketChecker detects pods mounting container runtime sockets.
// Direct socket access enables full container escape.
type ContainerRuntimeSocketChecker struct{}

// Name returns the check ID.
func (c *ContainerRuntimeSocketChecker) Name() string { return "container-runtime-socket" }

// Description returns a human-readable description.
func (c *ContainerRuntimeSocketChecker) Description() string {
	return "Detects pods mounting container runtime sockets (docker.sock, containerd.sock, crio.sock), which enable container escape."
}

// Categories returns the check categories.
func (c *ContainerRuntimeSocketChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySupplyChain}
}

// SupportedModes returns which scan modes this check supports.
func (c *ContainerRuntimeSocketChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ContainerRuntimeSocketChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the container runtime socket check.
func (c *ContainerRuntimeSocketChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("container-runtime-socket check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)

	for i := range specs {
		info := &specs[i]
		for j := range info.Spec.Volumes {
			if info.Spec.Volumes[j].HostPath == nil {
				continue
			}
			if !runtimeSocketPaths[info.Spec.Volumes[j].HostPath.Path] {
				continue
			}

			// Find containers that mount this volume.
			vol := &info.Spec.Volumes[j]
			workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
				for _, vm := range container.VolumeMounts {
					if vm.Name == vol.Name {
						findings = append(findings, checker.Finding{
							Checker:   "container-runtime-socket",
							Severity:  checker.SeverityCritical,
							Resource:  info.ResourceName,
							Namespace: info.Namespace,
							Kind:      info.Kind,
							Container: container.Name,
							Message:   fmt.Sprintf("Container %q mounts container runtime socket %q via volume %q.", container.Name, vol.HostPath.Path, vol.Name),
							Remediation: "## Why This Matters\n\n" +
								"Mounting the container runtime socket (docker.sock, containerd.sock, crio.sock) gives the container " +
								"full control over every container on the node. An attacker can create privileged containers, access " +
								"secrets from other pods, or escape to the host entirely. This is one of the most critical container " +
								"escape vectors.\n\n" +
								"## How to Fix\n\n" +
								"Remove the hostPath volume that mounts the runtime socket:\n\n" +
								"```yaml\nspec:\n  volumes:\n    # Remove this volume entirely:\n    # - name: docker-sock\n    #   hostPath:\n    #     path: /var/run/docker.sock\n  containers:\n    - name: app\n      volumeMounts: []            # Remove the corresponding mount\n```\n\n" +
								"If you need to build container images, use rootless builders like Kaniko or Buildah instead of Docker-in-Docker.\n\n" +
								"## Learn More\n\n" +
								"See MITRE ATT&CK T1611 (Escape to Host) for container escape techniques. The CIS Kubernetes Benchmark " +
								"and NSA/CISA Hardening Guide both prohibit mounting container runtime sockets.",
							FieldPath: fmt.Sprintf(".spec.volumes[%d].hostPath.path", j),
						})
					}
				}
			})
		}
	}

	return findings, nil
}
