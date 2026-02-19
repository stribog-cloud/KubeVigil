package workload

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostPathVolumesChecker detects pods that mount hostPath volumes.
// hostPath volumes give containers direct access to the host filesystem,
// which can lead to information disclosure or container escape depending
// on the path mounted.
type HostPathVolumesChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostPathVolumesChecker) Name() string { return "host-path-volumes" }

// Description returns a human-readable description.
func (c *HostPathVolumesChecker) Description() string {
	return "Detects pods that mount hostPath volumes, which provides direct access to the host filesystem."
}

// Categories returns the check categories.
func (c *HostPathVolumesChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostPathVolumesChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostPathVolumesChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-path-volumes check against all workload resources in the cache.
func (c *HostPathVolumesChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-path-volumes check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for volIdx := range info.Spec.Volumes {
			vol := &info.Spec.Volumes[volIdx]
			if vol.HostPath == nil {
				continue
			}

			hostPath := vol.HostPath.Path
			severity := hostPathSeverity(hostPath)

			findings = append(findings, checker.Finding{
				Checker:     "host-path-volumes",
				Severity:    severity,
				Resource:    info.ResourceName,
				Namespace:   info.Namespace,
				Kind:        info.Kind,
				Container:   "",
				Message:     fmt.Sprintf("%s %q mounts hostPath %q via volume %q.", info.Kind, info.ResourceName, hostPath, vol.Name),
				Remediation: "Remove hostPath volume mounts. Use persistent volumes or emptyDir instead.",
				FieldPath:   fmt.Sprintf(".spec.volumes[%d].hostPath", volIdx),
			})
		}
	}

	return findings, nil
}

// hostPathSeverity determines the severity based on the host path being mounted.
// Critical paths enable container escape or full host compromise. High paths
// expose sensitive logs. All other paths are Medium.
func hostPathSeverity(path string) checker.Severity {
	// Container runtime sockets — direct container escape vector.
	switch path {
	case "/var/run/docker.sock", "/run/containerd/containerd.sock":
		return checker.SeverityCritical
	}

	// Root filesystem — full host access.
	if path == "/" {
		return checker.SeverityCritical
	}

	// /etc or subdirectories — access to host configuration, credentials, shadow, etc.
	if path == "/etc" || strings.HasPrefix(path, "/etc/") {
		return checker.SeverityCritical
	}

	// /var/log or subdirectories — access to host and container logs.
	if path == "/var/log" || strings.HasPrefix(path, "/var/log/") {
		return checker.SeverityHigh
	}

	// All other hostPath mounts are a defense-in-depth concern.
	return checker.SeverityMedium
}
