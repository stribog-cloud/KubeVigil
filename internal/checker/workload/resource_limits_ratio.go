package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// limitsToRequestsThreshold is the maximum acceptable ratio of limits to requests.
// A ratio above this value indicates significant overcommitment risk.
const limitsToRequestsThreshold = 3.0

// ResourceLimitsRatioChecker detects containers where the limits-to-requests ratio
// exceeds the threshold. High ratios cause node overcommitment and increase the
// risk of OOM kills when multiple pods burst simultaneously.
type ResourceLimitsRatioChecker struct{}

// Name returns the kebab-case check ID.
func (c *ResourceLimitsRatioChecker) Name() string { return "resource-limits-ratio" }

// Description returns a human-readable description.
func (c *ResourceLimitsRatioChecker) Description() string {
	return "Detects containers where limits-to-requests ratio exceeds 3x, indicating overcommitment risk."
}

// Categories returns the check categories.
func (c *ResourceLimitsRatioChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ResourceLimitsRatioChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ResourceLimitsRatioChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the resource-limits-ratio check against all workload resources in the cache.
func (c *ResourceLimitsRatioChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resource-limits-ratio check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			cpuRatio, cpuOK := resourceRatio(&container, corev1.ResourceCPU)
			memRatio, memOK := resourceRatio(&container, corev1.ResourceMemory)

			highCPU := cpuOK && cpuRatio > limitsToRequestsThreshold
			highMem := memOK && memRatio > limitsToRequestsThreshold

			if !highCPU && !highMem {
				return
			}

			var msg string
			switch {
			case highCPU && highMem:
				msg = fmt.Sprintf("Container %q has high limits-to-requests ratio for CPU (%.1fx) and memory (%.1fx), threshold is %.1fx.",
					container.Name, cpuRatio, memRatio, limitsToRequestsThreshold)
			case highCPU:
				msg = fmt.Sprintf("Container %q has high limits-to-requests ratio for CPU (%.1fx), threshold is %.1fx.",
					container.Name, cpuRatio, limitsToRequestsThreshold)
			default:
				msg = fmt.Sprintf("Container %q has high limits-to-requests ratio for memory (%.1fx), threshold is %.1fx.",
					container.Name, memRatio, limitsToRequestsThreshold)
			}

			fieldPath := containerFieldPath(ct, idx, "resources")

			findings = append(findings, checker.Finding{
				Checker:     "resource-limits-ratio",
				Severity:    checker.SeverityLow,
				Resource:    info.ResourceName,
				Namespace:   info.Namespace,
				Kind:        info.Kind,
				Container:   container.Name,
				Message:     msg,
				Remediation: "Reduce the limits-to-requests ratio. High ratios cause overcommitment and OOM kills.",
				FieldPath:   fieldPath,
			})
		})
	}

	return findings, nil
}

// resourceRatio calculates the limits-to-requests ratio for a given resource.
// Returns the ratio and true if both limits and requests are set and the request is non-zero.
// Returns 0 and false if either is missing or the request is zero.
func resourceRatio(container *corev1.Container, name corev1.ResourceName) (float64, bool) {
	if container.Resources.Limits == nil || container.Resources.Requests == nil {
		return 0, false
	}

	limit, limitOK := container.Resources.Limits[name]
	request, requestOK := container.Resources.Requests[name]
	if !limitOK || !requestOK {
		return 0, false
	}

	var limitVal, requestVal int64
	if name == corev1.ResourceCPU {
		limitVal = limit.MilliValue()
		requestVal = request.MilliValue()
	} else {
		limitVal = limit.Value()
		requestVal = request.Value()
	}

	if requestVal == 0 {
		return 0, false
	}

	return float64(limitVal) / float64(requestVal), true
}
