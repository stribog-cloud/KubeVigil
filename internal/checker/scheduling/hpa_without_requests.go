package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// HPAWithoutRequestsChecker detects HorizontalPodAutoscalers targeting workloads
// that have no resource requests set. HPA based on CPU/memory percentage requires
// requests to be defined; without them, autoscaling is unpredictable.
type HPAWithoutRequestsChecker struct{}

// Name returns the kebab-case check ID.
func (c *HPAWithoutRequestsChecker) Name() string { return "hpa-without-requests" }

// Description returns a human-readable description.
func (c *HPAWithoutRequestsChecker) Description() string {
	return "Detects HPAs targeting workloads without resource requests, making percentage-based autoscaling unpredictable."
}

// Categories returns the check categories.
func (c *HPAWithoutRequestsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *HPAWithoutRequestsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HPAWithoutRequestsChecker) RequiredResources() []schema.GroupVersionResource {
	gvrs := workload.GVRs()
	return append(gvrs, HorizontalPodAutoscalerGVR)
}

// Run executes the hpa-without-requests check.
func (c *HPAWithoutRequestsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hpa-without-requests check: %w", err)
	}

	hpas := resources.List(HorizontalPodAutoscalerGVR)
	var findings []checker.Finding

	for i := range hpas {
		hpa := &hpas[i]
		targetKind, targetName, _ := extractHPATargetRef(hpa)
		if targetKind == "" || targetName == "" {
			continue
		}

		ns := hpa.GetNamespace()
		if !workloadHasRequests(resources, targetKind, targetName, ns) {
			findings = append(findings, checker.Finding{
				Checker:   "hpa-without-requests",
				Severity:  checker.SeverityMedium,
				Resource:  hpa.GetName(),
				Namespace: ns,
				Kind:      "HorizontalPodAutoscaler",
				Message:   fmt.Sprintf("HPA %q targets %s %q which has no resource requests set; percentage-based autoscaling will be unpredictable.", hpa.GetName(), targetKind, targetName),
				Remediation: fmt.Sprintf("## Why This Matters\n\n"+
					"HPA calculates utilization as a percentage of resource requests (e.g., 80%% of requested CPU). "+
					"Without requests defined on the target %s %q, the HPA cannot compute meaningful utilization percentages, "+
					"leading to erratic scaling behavior, unnecessary scale-ups, or failure to scale entirely.\n\n"+
					"## How to Fix\n\n"+
					"Set resource requests on all containers in the target workload:\n\n"+
					"```yaml\ncontainers:\n  - name: app\n    resources:\n      requests:\n        cpu: 250m\n        memory: 256Mi\n      limits:\n        cpu: 500m\n        memory: 512Mi\n```\n\n"+
					"Size requests based on observed steady-state usage. The HPA will then scale when actual usage exceeds the target percentage of these requests.\n\n"+
					"## Learn More\n\n"+
					"See the Kubernetes HorizontalPodAutoscaler documentation on resource metrics. "+
					"The HPA algorithm divides current usage by requests to determine the desired replica count.", targetKind, targetName),
				FieldPath: ".spec.scaleTargetRef",
			})
		}
	}

	return findings, nil
}
