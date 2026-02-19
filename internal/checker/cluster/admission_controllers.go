package cluster

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// criticalAdmissionControllers that should be enabled.
var criticalAdmissionControllers = []string{
	"NodeRestriction",
	"PodSecurity",
}

// AdmissionControllersChecker detects critical admission controllers that are disabled.
type AdmissionControllersChecker struct{}

func (c *AdmissionControllersChecker) Name() string { return "admission-controllers" }
func (c *AdmissionControllersChecker) Description() string {
	return "Detects critical admission controllers that are disabled."
}
func (c *AdmissionControllersChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}
func (c *AdmissionControllersChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}
func (c *AdmissionControllersChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ConfigMapGVR}
}

func (c *AdmissionControllersChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("admission-controllers check: %w", err)
	}

	cms := resources.ListNamespaced(ConfigMapGVR, "kube-system")
	var findings []checker.Finding

	for i := range cms {
		cm := &cms[i]
		name := cm.GetName()
		if name != "kubeadm-config" && name != "kube-apiserver" {
			continue
		}

		data, found, _ := unstructured.NestedStringMap(cm.Object, "data")
		if !found {
			continue
		}

		for _, v := range data {
			if containsFlag(v, "--disable-admission-plugins") {
				for _, ac := range criticalAdmissionControllers {
					if strings.Contains(v, ac) {
						findings = append(findings, checker.Finding{
							Checker:   "admission-controllers",
							Severity:  checker.SeverityMedium,
							Resource:  name,
							Namespace: "kube-system",
							Kind:      "ConfigMap",
							Message:   fmt.Sprintf("Critical admission controller %q appears to be disabled.", ac),
							Remediation: fmt.Sprintf("## Why This Matters\n\n"+
								"The %s admission controller enforces critical security constraints on API requests. "+
								"Disabling it removes a defense-in-depth layer, allowing requests that would otherwise be rejected -- such as privilege escalations or unsafe pod configurations.\n\n"+
								"## How to Fix\n\n"+
								"Re-enable the admission controller in the API server configuration:\n\n"+
								"```yaml\n# kube-apiserver flags:\n# --enable-admission-plugins=NodeRestriction,PodSecurity,...\n# Ensure %s is NOT listed in:\n# --disable-admission-plugins\n```\n\n"+
								"Restart the API server after changing admission controller flags.\n\n"+
								"## Learn More\n\n"+
								"CIS Kubernetes Benchmark 1.2.11-1.2.18 covers required admission controllers. "+
								"See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/ for the full list and their security roles.", ac, ac),
						})
					}
				}
			}
		}
	}

	return findings, nil
}
