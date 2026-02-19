// Package psa implements Pod Security Standards (PSA/PSS) checkers.
// These checkers analyze namespace PSA labels and workload compliance
// with the Kubernetes Pod Security Standards Baseline and Restricted profiles.
package psa

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// GVR constants for PSA-related resources.
var (
	// NamespaceGVR is the GroupVersionResource for Namespace.
	NamespaceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	// PodSecurityPolicyGVR is the GroupVersionResource for PodSecurityPolicy (deprecated in K8s 1.25).
	PodSecurityPolicyGVR = schema.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}
)

// PSA label constants for Pod Security Admission.
const (
	psaLabelPrefix = "pod-security.kubernetes.io/"
	psaEnforce     = psaLabelPrefix + "enforce"
	psaEnforceVer  = psaLabelPrefix + "enforce-version"
	psaAudit       = psaLabelPrefix + "audit"
	psaAuditVer    = psaLabelPrefix + "audit-version"
	psaWarn        = psaLabelPrefix + "warn"
	psaWarnVer     = psaLabelPrefix + "warn-version"
)

// systemNamespaces is the set of Kubernetes system namespaces that are excluded
// from PSA label checks. These namespaces require special handling and are
// typically managed by the cluster control plane.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// isSystemNamespace returns true for Kubernetes system namespaces that should
// be excluded from PSA enforcement checks.
func isSystemNamespace(name string) bool {
	return systemNamespaces[name]
}

// containerFieldPath builds a JSON-path field reference for a container field.
func containerFieldPath(ct workload.ContainerType, idx int, field string) string {
	switch ct {
	case workload.ContainerTypeInit, workload.ContainerTypeSidecar:
		return fmt.Sprintf(".spec.initContainers[%d].%s", idx, field)
	default:
		return fmt.Sprintf(".spec.containers[%d].%s", idx, field)
	}
}
