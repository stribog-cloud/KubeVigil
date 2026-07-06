// Package cluster implements cluster configuration and hardening checkers.
// These checkers analyze namespaces, LimitRanges, ResourceQuotas, API server
// configuration, audit logging, etcd encryption, kubelet config, and API versions.
package cluster

import "k8s.io/apimachinery/pkg/runtime/schema"

// GVR constants for cluster-related resources.
var (
	// NamespaceGVR is the GroupVersionResource for core/v1 Namespace objects.
	NamespaceGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "namespaces",
	}
	// LimitRangeGVR is the GroupVersionResource for core/v1 LimitRange objects.
	LimitRangeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "limitranges",
	}
	// ResourceQuotaGVR is the GroupVersionResource for core/v1 ResourceQuota objects.
	ResourceQuotaGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "resourcequotas",
	}
	// NodeGVR is the GroupVersionResource for core/v1 Node objects.
	NodeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "nodes",
	}
	// ConfigMapGVR is the GroupVersionResource for core/v1 ConfigMap objects.
	ConfigMapGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "configmaps",
	}
	// ValidatingWebhookConfigurationGVR is the GroupVersionResource for
	// admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration objects.
	ValidatingWebhookConfigurationGVR = schema.GroupVersionResource{
		Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations",
	}
	// MutatingWebhookConfigurationGVR is the GroupVersionResource for
	// admissionregistration.k8s.io/v1 MutatingWebhookConfiguration objects.
	MutatingWebhookConfigurationGVR = schema.GroupVersionResource{
		Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations",
	}
	// ValidatingAdmissionPolicyGVR is the GroupVersionResource for
	// admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy objects.
	ValidatingAdmissionPolicyGVR = schema.GroupVersionResource{
		Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies",
	}
	// ValidatingAdmissionPolicyBindingGVR is the GroupVersionResource for
	// admissionregistration.k8s.io/v1 ValidatingAdmissionPolicyBinding objects.
	ValidatingAdmissionPolicyBindingGVR = schema.GroupVersionResource{
		Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings",
	}
	// APIServiceGVR is the GroupVersionResource for apiregistration.k8s.io/v1
	// APIService objects.
	APIServiceGVR = schema.GroupVersionResource{
		Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices",
	}
)

// systemNamespaces is the set of Kubernetes system namespaces excluded from
// namespace-level checks.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// isSystemNamespace returns true for Kubernetes system namespaces.
func isSystemNamespace(name string) bool {
	return systemNamespaces[name]
}
