// Package network implements network security checkers for Kubernetes resources.
// These checkers analyze NetworkPolicies, Ingresses, and Services for security
// misconfigurations and missing hardening.
package network

import (
	"slices"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVR constants for network-related resources.
var (
	// NetworkPolicyGVR is the GroupVersionResource for NetworkPolicy.
	NetworkPolicyGVR = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	// IngressGVR is the GroupVersionResource for Ingress.
	IngressGVR = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}
	// ServiceGVR is the GroupVersionResource for Service.
	ServiceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	// NamespaceGVR is the GroupVersionResource for Namespace.
	NamespaceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	// GatewayGVR is the GroupVersionResource for the Gateway API Gateway resource.
	GatewayGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	// HTTPRouteGVR is the GroupVersionResource for the Gateway API HTTPRoute resource.
	HTTPRouteGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
)

// systemNamespaces are Kubernetes system namespaces that are excluded from
// namespace-level network security checks.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"default":         true,
}

// isSystemNamespace returns true if the given namespace is a Kubernetes system namespace
// that should be excluded from namespace-level network security checks.
func isSystemNamespace(name string) bool {
	return systemNamespaces[name]
}

// toStringSlice converts an any (expected []any) to []string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	slice, ok := v.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// containsString checks if a string slice contains a specific value.
func containsString(slice []string, val string) bool {
	return slices.Contains(slice, val)
}
