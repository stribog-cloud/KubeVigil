// Package cluster implements cluster configuration and hardening checkers.
// These checkers analyze namespaces, LimitRanges, ResourceQuotas, API server
// configuration, audit logging, etcd encryption, kubelet config, and API versions.
package cluster

import "k8s.io/apimachinery/pkg/runtime/schema"

// GVR constants for cluster-related resources.
var (
	NamespaceGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "namespaces",
	}
	LimitRangeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "limitranges",
	}
	ResourceQuotaGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "resourcequotas",
	}
	NodeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "nodes",
	}
	ConfigMapGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "configmaps",
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
