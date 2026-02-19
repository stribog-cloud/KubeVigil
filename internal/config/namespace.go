package config

// NamespaceType classifies a Kubernetes namespace.
type NamespaceType int

const (
	// NamespaceApplication is a user application namespace.
	NamespaceApplication NamespaceType = iota
	// NamespaceInfrastructure is a cluster infrastructure namespace.
	NamespaceInfrastructure
	// NamespaceSystem is a Kubernetes system namespace.
	NamespaceSystem
	// NamespaceClusterScoped represents cluster-scoped resources (empty namespace).
	NamespaceClusterScoped
)

// String returns the string representation of the namespace type.
func (t NamespaceType) String() string {
	switch t {
	case NamespaceApplication:
		return "application"
	case NamespaceInfrastructure:
		return "infrastructure"
	case NamespaceSystem:
		return "system"
	case NamespaceClusterScoped:
		return "cluster-scoped"
	default:
		return "unknown"
	}
}

// defaultInfraNamespaces are namespaces belonging to common cluster infrastructure
// components. These are auto-detected and can be excluded with --exclude-infra.
var defaultInfraNamespaces = map[string]bool{
	// CNI
	"calico-system":    true,
	"calico-apiserver": true,
	"tigera-operator":  true,
	"cilium":           true,
	"flannel":          true,
	"weave-net":        true,
	// Storage
	"rook-ceph":       true,
	"longhorn-system": true,
	"openebs":         true,
	"ceph-csi":        true,
	// Monitoring
	"monitoring":     true,
	"prometheus":     true,
	"grafana":        true,
	"loki":           true,
	"elastic-system": true,
	// Ingress / Service Mesh
	"ingress-nginx": true,
	"traefik":       true,
	"istio-system":  true,
	"istio-ingress": true,
	// Security
	"cert-manager": true,
	"vault":        true,
	"falco":        true,
	"trivy-system": true,
	// GitOps
	"argocd":           true,
	"flux-system":      true,
	"tekton-pipelines": true,
	// Other infrastructure
	"metallb-system":    true,
	"external-dns":      true,
	"kyverno":           true,
	"gatekeeper-system": true,
}

// ClassifyNamespace returns the namespace type for a given namespace name.
// It checks system namespaces first, then infrastructure, then defaults to
// application. An empty namespace is classified as cluster-scoped.
func ClassifyNamespace(cfg *Config, ns string) NamespaceType {
	if ns == "" {
		return NamespaceClusterScoped
	}
	if IsSystemNamespace(ns) {
		return NamespaceSystem
	}
	if isInfraNamespace(cfg, ns) {
		return NamespaceInfrastructure
	}
	return NamespaceApplication
}

// isInfraNamespace checks if a namespace is an infrastructure namespace,
// using both the built-in list and any user-configured overrides.
func isInfraNamespace(cfg *Config, ns string) bool {
	// Check user-configured infra namespaces first.
	if cfg != nil {
		for _, infra := range cfg.Settings.InfraNamespaces {
			if infra == ns {
				return true
			}
		}
	}
	return defaultInfraNamespaces[ns]
}

// IsInfraNamespace returns true if the namespace is classified as infrastructure.
func IsInfraNamespace(cfg *Config, ns string) bool {
	return ClassifyNamespace(cfg, ns) == NamespaceInfrastructure
}
