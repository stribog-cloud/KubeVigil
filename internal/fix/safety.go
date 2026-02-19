package fix

import "sort"

// DefaultSystemNamespaces is the built-in list of system namespaces that are
// protected from auto-remediation unless explicitly overridden.
var DefaultSystemNamespaces = []string{
	"kube-system", "kube-public", "kube-node-lease",
	"rook-ceph", "rook-ceph-system",
	"calico-system", "calico-apiserver", "tigera-operator",
	"cilium", "cilium-system",
	"ingress-nginx", "traefik", "traefik-system",
	"cert-manager",
	"monitoring", "prometheus", "grafana",
	"istio-system", "linkerd", "linkerd-cni",
	"metallb-system", "longhorn-system", "openebs",
}

// SafetyClassifier determines whether resources should be skipped during fix operations.
type SafetyClassifier struct {
	systemNamespaces map[string]bool
}

// NewSafetyClassifier creates a SafetyClassifier with the default system namespaces
// plus any additional ones provided. The additional namespaces extend (never replace)
// the built-in defaults.
func NewSafetyClassifier(additionalNamespaces []string) *SafetyClassifier {
	sc := &SafetyClassifier{
		systemNamespaces: make(map[string]bool, len(DefaultSystemNamespaces)+len(additionalNamespaces)),
	}
	for _, ns := range DefaultSystemNamespaces {
		sc.systemNamespaces[ns] = true
	}
	for _, ns := range additionalNamespaces {
		if ns != "" {
			sc.systemNamespaces[ns] = true
		}
	}
	return sc
}

// IsSystemNamespace returns true if the namespace is a recognized system namespace.
func (sc *SafetyClassifier) IsSystemNamespace(namespace string) bool {
	return sc.systemNamespaces[namespace]
}

// SystemNamespaces returns the full list of system namespaces (sorted).
func (sc *SafetyClassifier) SystemNamespaces() []string {
	result := make([]string, 0, len(sc.systemNamespaces))
	for ns := range sc.systemNamespaces {
		result = append(result, ns)
	}
	sort.Strings(result)
	return result
}

// ClassifyResource determines whether a resource should be skipped and why.
// Returns skip=true with a reason string, or skip=false with empty reason.
// Checks system namespace first, then known workload patterns.
func (sc *SafetyClassifier) ClassifyResource(namespace, kind string, images []string) (skip bool, reason string) {
	if namespace != "" && sc.IsSystemNamespace(namespace) {
		return true, "system_namespace"
	}
	if wl, matched := MatchKnownWorkload(images); matched {
		return true, wl.Reason
	}
	return false, ""
}
