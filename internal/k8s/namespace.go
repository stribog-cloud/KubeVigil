package k8s

// CoreSystemNamespaces are the three Kubernetes control-plane namespaces.
// Resources in these namespaces legitimately require elevated privileges.
var CoreSystemNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
}

// InfrastructureNamespaces are namespaces used by common Kubernetes infrastructure
// components (CNI, ingress, service mesh, observability, storage, etc.).
// These namespaces are protected from auto-remediation because their workloads
// intentionally use privileged capabilities.
var InfrastructureNamespaces = []string{
	"rook-ceph", "rook-ceph-system",
	"calico-system", "calico-apiserver", "tigera-operator",
	"cilium", "cilium-system",
	"ingress-nginx", "traefik", "traefik-system",
	"cert-manager",
	"monitoring", "prometheus", "grafana",
	"istio-system", "linkerd", "linkerd-cni",
	"metallb-system", "longhorn-system", "openebs",
}

// AllProtectedNamespaces combines CoreSystemNamespaces and InfrastructureNamespaces.
// This is the full set of namespaces that should be protected from auto-remediation.
var AllProtectedNamespaces = func() []string {
	all := make([]string, 0, len(CoreSystemNamespaces)+len(InfrastructureNamespaces))
	all = append(all, CoreSystemNamespaces...)
	all = append(all, InfrastructureNamespaces...)
	return all
}()
