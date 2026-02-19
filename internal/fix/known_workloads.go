package fix

import "strings"

// KnownWorkload describes a system-critical workload detected by image name pattern.
type KnownWorkload struct {
	// Pattern is a substring to match against container image names.
	Pattern string
	// Category describes the type of system workload (e.g., "CNI plugin", "Storage operator").
	Category string
	// Reason explains why this workload requires elevated privileges.
	Reason string
}

// DefaultKnownWorkloads is the built-in list of known system workloads.
var DefaultKnownWorkloads = []KnownWorkload{
	// CNI plugins
	{Pattern: "calico/node", Category: "CNI plugin", Reason: "CNI plugin requires elevated privileges for network management"},
	{Pattern: "calico/cni", Category: "CNI plugin", Reason: "CNI plugin requires elevated privileges for network setup"},
	{Pattern: "calico/kube-controllers", Category: "CNI plugin", Reason: "Calico controller manages network policies"},
	{Pattern: "cilium/cilium", Category: "CNI plugin", Reason: "CNI plugin requires elevated privileges for eBPF"},
	{Pattern: "cilium/operator", Category: "CNI plugin", Reason: "Cilium operator manages eBPF programs"},
	{Pattern: "flannel/flannel", Category: "CNI plugin", Reason: "CNI plugin requires host networking for overlay setup"},
	{Pattern: "weave/weave-kube", Category: "CNI plugin", Reason: "CNI plugin requires host networking"},
	{Pattern: "weave/weave-npc", Category: "CNI plugin", Reason: "Weave network policy controller"},

	// Storage operators
	{Pattern: "rook/ceph", Category: "Storage operator", Reason: "Storage operator requires privileged access for disk management"},
	{Pattern: "rancher/local-path-provisioner", Category: "Storage provisioner", Reason: "Storage provisioner needs host paths for volume management"},
	{Pattern: "longhornio/longhorn", Category: "Storage operator", Reason: "Storage operator requires privileged access for disk management"},
	{Pattern: "openebs/", Category: "Storage operator", Reason: "Storage operator requires privileged access for disk management"},

	// Core Kubernetes components
	{Pattern: "registry.k8s.io/kube-proxy", Category: "Core component", Reason: "kube-proxy requires host networking and capabilities for iptables management"},
	{Pattern: "registry.k8s.io/coredns", Category: "Core component", Reason: "CoreDNS needs NET_BIND_SERVICE to bind port 53"},
	{Pattern: "registry.k8s.io/etcd", Category: "Core component", Reason: "etcd is a core control plane component"},
	{Pattern: "registry.k8s.io/kube-apiserver", Category: "Core component", Reason: "API server is a core control plane component"},
	{Pattern: "registry.k8s.io/kube-controller-manager", Category: "Core component", Reason: "Controller manager is a core control plane component"},
	{Pattern: "registry.k8s.io/kube-scheduler", Category: "Core component", Reason: "Scheduler is a core control plane component"},

	// Monitoring
	{Pattern: "prom/node-exporter", Category: "Monitoring agent", Reason: "Node exporter requires host PID and network for metrics collection"},
	{Pattern: "prometheus/node-exporter", Category: "Monitoring agent", Reason: "Node exporter requires host PID and network for metrics collection"},
	{Pattern: "grafana/agent", Category: "Monitoring agent", Reason: "Grafana agent may need host access for metrics collection"},

	// Ingress controllers
	{Pattern: "ingress-nginx/controller", Category: "Ingress controller", Reason: "Ingress controller requires host ports and capabilities"},
	{Pattern: "traefik:", Category: "Ingress controller", Reason: "Traefik may need host ports for ingress traffic"},

	// Service mesh
	{Pattern: "istio/proxyv2", Category: "Service mesh", Reason: "Istio sidecar needs NET_ADMIN for traffic interception"},
	{Pattern: "linkerd/proxy", Category: "Service mesh", Reason: "Linkerd proxy needs network capabilities"},
	{Pattern: "linkerd/proxy-init", Category: "Service mesh", Reason: "Linkerd init container needs NET_ADMIN for iptables rules"},
}

// MatchKnownWorkload checks if any of the provided images match a known system workload.
// Returns the matching KnownWorkload and true if found, zero value and false otherwise.
// Matching is case-sensitive using substring containment.
func MatchKnownWorkload(images []string) (KnownWorkload, bool) {
	for _, image := range images {
		for _, wl := range DefaultKnownWorkloads {
			if strings.Contains(image, wl.Pattern) {
				return wl, true
			}
		}
	}
	return KnownWorkload{}, false
}
