// Package cloud implements cloud provider security checkers.
// These checkers detect IMDS exposure, metadata concealment gaps,
// deprecated pod identity, and auto-detect cloud providers.
package cloud

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVR constants for cloud-related resource types.
var (
	NodeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "nodes",
	}
	NetworkPolicyGVR = schema.GroupVersionResource{
		Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
	}
	DaemonSetGVR = schema.GroupVersionResource{
		Group: "apps", Version: "v1", Resource: "daemonsets",
	}
)

// Provider represents a detected cloud provider.
type Provider string

const (
	ProviderEKS     Provider = "EKS"
	ProviderGKE     Provider = "GKE"
	ProviderAKS     Provider = "AKS"
	ProviderUnknown Provider = "Unknown"
)

// detectProvider determines the cloud provider from node labels.
func detectProvider(nodes []unstructured.Unstructured) Provider {
	for _, node := range nodes {
		labels := node.GetLabels()
		if labels == nil {
			continue
		}

		// EKS nodes have eks.amazonaws.com labels or alpha.eksctl.io labels.
		if _, ok := labels["eks.amazonaws.com/nodegroup"]; ok {
			return ProviderEKS
		}
		if _, ok := labels["alpha.eksctl.io/cluster-name"]; ok {
			return ProviderEKS
		}

		// GKE nodes have cloud.google.com labels.
		if _, ok := labels["cloud.google.com/gke-nodepool"]; ok {
			return ProviderGKE
		}

		// AKS nodes have kubernetes.azure.com labels.
		if _, ok := labels["kubernetes.azure.com/cluster"]; ok {
			return ProviderAKS
		}

		// Provider ID based detection.
		providerID, _, _ := unstructured.NestedString(node.Object, "spec", "providerID")
		if len(providerID) > 4 {
			switch {
			case providerID[:5] == "aws:/":
				return ProviderEKS
			case providerID[:4] == "gce:":
				return ProviderGKE
			case len(providerID) > 6 && providerID[:7] == "azure:/":
				return ProviderAKS
			}
		}
	}

	return ProviderUnknown
}
