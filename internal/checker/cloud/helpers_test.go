package cloud

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDetectProvider(t *testing.T) {
	testCases := []struct {
		name     string
		nodes    []unstructured.Unstructured
		expected Provider
	}{
		{
			name:     "empty node list returns Unknown",
			nodes:    nil,
			expected: ProviderUnknown,
		},
		{
			name: "node with no cloud labels returns Unknown",
			nodes: []unstructured.Unstructured{
				makeNode(t, "bare-metal", map[string]string{"kubernetes.io/os": "linux"}),
			},
			expected: ProviderUnknown,
		},
		{
			name: "node with nil labels returns Unknown",
			nodes: []unstructured.Unstructured{
				makeNode(t, "no-labels", nil),
			},
			expected: ProviderUnknown,
		},
		{
			name: "node with eks.amazonaws.com/nodegroup label returns EKS",
			nodes: []unstructured.Unstructured{
				makeNode(t, "eks-node", map[string]string{"eks.amazonaws.com/nodegroup": "workers"}),
			},
			expected: ProviderEKS,
		},
		{
			name: "node with alpha.eksctl.io/cluster-name label returns EKS",
			nodes: []unstructured.Unstructured{
				makeNode(t, "eks-node", map[string]string{"alpha.eksctl.io/cluster-name": "my-cluster"}),
			},
			expected: ProviderEKS,
		},
		{
			name: "node with GKE label returns GKE",
			nodes: []unstructured.Unstructured{
				makeNode(t, "gke-node", map[string]string{"cloud.google.com/gke-nodepool": "default-pool"}),
			},
			expected: ProviderGKE,
		},
		{
			name: "node with AKS label returns AKS",
			nodes: []unstructured.Unstructured{
				makeNode(t, "aks-node", map[string]string{"kubernetes.azure.com/cluster": "my-cluster"}),
			},
			expected: ProviderAKS,
		},
		{
			name: "multiple nodes with different labels returns first match",
			nodes: []unstructured.Unstructured{
				makeNode(t, "bare-node", map[string]string{"kubernetes.io/os": "linux"}),
				makeNode(t, "gke-node", map[string]string{"cloud.google.com/gke-nodepool": "pool1"}),
				makeNode(t, "eks-node", map[string]string{"eks.amazonaws.com/nodegroup": "workers"}),
			},
			expected: ProviderGKE,
		},
		{
			name: "node with AWS providerID returns EKS",
			nodes: []unstructured.Unstructured{
				nodeWithProviderID(t, "aws-node", "aws://us-east-1/i-1234567890"),
			},
			expected: ProviderEKS,
		},
		{
			name: "node with GCE providerID returns GKE",
			nodes: []unstructured.Unstructured{
				nodeWithProviderID(t, "gce-node", "gce://my-project/us-central1-a/node-1"),
			},
			expected: ProviderGKE,
		},
		{
			name: "node with Azure providerID returns AKS",
			nodes: []unstructured.Unstructured{
				nodeWithProviderID(t, "azure-node", "azure:///subscriptions/sub-id/resourceGroups/rg"),
			},
			expected: ProviderAKS,
		},
		{
			name: "node with short providerID returns Unknown",
			nodes: []unstructured.Unstructured{
				nodeWithProviderID(t, "short-node", "abc"),
			},
			expected: ProviderUnknown,
		},
		{
			name: "node with unknown providerID returns Unknown",
			nodes: []unstructured.Unstructured{
				nodeWithProviderID(t, "openstack-node", "openstack:///instance-id"),
			},
			expected: ProviderUnknown,
		},
		{
			name: "first node with no labels skipped, second node detected",
			nodes: []unstructured.Unstructured{
				makeNode(t, "no-labels", nil),
				makeNode(t, "aks-node", map[string]string{"kubernetes.azure.com/cluster": "cluster1"}),
			},
			expected: ProviderAKS,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectProvider(tc.nodes)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// nodeWithProviderID creates a Node with a providerID set in spec.providerID.
func nodeWithProviderID(t *testing.T, name, providerID string) unstructured.Unstructured {
	t.Helper()
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Node",
			"metadata": map[string]interface{}{
				"name":   name,
				"labels": map[string]interface{}{},
			},
			"spec": map[string]interface{}{
				"providerID": providerID,
			},
		},
	}
}

func TestHasNetworkPolicyBlockingIMDS(t *testing.T) {
	testCases := []struct {
		name     string
		policies []unstructured.Unstructured
		expected bool
	}{
		{
			name:     "empty policies slice returns false",
			policies: nil,
			expected: false,
		},
		{
			name: "policy with no policyTypes returns false",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
				}),
			},
			expected: false,
		},
		{
			name: "policy with Ingress only returns false",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				}),
			},
			expected: false,
		},
		{
			name: "policy with Egress and non-empty egress rules returns false",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr": "10.0.0.0/8",
									},
								},
							},
						},
					},
				}),
			},
			expected: false,
		},
		{
			name: "policy with Egress and empty egress rules (default deny) returns true",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
				}),
			},
			expected: true,
		},
		{
			name: "policy with Egress and explicit empty egress array returns true",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress":      []interface{}{},
				}),
			},
			expected: true,
		},
		{
			name: "multiple policies, second one has default deny egress returns true",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				}),
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
				}),
			},
			expected: true,
		},
		{
			name: "policy with both Ingress and Egress policyTypes and empty egress returns true",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress", "Egress"},
				}),
			},
			expected: true,
		},
		{
			name: "multiple policies none matching returns false",
			policies: []unstructured.Unstructured{
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				}),
				makeNetworkPolicy(map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr": "0.0.0.0/0",
									},
								},
							},
						},
					},
				}),
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasNetworkPolicyBlockingIMDS(tc.policies)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// makeNetworkPolicy creates an unstructured NetworkPolicy with the given spec fields.
func makeNetworkPolicy(spec map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      "test-policy",
				"namespace": "default",
			},
			"spec": spec,
		},
	}
}
