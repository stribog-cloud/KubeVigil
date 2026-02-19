package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// --- Test helper functions for building unstructured K8s objects ---

// makeNamespace builds an unstructured Namespace for testing.
func makeNamespace(name string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]interface{}{"name": name},
	}}
}

// makeNetworkPolicy builds an unstructured NetworkPolicy for testing.
func makeNetworkPolicy(name, namespace string, spec map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"spec":       spec,
	}}
}

// makeDefaultDenyPolicy builds a default-deny NetworkPolicy.
func makeDefaultDenyPolicy(name, namespace string, policyTypes ...string) unstructured.Unstructured {
	pt := make([]interface{}, len(policyTypes))
	for i, p := range policyTypes {
		pt[i] = p
	}
	return makeNetworkPolicy(name, namespace, map[string]interface{}{
		"podSelector": map[string]interface{}{},
		"policyTypes": pt,
	})
}

// makeIngress builds an unstructured Ingress for testing.
func makeIngress(name, namespace string, spec map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"spec":       spec,
	}}
}

// makeIngressWithAnnotations builds an unstructured Ingress with annotations.
func makeIngressWithAnnotations(name, namespace string, annotations map[string]string, spec map[string]interface{}) unstructured.Unstructured {
	annIface := make(map[string]interface{}, len(annotations))
	for k, v := range annotations {
		annIface[k] = v
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace, "annotations": annIface},
		"spec":       spec,
	}}
}

// makeIngressRule builds a single Ingress rule map.
func makeIngressRule(host string) map[string]interface{} {
	rule := map[string]interface{}{
		"http": map[string]interface{}{
			"paths": []interface{}{
				map[string]interface{}{
					"path":     "/",
					"pathType": "Prefix",
					"backend": map[string]interface{}{
						"service": map[string]interface{}{
							"name": "my-svc",
							"port": map[string]interface{}{"number": int64(80)},
						},
					},
				},
			},
		},
	}
	if host != "" {
		rule["host"] = host
	}
	return rule
}

// makeIngressTLS builds a single TLS entry for an Ingress.
func makeIngressTLS(hosts []string, secretName string) map[string]interface{} {
	hostIface := make([]interface{}, len(hosts))
	for i, h := range hosts {
		hostIface[i] = h
	}
	return map[string]interface{}{
		"hosts":      hostIface,
		"secretName": secretName,
	}
}

// --- Tests for helper functions ---

func TestIsSystemNamespace(t *testing.T) {
	tests := []struct {
		name   string
		ns     string
		system bool
	}{
		{"kube-system is system", "kube-system", true},
		{"kube-public is system", "kube-public", true},
		{"kube-node-lease is system", "kube-node-lease", true},
		{"default is system", "default", true},
		{"custom namespace is not system", "my-app", false},
		{"production is not system", "production", false},
		{"empty is not system", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.system, isSystemNamespace(tt.ns))
		})
	}
}

func TestContainsString(t *testing.T) {
	assert.True(t, containsString([]string{"a", "b", "c"}, "b"))
	assert.False(t, containsString([]string{"a", "b", "c"}, "d"))
	assert.False(t, containsString(nil, "a"))
	assert.False(t, containsString([]string{}, "a"))
}

func TestToStringSlice(t *testing.T) {
	assert.Nil(t, toStringSlice(nil))
	assert.Nil(t, toStringSlice("not a slice"))
	assert.Equal(t, []string{"a", "b"}, toStringSlice([]interface{}{"a", "b"}))
	assert.Equal(t, []string{"a"}, toStringSlice([]interface{}{"a", 42}))
}

func TestGVRConstants(t *testing.T) {
	assert.Equal(t, "networking.k8s.io", NetworkPolicyGVR.Group)
	assert.Equal(t, "v1", NetworkPolicyGVR.Version)
	assert.Equal(t, "networkpolicies", NetworkPolicyGVR.Resource)

	assert.Equal(t, "networking.k8s.io", IngressGVR.Group)
	assert.Equal(t, "v1", IngressGVR.Version)
	assert.Equal(t, "ingresses", IngressGVR.Resource)

	assert.Equal(t, "", ServiceGVR.Group)
	assert.Equal(t, "v1", ServiceGVR.Version)
	assert.Equal(t, "services", ServiceGVR.Resource)

	assert.Equal(t, "", NamespaceGVR.Group)
	assert.Equal(t, "v1", NamespaceGVR.Version)
	assert.Equal(t, "namespaces", NamespaceGVR.Resource)
}
