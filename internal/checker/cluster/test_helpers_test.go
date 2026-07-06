package cluster

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func toUnstructured(t *testing.T, obj any) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

func makeNamespace(t *testing.T, name string, labels map[string]string) unstructured.Unstructured {
	t.Helper()
	ns := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	return toUnstructured(t, ns)
}

func makeConfigMap(t *testing.T, name, ns string, data map[string]string) unstructured.Unstructured {
	t.Helper()
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       data,
	}
	return toUnstructured(t, cm)
}

func makeNode(name, kubeletVersion string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata":   map[string]any{"name": name},
		"status": map[string]any{
			"nodeInfo": map[string]any{
				"kubeletVersion": kubeletVersion,
			},
		},
	}}
}

// makeValidatingWebhookConfig creates a ValidatingWebhookConfiguration
// unstructured object for testing.
func makeValidatingWebhookConfig(t *testing.T, name string, webhooks []map[string]any) unstructured.Unstructured {
	t.Helper()
	return toUnstructured(t, map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingWebhookConfiguration",
		"metadata":   map[string]any{"name": name},
		"webhooks":   webhooks,
	})
}

// makeMutatingWebhookConfig creates a MutatingWebhookConfiguration
// unstructured object for testing.
func makeMutatingWebhookConfig(t *testing.T, name string, webhooks []map[string]any) unstructured.Unstructured {
	t.Helper()
	return toUnstructured(t, map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "MutatingWebhookConfiguration",
		"metadata":   map[string]any{"name": name},
		"webhooks":   webhooks,
	})
}

// makeValidatingAdmissionPolicyBinding creates a ValidatingAdmissionPolicyBinding
// unstructured object for testing.
func makeValidatingAdmissionPolicyBinding(t *testing.T, name, policyName string, validationActions []string) unstructured.Unstructured {
	t.Helper()
	return toUnstructured(t, map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"policyName":        policyName,
			"validationActions": validationActions,
		},
	})
}

// makeValidatingAdmissionPolicy creates a ValidatingAdmissionPolicy
// unstructured object for testing.
func makeValidatingAdmissionPolicy(t *testing.T, name string) unstructured.Unstructured {
	t.Helper()
	return toUnstructured(t, map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicy",
		"metadata":   map[string]any{"name": name},
	})
}

// makeAPIService creates an APIService unstructured object for testing.
func makeAPIService(t *testing.T, name string, insecureSkipTLSVerify bool, caBundle string) unstructured.Unstructured {
	t.Helper()
	spec := map[string]any{
		"insecureSkipTLSVerify": insecureSkipTLSVerify,
	}
	if caBundle != "" {
		spec["caBundle"] = caBundle
	}
	return toUnstructured(t, map[string]any{
		"apiVersion": "apiregistration.k8s.io/v1",
		"kind":       "APIService",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	})
}
