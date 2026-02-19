package psa

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// toUnstructured converts a typed Kubernetes object to an unstructured representation.
func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

// makeNamespace builds an unstructured Namespace for testing.
func makeNamespace(t *testing.T, name string, labels map[string]string) unstructured.Unstructured {
	t.Helper()
	ns := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	return toUnstructured(t, ns)
}

// makePSP builds an unstructured PodSecurityPolicy for testing.
func makePSP(name string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "policy/v1beta1",
		"kind":       "PodSecurityPolicy",
		"metadata":   map[string]interface{}{"name": name},
		"spec":       map[string]interface{}{"privileged": false},
	}}
}
