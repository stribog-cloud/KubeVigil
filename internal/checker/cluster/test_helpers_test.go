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
