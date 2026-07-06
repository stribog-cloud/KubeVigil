package crd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// toUnstructured converts a map to an unstructured representation.
func toUnstructured(t *testing.T, obj map[string]interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

// makeCRD creates a CRD unstructured object for testing.
func makeCRD(t *testing.T, name string, versions []map[string]interface{}, conversion map[string]interface{}) unstructured.Unstructured {
	t.Helper()
	obj := map[string]interface{}{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata": map[string]interface{}{
			"name": name,
		},
		"spec": map[string]interface{}{
			"versions": versions,
		},
	}
	if conversion != nil {
		obj["spec"].(map[string]interface{})["conversion"] = conversion
	}
	return toUnstructured(t, obj)
}

// makeCRDWithSpec creates a CRD unstructured object for testing, like makeCRD,
// but also merges arbitrary additional top-level spec fields (e.g.
// preserveUnknownFields) into the resulting object.
func makeCRDWithSpec(t *testing.T, name string, versions []map[string]interface{}, conversion map[string]interface{}, extraSpec map[string]interface{}) unstructured.Unstructured {
	t.Helper()
	obj := makeCRD(t, name, versions, conversion)
	spec, ok := obj.Object["spec"].(map[string]interface{})
	require.True(t, ok)
	for k, v := range extraSpec {
		spec[k] = v
	}
	return obj
}

// makeCertificate creates a cert-manager Certificate unstructured object for testing.
func makeCertificate(t *testing.T, name, ns string, spec map[string]interface{}, status map[string]interface{}) unstructured.Unstructured {
	t.Helper()
	obj := map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": ns,
		},
		"spec": spec,
	}
	if status != nil {
		obj["status"] = status
	}
	return toUnstructured(t, obj)
}
