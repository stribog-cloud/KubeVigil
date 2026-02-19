package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestCheckStringDataMap tests the checkStringDataMap helper function
// covering branches: missing stringData, non-map stringData, empty map,
// non-string values, short values, non-matching values, matching values.
func TestCheckStringDataMap(t *testing.T) {
	testCases := []struct {
		name         string
		obj          unstructured.Unstructured
		threshold    float64
		wantFindings int
	}{
		{
			name: "missing stringData returns no findings",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "test", "namespace": "default"},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 0,
		},
		{
			name: "stringData is not a map returns no findings",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "test", "namespace": "default"},
				"stringData": "not-a-map",
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 0,
		},
		{
			name: "empty stringData map returns no findings",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "test", "namespace": "default"},
				"stringData": map[string]interface{}{},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 0,
		},
		{
			name: "non-string values in stringData are skipped",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "test", "namespace": "default"},
				"stringData": map[string]interface{}{
					"count": 42,
					"flag":  true,
				},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 0,
		},
		{
			name: "short plaintext values are skipped",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "test", "namespace": "default"},
				"stringData": map[string]interface{}{
					"pin": "123",
					"tag": "ab",
				},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 0,
		},
		{
			name: "non-matching low entropy values produce no findings",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "test", "namespace": "default"},
				"stringData": map[string]interface{}{
					"config": "this is a normal configuration value for the app",
				},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 0,
		},
		{
			name: "JWT pattern in stringData triggers finding",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "jwt-secret", "namespace": "default"},
				"stringData": map[string]interface{}{
					"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
				},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 1,
		},
		{
			name: "high entropy value triggers finding",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "entropy-secret", "namespace": "default"},
				"stringData": map[string]interface{}{
					"api-key": "aB3$kL9mNp2QrS5tUv8WxYz1fG7hJ0kL",
				},
			}},
			threshold:    DefaultEntropyThreshold,
			wantFindings: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := checkStringDataMap(&tc.obj, tc.threshold)
			assert.Len(t, findings, tc.wantFindings)
			if tc.wantFindings > 0 {
				assert.Equal(t, "secrets-hardcoded-manifests", findings[0].Checker)
			}
		})
	}
}

// TestNestedStringMap tests the nestedStringMap helper function
// covering branches: missing key, non-map intermediate value, non-map final value,
// non-string values in map, successful extraction.
func TestNestedStringMap(t *testing.T) {
	testCases := []struct {
		name      string
		obj       map[string]interface{}
		fields    []string
		wantMap   map[string]string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "missing key returns not found",
			obj:       map[string]interface{}{},
			fields:    []string{"data"},
			wantMap:   nil,
			wantFound: false,
			wantErr:   false,
		},
		{
			name: "final value is not a map returns error",
			obj: map[string]interface{}{
				"data": "not-a-map",
			},
			fields:    []string{"data"},
			wantMap:   nil,
			wantFound: false,
			wantErr:   true,
		},
		{
			name: "intermediate value is not a map returns error",
			obj: map[string]interface{}{
				"spec": "not-a-map",
			},
			fields:    []string{"spec", "data"},
			wantMap:   nil,
			wantFound: false,
			wantErr:   true,
		},
		{
			name: "non-string values in final map are skipped",
			obj: map[string]interface{}{
				"data": map[string]interface{}{
					"key1": "value1",
					"key2": 42,
					"key3": true,
					"key4": "value4",
				},
			},
			fields:    []string{"data"},
			wantMap:   map[string]string{"key1": "value1", "key4": "value4"},
			wantFound: true,
			wantErr:   false,
		},
		{
			name: "empty map returns empty result",
			obj: map[string]interface{}{
				"data": map[string]interface{}{},
			},
			fields:    []string{"data"},
			wantMap:   map[string]string{},
			wantFound: true,
			wantErr:   false,
		},
		{
			name: "successful extraction with single field",
			obj: map[string]interface{}{
				"data": map[string]interface{}{
					"host": "localhost",
					"port": "8080",
				},
			},
			fields:    []string{"data"},
			wantMap:   map[string]string{"host": "localhost", "port": "8080"},
			wantFound: true,
			wantErr:   false,
		},
		{
			name: "successful extraction with nested fields",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"key1": "val1",
					},
				},
			},
			fields:    []string{"spec", "template"},
			wantMap:   map[string]string{"key1": "val1"},
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "no fields returns nil not found",
			obj:       map[string]interface{}{"data": "value"},
			fields:    []string{},
			wantMap:   nil,
			wantFound: false,
			wantErr:   false,
		},
		{
			name: "missing nested key returns not found",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{},
			},
			fields:    []string{"spec", "missing"},
			wantMap:   nil,
			wantFound: false,
			wantErr:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, found, err := nestedStringMap(tc.obj, tc.fields...)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantFound, found)
			if tc.wantFound {
				assert.Equal(t, tc.wantMap, result)
			}
		})
	}
}
