package scheduling

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGetReplicas_Int64(t *testing.T) {
	// Live cluster data stores replicas as int64 in unstructured objects.
	// Regression: old code only tried NestedFloat64, which returned false
	// for int64 values, defaulting replicas to 1.
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"replicas": int64(3),
			},
		},
	}
	assert.Equal(t, int64(3), getReplicas(obj))
}

func TestGetReplicas_Float64(t *testing.T) {
	// JSON decoding from YAML/manifest files stores replicas as float64.
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"replicas": float64(5),
			},
		},
	}
	assert.Equal(t, int64(5), getReplicas(obj))
}

func TestGetReplicas_Missing(t *testing.T) {
	// When spec.replicas is absent, Kubernetes defaults to 1.
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{},
		},
	}
	assert.Equal(t, int64(1), getReplicas(obj))
}

func TestGetReplicas_Zero(t *testing.T) {
	// Explicitly scaled to zero — must return 0, not the default 1.
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"replicas": int64(0),
			},
		},
	}
	assert.Equal(t, int64(0), getReplicas(obj))
}
