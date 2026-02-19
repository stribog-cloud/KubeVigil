package workload

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestExtractFromUnstructured tests the extractFromUnstructured helper function
// covering branches: unknown kind, empty/missing podSpec map, valid extraction from each kind.
func TestExtractFromUnstructured(t *testing.T) {
	testCases := []struct {
		name     string
		obj      unstructured.Unstructured
		kind     string
		wantLen  int
		wantName string
	}{
		{
			name: "unknown kind returns nil",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test"},
				"spec":     map[string]interface{}{},
			}},
			kind:    "Unknown",
			wantLen: 0,
		},
		{
			name: "Pod with missing spec returns nil",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-pod"},
			}},
			kind:    "Pod",
			wantLen: 0,
		},
		{
			name: "Pod with empty spec map returns valid PodSpecInfo",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-pod", "namespace": "default"},
				"spec":     map[string]interface{}{},
			}},
			kind:     "Pod",
			wantLen:  1,
			wantName: "test-pod",
		},
		{
			name: "Deployment with valid template spec",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-deploy", "namespace": "default"},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "app",
									"image": "nginx:1.25",
								},
							},
						},
					},
				},
			}},
			kind:     "Deployment",
			wantLen:  1,
			wantName: "test-deploy",
		},
		{
			name: "Deployment with missing template returns nil",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-deploy"},
				"spec":     map[string]interface{}{},
			}},
			kind:    "Deployment",
			wantLen: 0,
		},
		{
			name: "StatefulSet with valid template spec",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-sts", "namespace": "default"},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "db",
									"image": "postgres:15",
								},
							},
						},
					},
				},
			}},
			kind:     "StatefulSet",
			wantLen:  1,
			wantName: "test-sts",
		},
		{
			name: "DaemonSet with valid template spec",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-ds", "namespace": "default"},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "agent",
									"image": "agent:v1",
								},
							},
						},
					},
				},
			}},
			kind:     "DaemonSet",
			wantLen:  1,
			wantName: "test-ds",
		},
		{
			name: "ReplicaSet with valid template spec",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-rs", "namespace": "default"},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "web",
									"image": "web:v2",
								},
							},
						},
					},
				},
			}},
			kind:     "ReplicaSet",
			wantLen:  1,
			wantName: "test-rs",
		},
		{
			name: "Job with valid template spec",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-job", "namespace": "default"},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "batch",
									"image": "batch:v1",
								},
							},
						},
					},
				},
			}},
			kind:     "Job",
			wantLen:  1,
			wantName: "test-job",
		},
		{
			name: "CronJob with valid nested template spec",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-cronjob", "namespace": "default"},
				"spec": map[string]interface{}{
					"jobTemplate": map[string]interface{}{
						"spec": map[string]interface{}{
							"template": map[string]interface{}{
								"spec": map[string]interface{}{
									"containers": []interface{}{
										map[string]interface{}{
											"name":  "cron",
											"image": "cron:v1",
										},
									},
								},
							},
						},
					},
				},
			}},
			kind:     "CronJob",
			wantLen:  1,
			wantName: "test-cronjob",
		},
		{
			name: "CronJob with missing jobTemplate returns nil",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-cronjob"},
				"spec":     map[string]interface{}{},
			}},
			kind:    "CronJob",
			wantLen: 0,
		},
		{
			name: "Pod with spec as non-map returns nil",
			obj: unstructured.Unstructured{Object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "test-pod"},
				"spec":     "not-a-map",
			}},
			kind:    "Pod",
			wantLen: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractFromUnstructured(tc.obj, tc.kind)
			assert.Len(t, result, tc.wantLen)
			if tc.wantLen > 0 && tc.wantName != "" {
				assert.Equal(t, tc.wantName, result[0].ResourceName)
				assert.Equal(t, tc.kind, result[0].Kind)
			}
		})
	}
}

// TestFindPodSpecMap tests the findPodSpecMap helper function
// covering branches: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, unknown kind.
func TestFindPodSpecMap(t *testing.T) {
	testCases := []struct {
		name      string
		obj       map[string]interface{}
		kind      string
		wantFound bool
	}{
		{
			name: "Pod path: spec",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{},
				},
			},
			kind:      "Pod",
			wantFound: true,
		},
		{
			name: "Deployment path: spec.template.spec",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{},
						},
					},
				},
			},
			kind:      "Deployment",
			wantFound: true,
		},
		{
			name: "Job path: spec.template.spec",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{},
					},
				},
			},
			kind:      "Job",
			wantFound: true,
		},
		{
			name: "CronJob path: spec.jobTemplate.spec.template.spec",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"jobTemplate": map[string]interface{}{
						"spec": map[string]interface{}{
							"template": map[string]interface{}{
								"spec": map[string]interface{}{},
							},
						},
					},
				},
			},
			kind:      "CronJob",
			wantFound: true,
		},
		{
			name:      "CronJob with missing intermediate key",
			obj:       map[string]interface{}{"spec": map[string]interface{}{}},
			kind:      "CronJob",
			wantFound: false,
		},
		{
			name:      "unknown kind returns not found",
			obj:       map[string]interface{}{"spec": map[string]interface{}{}},
			kind:      "CustomResource",
			wantFound: false,
		},
		{
			name:      "empty object returns not found for Pod",
			obj:       map[string]interface{}{},
			kind:      "Pod",
			wantFound: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, found := findPodSpecMap(tc.obj, tc.kind)
			assert.Equal(t, tc.wantFound, found)
			if tc.wantFound {
				require.NotNil(t, result)
			}
		})
	}
}

// TestNestedMap tests the nestedMap helper function
// covering branches: missing key, value at intermediate key not a map, valid nested traversal.
func TestNestedMap(t *testing.T) {
	testCases := []struct {
		name      string
		obj       map[string]interface{}
		keys      []string
		wantFound bool
	}{
		{
			name:      "single key found",
			obj:       map[string]interface{}{"spec": map[string]interface{}{"foo": "bar"}},
			keys:      []string{"spec"},
			wantFound: true,
		},
		{
			name:      "single key missing",
			obj:       map[string]interface{}{},
			keys:      []string{"spec"},
			wantFound: false,
		},
		{
			name:      "intermediate key is not a map",
			obj:       map[string]interface{}{"spec": "not-a-map"},
			keys:      []string{"spec", "template"},
			wantFound: false,
		},
		{
			name: "deeply nested path found",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{"containers": []interface{}{}},
					},
				},
			},
			keys:      []string{"spec", "template", "spec"},
			wantFound: true,
		},
		{
			name: "missing key in deep path",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{},
				},
			},
			keys:      []string{"spec", "template", "spec"},
			wantFound: false,
		},
		{
			name: "value at leaf is not a map",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": "not-a-map",
				},
			},
			keys:      []string{"spec", "template"},
			wantFound: false,
		},
		{
			name:      "no keys returns the object itself",
			obj:       map[string]interface{}{"foo": "bar"},
			keys:      []string{},
			wantFound: true,
		},
		{
			name: "value at intermediate position is a slice (not a map)",
			obj: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{"a", "b"},
				},
			},
			keys:      []string{"spec", "containers", "name"},
			wantFound: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, found := nestedMap(tc.obj, tc.keys...)
			assert.Equal(t, tc.wantFound, found)
			if tc.wantFound {
				require.NotNil(t, result)
			}
		})
	}
}
