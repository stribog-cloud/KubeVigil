package scheduling

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
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

func TestExtractPodSpec(t *testing.T) {
	testCases := []struct {
		name      string
		obj       func() *unstructured.Unstructured
		wantOK    bool
		wantNil   bool
		wantCheck func(t *testing.T, spec *corev1.PodSpec)
	}{
		{
			name: "Pod kind extracts spec directly",
			obj: func() *unstructured.Unstructured {
				pod := &corev1.Pod{
					TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
					},
				}
				u := toUnstructured(t, pod)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "app", spec.Containers[0].Name)
			},
		},
		{
			name: "Deployment kind extracts spec.template.spec",
			obj: func() *unstructured.Unstructured {
				replicas := int32(1)
				dep := &appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-dep", Namespace: "default"},
					Spec: appsv1.DeploymentSpec{
						Replicas: &replicas,
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "web", Image: "nginx:1.25"}},
							},
						},
					},
				}
				u := toUnstructured(t, dep)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "web", spec.Containers[0].Name)
			},
		},
		{
			name: "StatefulSet kind extracts spec.template.spec",
			obj: func() *unstructured.Unstructured {
				replicas := int32(1)
				ss := &appsv1.StatefulSet{
					TypeMeta:   metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-ss", Namespace: "default"},
					Spec: appsv1.StatefulSetSpec{
						Replicas: &replicas,
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "db", Image: "postgres:16"}},
							},
						},
					},
				}
				u := toUnstructured(t, ss)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "db", spec.Containers[0].Name)
			},
		},
		{
			name: "DaemonSet kind extracts spec.template.spec",
			obj: func() *unstructured.Unstructured {
				ds := &appsv1.DaemonSet{
					TypeMeta:   metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-ds", Namespace: "kube-system"},
					Spec: appsv1.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "agent", Image: "fluentd"}},
							},
						},
					},
				}
				u := toUnstructured(t, ds)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "agent", spec.Containers[0].Name)
			},
		},
		{
			name: "ReplicaSet kind extracts spec.template.spec",
			obj: func() *unstructured.Unstructured {
				replicas := int32(1)
				rs := &appsv1.ReplicaSet{
					TypeMeta:   metav1.TypeMeta{Kind: "ReplicaSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-rs", Namespace: "default"},
					Spec: appsv1.ReplicaSetSpec{
						Replicas: &replicas,
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "worker", Image: "worker:v1"}},
							},
						},
					},
				}
				u := toUnstructured(t, rs)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "worker", spec.Containers[0].Name)
			},
		},
		{
			name: "Job kind extracts spec.template.spec",
			obj: func() *unstructured.Unstructured {
				job := &batchv1.Job{
					TypeMeta:   metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-job", Namespace: "default"},
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								RestartPolicy: corev1.RestartPolicyNever,
								Containers:    []corev1.Container{{Name: "task", Image: "busybox"}},
							},
						},
					},
				}
				u := toUnstructured(t, job)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "task", spec.Containers[0].Name)
			},
		},
		{
			name: "CronJob kind extracts nested spec",
			obj: func() *unstructured.Unstructured {
				cj := &batchv1.CronJob{
					TypeMeta:   metav1.TypeMeta{Kind: "CronJob", APIVersion: "batch/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-cron", Namespace: "default"},
					Spec: batchv1.CronJobSpec{
						Schedule: "0 * * * *",
						JobTemplate: batchv1.JobTemplateSpec{
							Spec: batchv1.JobSpec{
								Template: corev1.PodTemplateSpec{
									Spec: corev1.PodSpec{
										RestartPolicy: corev1.RestartPolicyNever,
										Containers:    []corev1.Container{{Name: "cron-task", Image: "busybox"}},
									},
								},
							},
						},
					},
				}
				u := toUnstructured(t, cj)
				return &u
			},
			wantOK: true,
			wantCheck: func(t *testing.T, spec *corev1.PodSpec) {
				require.Len(t, spec.Containers, 1)
				assert.Equal(t, "cron-task", spec.Containers[0].Name)
			},
		},
		{
			name: "unknown kind returns nil, false",
			obj: func() *unstructured.Unstructured {
				return &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "v1",
						"kind":       "ConfigMap",
						"metadata": map[string]interface{}{
							"name":      "test-cm",
							"namespace": "default",
						},
						"data": map[string]interface{}{
							"key": "value",
						},
					},
				}
			},
			wantOK:  false,
			wantNil: true,
		},
		{
			name: "known kind but missing nested path returns nil, false",
			obj: func() *unstructured.Unstructured {
				// Deployment without spec.template.spec
				return &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
						"metadata": map[string]interface{}{
							"name":      "broken-dep",
							"namespace": "default",
						},
						"spec": map[string]interface{}{
							"replicas": int64(1),
						},
					},
				}
			},
			wantOK:  false,
			wantNil: true,
		},
		{
			name: "CronJob with missing nested jobTemplate spec returns nil, false",
			obj: func() *unstructured.Unstructured {
				return &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "batch/v1",
						"kind":       "CronJob",
						"metadata": map[string]interface{}{
							"name":      "broken-cron",
							"namespace": "default",
						},
						"spec": map[string]interface{}{
							"schedule": "0 * * * *",
						},
					},
				}
			},
			wantOK:  false,
			wantNil: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj := tc.obj()
			spec, ok := extractPodSpec(obj)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantNil {
				assert.Nil(t, spec)
			}
			if tc.wantCheck != nil {
				require.NotNil(t, spec)
				tc.wantCheck(t, spec)
			}
		})
	}
}

func TestGvrForKind(t *testing.T) {
	testCases := []struct {
		name     string
		kind     string
		expected schema.GroupVersionResource
	}{
		{
			name: "Deployment returns apps/v1/deployments",
			kind: "Deployment",
			expected: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "deployments",
			},
		},
		{
			name: "StatefulSet returns apps/v1/statefulsets",
			kind: "StatefulSet",
			expected: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "statefulsets",
			},
		},
		{
			name: "DaemonSet returns apps/v1/daemonsets",
			kind: "DaemonSet",
			expected: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "daemonsets",
			},
		},
		{
			name: "ReplicaSet returns apps/v1/replicasets",
			kind: "ReplicaSet",
			expected: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "replicasets",
			},
		},
		{
			name:     "unknown kind returns empty GVR",
			kind:     "ConfigMap",
			expected: schema.GroupVersionResource{},
		},
		{
			name:     "empty string returns empty GVR",
			kind:     "",
			expected: schema.GroupVersionResource{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := gvrForKind(tc.kind)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestWorkloadHasRequests(t *testing.T) {
	testCases := []struct {
		name       string
		setup      func() *checker.ResourceCache
		targetKind string
		targetName string
		namespace  string
		expected   bool
	}{
		{
			name: "empty cache returns false",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   false,
		},
		{
			name: "unknown kind returns false",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			targetKind: "ConfigMap",
			targetName: "web",
			namespace:  "default",
			expected:   false,
		},
		{
			name: "workload found with resource requests on all containers returns true",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "default", 1, nil, corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:1.25",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
						},
					}},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   true,
		},
		{
			name: "workload found but no resource requests returns false",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   false,
		},
		{
			name: "workload with CPU request only returns true",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "default", 1, nil, corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:1.25",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("100m"),
							},
						},
					}},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   true,
		},
		{
			name: "workload with memory request only returns true",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "default", 1, nil, corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:1.25",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
						},
					}},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   true,
		},
		{
			name: "workload with requests on some but not all containers returns false",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "default", 1, nil, corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "app",
							Image: "nginx:1.25",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU: resource.MustParse("100m"),
								},
							},
						},
						{
							Name:  "sidecar",
							Image: "envoy:latest",
							// No requests
						},
					},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   false,
		},
		{
			name: "workload not found in cache returns false",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "other", "default", 1, nil, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   false,
		},
		{
			name: "StatefulSet with requests returns true",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				replicas := int32(1)
				ss := &appsv1.StatefulSet{
					TypeMeta:   metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default"},
					Spec: appsv1.StatefulSetSpec{
						Replicas: &replicas,
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "postgres",
									Image: "postgres:16",
									Resources: corev1.ResourceRequirements{
										Requests: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse("250m"),
											corev1.ResourceMemory: resource.MustParse("512Mi"),
										},
									},
								}},
							},
						},
					},
				}
				u := toUnstructured(t, ss)
				ssGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
				cache.Add(ssGVR, u)
				return cache
			},
			targetKind: "StatefulSet",
			targetName: "db",
			namespace:  "default",
			expected:   true,
		},
		{
			name: "workload in different namespace not found returns false",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "staging", 1, nil, corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:1.25",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("100m"),
							},
						},
					}},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			targetKind: "Deployment",
			targetName: "web",
			namespace:  "default",
			expected:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cache := tc.setup()
			got := workloadHasRequests(cache, tc.targetKind, tc.targetName, tc.namespace)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestKindForScalableGVR(t *testing.T) {
	testCases := []struct {
		name     string
		gvr      schema.GroupVersionResource
		expected string
	}{
		{
			name:     "deployments returns Deployment",
			gvr:      schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			expected: "Deployment",
		},
		{
			name:     "statefulsets returns StatefulSet",
			gvr:      schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
			expected: "StatefulSet",
		},
		{
			name:     "unknown resource returns resource name as-is",
			gvr:      schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			expected: "daemonsets",
		},
		{
			name:     "empty resource returns empty string",
			gvr:      schema.GroupVersionResource{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := kindForScalableGVR(tc.gvr)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestMatchesUntrustedValues(t *testing.T) {
	testCases := []struct {
		name     string
		values   []string
		expected bool
	}{
		{
			name:     "empty slice returns false",
			values:   []string{},
			expected: false,
		},
		{
			name:     "nil slice returns false",
			values:   nil,
			expected: false,
		},
		{
			name:     "single non-matching value returns false",
			values:   []string{"dedicated"},
			expected: false,
		},
		{
			name:     "single matching value spot returns true",
			values:   []string{"spot"},
			expected: true,
		},
		{
			name:     "single matching value preemptible returns true",
			values:   []string{"preemptible"},
			expected: true,
		},
		{
			name:     "single matching value ephemeral returns true",
			values:   []string{"ephemeral"},
			expected: true,
		},
		{
			name:     "case-insensitive match returns true",
			values:   []string{"SPOT"},
			expected: true,
		},
		{
			name:     "mixed values with one matching returns true",
			values:   []string{"dedicated", "trusted", "spot-instance"},
			expected: true,
		},
		{
			name:     "all matching values returns true",
			values:   []string{"spot", "preemptible", "ephemeral"},
			expected: true,
		},
		{
			name:     "substring match works",
			values:   []string{"gke-preemptible-node"},
			expected: true,
		},
		{
			name:     "all non-matching values returns false",
			values:   []string{"dedicated", "trusted", "stable"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesUntrustedValues(tc.values)
			assert.Equal(t, tc.expected, got)
		})
	}
}
