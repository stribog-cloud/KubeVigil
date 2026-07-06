package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

var (
	annotationsDeployGVR      = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	annotationsPodGVR         = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	annotationsStatefulSetGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
	annotationsDaemonSetGVR   = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
)

// workloadMetaObj builds a minimal unstructured workload object with the
// given annotations and labels. secrets-in-annotations only inspects
// metadata, so no spec is required.
func workloadMetaObj(kind, apiVersion, name, namespace string, annotations, labels map[string]string) unstructured.Unstructured {
	meta := map[string]interface{}{"name": name, "namespace": namespace}
	if len(annotations) > 0 {
		meta["annotations"] = stringMapToInterfaceMap(annotations)
	}
	if len(labels) > 0 {
		meta["labels"] = stringMapToInterfaceMap(labels)
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   meta,
	}}
}

func stringMapToInterfaceMap(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestInAnnotationsChecker_Metadata(t *testing.T) {
	c := &InAnnotationsChecker{}

	assert.Equal(t, "secrets-in-annotations", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestInAnnotationsChecker_Run(t *testing.T) {
	c := &InAnnotationsChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantResource  string
		wantFieldPath string
		wantMessage   string
	}{
		{
			name: "annotation key name match triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "leaky-app", "default",
					map[string]string{"deploy.example.com/api-key": "any-value-here"}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings:  1,
			wantResource:  "leaky-app",
			wantFieldPath: ".metadata.annotations.deploy.example.com/api-key",
			wantMessage:   `Deployment "leaky-app" has annotation "deploy.example.com/api-key" whose key name suggests it contains a secret`,
		},
		{
			name: "label key name match triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "leaky-label-app", "default",
					nil, map[string]string{"team-password": "hunter2value"})
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings:  1,
			wantResource:  "leaky-label-app",
			wantFieldPath: ".metadata.labels.team-password",
			wantMessage:   `Deployment "leaky-label-app" has label "team-password" whose key name suggests it contains a secret`,
		},
		{
			name: "known secret pattern value triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "aws-key-app", "default",
					map[string]string{"note": "AKIAIOSFODNN7EXAMPLE"}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 1,
			wantResource: "aws-key-app",
			wantMessage:  `Deployment "aws-key-app" has annotation "note" with a value matching a known secret pattern`,
		},
		{
			name: "high entropy value triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "entropy-app", "default",
					map[string]string{"deploy.example.com/build-tag": "aB3$kL9mNp2QrS5tUv8WxYz1fG7hJ0kL"}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 1,
			wantResource: "entropy-app",
			wantMessage:  `Deployment "entropy-app" has annotation "deploy.example.com/build-tag" with a high-entropy value (possible secret)`,
		},
		{
			name: "config file key is excluded from entropy strategy",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "config-key-app", "default",
					map[string]string{"deploy.example.com/app.config.yaml": "aB3$kL9mNp2QrS5tUv8WxYz1fG7hJ0kL"}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kubectl last-applied-configuration annotation is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "lkac-app", "default",
					map[string]string{"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"lkac-app"}}`}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty value is skipped even with a matching key name",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "empty-secret-app", "default",
					map[string]string{"my-secret": ""}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "low entropy plain value produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "clean-app", "default",
					map[string]string{"description": "Handles checkout traffic"}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no annotations or labels produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "bare-app", "default", nil, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "annotation and label each trigger a separate finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := workloadMetaObj("Deployment", "apps/v1", "double-leak-app", "default",
					map[string]string{"deploy.example.com/api-key": "value1"},
					map[string]string{"team-token": "value2"},
				)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 2,
			wantResource: "double-leak-app",
		},
		{
			name: "multiple workload kinds are all scanned",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(annotationsPodGVR, workloadMetaObj("Pod", "v1", "leaky-pod", "default",
					map[string]string{"my-secret-token": "value"}, nil))
				cache.Add(annotationsStatefulSetGVR, workloadMetaObj("StatefulSet", "apps/v1", "leaky-sts", "default",
					map[string]string{"my-secret-token": "value"}, nil))
				cache.Add(annotationsDaemonSetGVR, workloadMetaObj("DaemonSet", "apps/v1", "leaky-ds", "default",
					map[string]string{"my-secret-token": "value"}, nil))
				return cache
			},
			wantFindings: 3,
		},
		{
			name: "custom entropy threshold from policies suppresses a moderate-entropy value",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{Secrets: checker.SecretPolicies{EntropyThreshold: 6.0}})
				obj := workloadMetaObj("Deployment", "apps/v1", "custom-threshold-app", "default",
					map[string]string{"deploy.example.com/build-tag": "aB3$kL9mNp2QrS5tUv8WxYz1"}, nil)
				cache.Add(annotationsDeployGVR, obj)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)

			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				helpers.AssertAllFindingsHaveRequiredFields(t, findings)
				assert.Equal(t, "secrets-in-annotations", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantFieldPath != "" {
					assert.Equal(t, tt.wantFieldPath, findings[0].FieldPath)
				}
				if tt.wantMessage != "" {
					assert.Equal(t, tt.wantMessage, findings[0].Message)
				}
			}
		})
	}
}

func TestInAnnotationsChecker_CancelledContext(t *testing.T) {
	c := &InAnnotationsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	obj := workloadMetaObj("Deployment", "apps/v1", "leaky-app", "default",
		map[string]string{"deploy.example.com/api-key": "value"}, nil)
	cache.Add(annotationsDeployGVR, obj)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestInAnnotationsChecker_Fixtures(t *testing.T) {
	c := &InAnnotationsChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-in-annotations", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "leaky-metadata-app")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-in-annotations", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
