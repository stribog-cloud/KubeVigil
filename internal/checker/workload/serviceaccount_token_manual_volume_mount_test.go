package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// buildSecret returns an unstructured Secret with the given name, namespace, and type.
func buildSecret(name, namespace, secretType string) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
	}
	if secretType != "" {
		obj["type"] = secretType
	}
	return unstructured.Unstructured{Object: obj}
}

func withSecretVolume(volumeName, secretName string) helpers.PodOption {
	return helpers.WithVolume(corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: secretName},
		},
	})
}

func TestServiceAccountTokenManualVolumeMountChecker_Metadata(t *testing.T) {
	c := &ServiceAccountTokenManualVolumeMountChecker{}

	assert.Equal(t, "serviceaccount-token-manual-volume-mount", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), secretGVR)
}

func TestServiceAccountTokenManualVolumeMountChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &ServiceAccountTokenManualVolumeMountChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "pod mounting legacy SA-token secret triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("legacy-token-pod"),
					withSecretVolume("legacy-token", "legacy-sa-token"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(secretGVR, buildSecret("legacy-sa-token", "default", "kubernetes.io/service-account-token"))
				return cache
			},
			wantFindings: 1,
			wantResource: "legacy-token-pod",
		},
		{
			name: "pod mounting Opaque secret produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("opaque-pod"),
					withSecretVolume("app-config", "app-config-secret"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(secretGVR, buildSecret("app-config-secret", "default", "Opaque"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod with no volumes produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-volumes-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod referencing a secret absent from the cache produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("dangling-ref-pod"),
					withSecretVolume("missing", "does-not-exist"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "non-secret volume produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("emptydir-pod"),
					helpers.WithVolume(corev1.Volume{
						Name:         "scratch",
						VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "secret in a different namespace with the same name does not match",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("cross-ns-pod"),
					helpers.WithNamespace("team-a"),
					withSecretVolume("token", "shared-name"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				// Same secret name but a different namespace — must not match.
				cache.Add(secretGVR, buildSecret("shared-name", "team-b", "kubernetes.io/service-account-token"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "secret in the same namespace with matching name and type matches",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("same-ns-pod"),
					helpers.WithNamespace("team-a"),
					withSecretVolume("token", "shared-name"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(secretGVR, buildSecret("shared-name", "team-a", "kubernetes.io/service-account-token"))
				return cache
			},
			wantFindings: 1,
			wantResource: "same-ns-pod",
		},
		{
			name: "deployment mounting legacy SA-token secret triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(withSecretVolume("legacy-token", "legacy-sa-token"))
				cache.Add(deployGVR, toUnstructured(t, dep))
				cache.Add(secretGVR, buildSecret("legacy-sa-token", "default", "kubernetes.io/service-account-token"))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "multiple volumes — only the SA-token one triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-volume-pod"),
					withSecretVolume("config", "app-config-secret"),
					withSecretVolume("legacy-token", "legacy-sa-token"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(secretGVR, buildSecret("app-config-secret", "default", "Opaque"))
				cache.Add(secretGVR, buildSecret("legacy-sa-token", "default", "kubernetes.io/service-account-token"))
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-volume-pod",
		},
		{
			name: "secret with empty type produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-type-pod"),
					withSecretVolume("data", "some-secret"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(secretGVR, buildSecret("some-secret", "default", ""))
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
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "serviceaccount-token-manual-volume-mount", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "legacy-sa-token-mount-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "serviceaccount-token-manual-volume-mount", "passing.yaml")
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
				assert.Equal(t, "serviceaccount-token-manual-volume-mount", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestServiceAccountTokenManualVolumeMountChecker_CancelledContext(t *testing.T) {
	c := &ServiceAccountTokenManualVolumeMountChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestServiceAccountTokenManualVolumeMountChecker_FieldPath(t *testing.T) {
	c := &ServiceAccountTokenManualVolumeMountChecker{}
	ctx := context.Background()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		withSecretVolume("legacy-token", "legacy-sa-token"),
	)
	cache.Add(podGVR, toUnstructured(t, pod))
	cache.Add(secretGVR, buildSecret("legacy-sa-token", "default", "kubernetes.io/service-account-token"))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".spec.volumes[0].secret", findings[0].FieldPath)
}
