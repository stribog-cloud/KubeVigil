package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestEnvFromBulkChecker_Metadata(t *testing.T) {
	c := &EnvFromBulkChecker{}

	assert.Equal(t, "secrets-envfrom-bulk", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestEnvFromBulkChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &EnvFromBulkChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
		checkMessage  string
	}{
		{
			name: "container with envFrom secretRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("envfrom-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						EnvFrom: []corev1.EnvFromSource{
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db-credentials"}}},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "envfrom-pod",
			checkMessage:  `container "app" bulk-injects every key of secret "db-credentials" as environment variables via envFrom`,
		},
		{
			name: "container with envFrom configMapRef produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("envfrom-cm-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						EnvFrom: []corev1.EnvFromSource{
							{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container with no envFrom produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithContainer(helpers.NewContainer("app")))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container with volume-mounted secret produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("volume-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "creds", MountPath: "/etc/secrets", ReadOnly: true},
						},
					}),
					helpers.WithVolume(corev1.Volume{
						Name: "creds",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: "db-credentials"},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple envFrom sources produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-envfrom-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						EnvFrom: []corev1.EnvFromSource{
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db-credentials"}}},
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "api-credentials"}}},
							{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 2,
			wantResource: "multi-envfrom-pod",
		},
		{
			name: "init container with envFrom secretRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := corev1.Container{
					Name:  "init-setup",
					Image: "busybox:1.36",
					EnvFrom: []corev1.EnvFromSource{
						{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "init-secret"}}},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("init-envfrom-pod"),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with envFrom secretRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := corev1.Container{
					Name:  "envoy",
					Image: "envoyproxy/envoy:v1.28",
					EnvFrom: []corev1.EnvFromSource{
						{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "tls-secret"}}},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-envfrom-pod"),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "deployment with envFrom secretRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(corev1.Container{
						Name:  "web",
						Image: "nginx:1.25",
						EnvFrom: []corev1.EnvFromSource{
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "web-secret"}}},
						},
					}),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
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
				return helpers.LoadFixture(t, "secrets-envfrom-bulk", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "envfrom-bulk-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "secrets-envfrom-bulk", "passing.yaml")
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
				assert.Equal(t, "secrets-envfrom-bulk", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantContainer != "" {
					helpers.AssertFindingForContainer(t, findings, tt.wantContainer)
				}
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMessage != "" {
					assert.Equal(t, tt.checkMessage, findings[0].Message)
				}
			}
		})
	}
}

func TestEnvFromBulkChecker_CancelledContext(t *testing.T) {
	c := &EnvFromBulkChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			EnvFrom: []corev1.EnvFromSource{
				{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"}}},
			},
		}),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestEnvFromBulkChecker_FieldPath(t *testing.T) {
	c := &EnvFromBulkChecker{}
	ctx := context.Background()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()

	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			EnvFrom: []corev1.EnvFromSource{
				{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}},
				{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"}}},
			},
		}),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, ".spec.containers[0].envFrom[1].secretRef", findings[0].FieldPath)
}
