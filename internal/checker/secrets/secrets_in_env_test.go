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

func TestInEnvChecker_Metadata(t *testing.T) {
	c := &InEnvChecker{}

	assert.Equal(t, "secrets-in-env", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestInEnvChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &InEnvChecker{}
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
			name: "container with secretKeyRef in env triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("secret-env-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						Env: []corev1.EnvVar{
							{
								Name: "DB_PASSWORD",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
										Key:                  "password",
									},
								},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "secret-env-pod",
			checkMessage:  `container "app" passes secret "db-creds" key "password" via environment variable`,
		},
		{
			name: "container with configMapKeyRef in env produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("configmap-env-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						Env: []corev1.EnvVar{
							{
								Name: "LOG_LEVEL",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
										Key:                  "log_level",
									},
								},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container with plain env value produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("plain-env-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						Env: []corev1.EnvVar{
							{
								Name:  "PORT",
								Value: "8080",
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container with no env produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-env-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple env vars referencing secrets produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-secret-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						Env: []corev1.EnvVar{
							{
								Name: "DB_PASSWORD",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
										Key:                  "password",
									},
								},
							},
							{
								Name: "API_KEY",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "api-secret"},
										Key:                  "key",
									},
								},
							},
							{
								Name:  "PORT",
								Value: "8080",
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 2,
			wantResource: "multi-secret-pod",
		},
		{
			name: "init container with secretKeyRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := corev1.Container{
					Name:  "init-setup",
					Image: "busybox:1.36",
					Env: []corev1.EnvVar{
						{
							Name: "SECRET_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "init-secret"},
									Key:                  "token",
								},
							},
						},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("init-secret-pod"),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with secretKeyRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := corev1.Container{
					Name:  "envoy",
					Image: "envoyproxy/envoy:v1.28",
					Env: []corev1.EnvVar{
						{
							Name: "TLS_KEY",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "tls-secret"},
									Key:                  "tls.key",
								},
							},
						},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-secret-pod"),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "deployment with secretKeyRef triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(corev1.Container{
						Name:  "web",
						Image: "nginx:1.25",
						Env: []corev1.EnvVar{
							{
								Name: "DB_PASS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "db-secret"},
										Key:                  "password",
									},
								},
							},
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
				return helpers.LoadFixture(t, "secrets-in-env", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "secret-env-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "secrets-in-env", "passing.yaml")
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
				assert.Equal(t, "secrets-in-env", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

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

func TestInEnvChecker_CancelledContext(t *testing.T) {
	c := &InEnvChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			Env: []corev1.EnvVar{
				{
					Name: "SECRET",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
							Key:                  "key",
						},
					},
				},
			},
		}),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestInEnvChecker_FieldPath(t *testing.T) {
	c := &InEnvChecker{}
	ctx := context.Background()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()

	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			Env: []corev1.EnvVar{
				{
					Name:  "NORMAL",
					Value: "value",
				},
				{
					Name: "SECRET",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
							Key:                  "key",
						},
					},
				},
			},
		}),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, ".spec.containers[0].env[1].valueFrom.secretKeyRef", findings[0].FieldPath)
}

func TestInEnvChecker_InitContainerFieldPath(t *testing.T) {
	c := &InEnvChecker{}
	ctx := context.Background()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()

	initC := corev1.Container{
		Name:  "init-setup",
		Image: "busybox:1.36",
		Env: []corev1.EnvVar{
			{
				Name: "SECRET",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
						Key:                  "key",
					},
				},
			},
		},
	}
	pod := helpers.GeneratePod(
		helpers.WithName("init-fp-pod"),
		helpers.WithInitContainer(initC),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, ".spec.initContainers[0].env[0].valueFrom.secretKeyRef", findings[0].FieldPath)
}
