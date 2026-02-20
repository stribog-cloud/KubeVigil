package rbac

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

func TestTokenProjectionConfigChecker_Metadata(t *testing.T) {
	c := &TokenProjectionConfigChecker{}

	assert.Equal(t, "token-projection-config", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestTokenProjectionConfigChecker_Run(t *testing.T) {
	c := &TokenProjectionConfigChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantKind     string
	}{
		{
			name: "pod with automount not disabled and no projected token triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-proj-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-proj-pod",
			wantKind:     "Pod",
		},
		{
			name: "pod with automount=true and no projected token triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("automount-true-pod"),
					helpers.WithAutomountServiceAccountToken(true),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "automount-true-pod",
		},
		{
			name: "pod with automount=false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("automount-false-pod"),
					helpers.WithAutomountServiceAccountToken(false),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod with projected token volume with expirationSeconds produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				projVol := corev1.Volume{
					Name: "sa-token",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										ExpirationSeconds: int64Ptr(3600),
										Audience:          "api",
										Path:              "token",
									},
								},
							},
						},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("projected-token-pod"),
					helpers.WithVolume(projVol),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod with projected token volume without expirationSeconds triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				projVol := corev1.Volume{
					Name: "sa-token",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										Path: "token",
									},
								},
							},
						},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("no-expiry-pod"),
					helpers.WithVolume(projVol),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-expiry-pod",
		},
		{
			name: "pod with non-token projected volume triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				projVol := corev1.Volume{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ConfigMap: &corev1.ConfigMapProjection{
										LocalObjectReference: corev1.LocalObjectReference{Name: "my-config"},
									},
								},
							},
						},
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("config-proj-pod"),
					helpers.WithVolume(projVol),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "config-proj-pod",
		},
		{
			name: "deployment with no projected token triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment()
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
			wantKind:     "Deployment",
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-no-projected-token.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "token-projection-config", "pod-no-projected-token.yaml")
			},
			wantFindings: 1,
			wantResource: "no-projected-token-pod",
		},
		{
			name: "fixture: pod-projected-token.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "token-projection-config", "pod-projected-token.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-automount-disabled.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "token-projection-config", "pod-automount-disabled.yaml")
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
				assert.Equal(t, "token-projection-config", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, ".spec.volumes", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantKind != "" {
					assert.Equal(t, tt.wantKind, findings[0].Kind)
				}
			}
		})
	}
}

func int64Ptr(v int64) *int64 { return &v }

func TestTokenProjectionConfigChecker_CancelledContext(t *testing.T) {
	c := &TokenProjectionConfigChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod()
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTokenProjectionConfigChecker_AllWorkloadTypes(t *testing.T) {
	c := &TokenProjectionConfigChecker{}
	ctx := context.Background()

	workloadTypes := []struct {
		name     string
		gvr      schema.GroupVersionResource
		generate func() interface{}
	}{
		{
			name: "StatefulSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
			generate: func() interface{} {
				return helpers.GenerateStatefulSet()
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet()
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob()
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob()
			},
		},
	}

	for _, wt := range workloadTypes {
		t.Run(wt.name, func(t *testing.T) {
			cache := checker.NewResourceCache()
			cache.Add(wt.gvr, toUnstructured(t, wt.generate()))

			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)
			// Default generator creates pods with nil automount, no projected volumes → should trigger
			assert.Len(t, findings, 1, "expected finding for %s without projected token", wt.name)
			if len(findings) > 0 {
				assert.Equal(t, wt.name, findings[0].Kind)
			}
		})
	}
}
