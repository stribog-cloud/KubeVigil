package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestGenericEphemeralVolumeNoLimitsChecker_Metadata(t *testing.T) {
	c := &GenericEphemeralVolumeNoLimitsChecker{}
	assert.Equal(t, "generic-ephemeral-volume-no-limits", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestGenericEphemeralVolumeNoLimitsChecker_Run(t *testing.T) {
	c := &GenericEphemeralVolumeNoLimitsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
		},
		{
			name: "pod with no volumes produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				}))
				return cache
			},
		},
		{
			name: "pod with PVC volume produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name:         "data",
						VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc"}},
					}},
				}))
				return cache
			},
		},
		{
			name: "generic ephemeral volume without storage request triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "scratch",
						VolumeSource: corev1.VolumeSource{
							Ephemeral: &corev1.EphemeralVolumeSource{
								VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
									Spec: corev1.PersistentVolumeClaimSpec{
										AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
									},
								},
							},
						},
					}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "generic ephemeral volume with storage request produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "scratch",
						VolumeSource: corev1.VolumeSource{
							Ephemeral: &corev1.EphemeralVolumeSource{
								VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
									Spec: corev1.PersistentVolumeClaimSpec{
										AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
										Resources: corev1.VolumeResourceRequirements{
											Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("5Gi")},
										},
									},
								},
							},
						},
					}},
				}))
				return cache
			},
		},
		{
			name: "ephemeral volume with nil VolumeClaimTemplate produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}}},
				}))
				return cache
			},
		},
		{
			name: "resources.requests set but missing storage key triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "scratch",
						VolumeSource: corev1.VolumeSource{
							Ephemeral: &corev1.EphemeralVolumeSource{
								VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
									Spec: corev1.PersistentVolumeClaimSpec{
										Resources: corev1.VolumeResourceRequirements{
											Limits: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
										},
									},
								},
							},
						},
					}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "two ephemeral volumes without storage request trigger two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{
						{Name: "scratch1", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}},
						{Name: "scratch2", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}},
					},
				}))
				return cache
			},
			wantFindings: 2,
			wantResource: "app",
		},
		{
			name: "one ephemeral volume with limit, one without triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{
						{Name: "ok", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
							Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}}},
						}}}},
						{Name: "bad", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}},
					},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "multiple pods, only one with unbounded ephemeral volume",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "clean", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				}))
				cache.Add(podGVR, makePodWithSpec(t, "risky", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "risky",
		},
		{
			name: "ephemeral volume in non-default namespace reports correct namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "prod", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "storage request set to zero quantity still counts as present",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "scratch",
						VolumeSource: corev1.VolumeSource{
							Ephemeral: &corev1.EphemeralVolumeSource{
								VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
									Spec: corev1.PersistentVolumeClaimSpec{
										Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("0")}},
									},
								},
							},
						},
					}},
				}))
				return cache
			},
		},
		{
			name: "hostPath volume produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				path := "/data"
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path}}}},
				}))
				return cache
			},
		},
		{
			name: "no volumes field at all produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{}))
				return cache
			},
		},
		{
			name: "requests present but empty map still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "scratch",
						VolumeSource: corev1.VolumeSource{
							Ephemeral: &corev1.EphemeralVolumeSource{
								VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
									Spec: corev1.PersistentVolumeClaimSpec{
										Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{}},
									},
								},
							},
						},
					}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
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
				assert.Equal(t, "generic-ephemeral-volume-no-limits", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestGenericEphemeralVolumeNoLimitsChecker_CancelledContext(t *testing.T) {
	c := &GenericEphemeralVolumeNoLimitsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestGenericEphemeralVolumeNoLimitsChecker_Fixtures(t *testing.T) {
	c := &GenericEphemeralVolumeNoLimitsChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "generic-ephemeral-volume-no-limits", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "generic-ephemeral-volume-no-limits", findings[0].Checker)
		assert.Equal(t, checker.SeverityLow, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "generic-ephemeral-volume-no-limits", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
