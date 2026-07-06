package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func boolPtrCSI(v bool) *bool { return &v }

func TestCSIInlineEphemeralVolumeChecker_Metadata(t *testing.T) {
	c := &CSIInlineEphemeralVolumeChecker{}
	assert.Equal(t, "csi-inline-ephemeral-volume", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestCSIInlineEphemeralVolumeChecker_Run(t *testing.T) {
	c := &CSIInlineEphemeralVolumeChecker{}
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
						Name: "data",
						VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "reviewed-pvc"},
						},
					}},
				}))
				return cache
			},
		},
		{
			name: "pod with emptyDir volume produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
				}))
				return cache
			},
		},
		{
			name: "pod with inline CSI volume triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "secrets",
						VolumeSource: corev1.VolumeSource{
							CSI: &corev1.CSIVolumeSource{Driver: "secrets-store.csi.k8s.io", ReadOnly: boolPtrCSI(true)},
						},
					}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "pod with CSI volume but empty driver produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: ""}}}},
				}))
				return cache
			},
		},
		{
			name: "pod with two inline CSI volumes triggers two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{
						{Name: "v1", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "driver.one.io"}}},
						{Name: "v2", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "driver.two.io"}}},
					},
				}))
				return cache
			},
			wantFindings: 2,
			wantResource: "app",
		},
		{
			name: "pod mixing CSI volume with PVC volume triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{
						{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc"}}},
						{Name: "secrets", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "secrets-store.csi.k8s.io"}}},
					},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "multiple pods, only one with inline CSI volume",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "clean", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				}))
				cache.Add(podGVR, makePodWithSpec(t, "risky", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "driver.io"}}}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "risky",
		},
		{
			name: "CSI volume in non-default namespace is reported with correct namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "prod", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes:    []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "driver.io"}}}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "CSI volume with volumeAttributes still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "secrets",
						VolumeSource: corev1.VolumeSource{
							CSI: &corev1.CSIVolumeSource{
								Driver:           "secrets-store.csi.k8s.io",
								VolumeAttributes: map[string]string{"secretProviderClass": "app-secrets"},
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
			name: "hostPath volume produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				path := "/var/log"
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
			name: "CSI volume with fsType and nodePublishSecretRef still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				fsType := "ext4"
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{{
						Name: "vol",
						VolumeSource: corev1.VolumeSource{
							CSI: &corev1.CSIVolumeSource{
								Driver:               "example.csi.io",
								FSType:               &fsType,
								NodePublishSecretRef: &corev1.LocalObjectReference{Name: "csi-secret"},
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
			name: "three CSI volumes across pod triggers three findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Volumes: []corev1.Volume{
						{Name: "v1", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "one.io"}}},
						{Name: "v2", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "two.io"}}},
						{Name: "v3", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "three.io"}}},
					},
				}))
				return cache
			},
			wantFindings: 3,
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
				assert.Equal(t, "csi-inline-ephemeral-volume", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestCSIInlineEphemeralVolumeChecker_CancelledContext(t *testing.T) {
	c := &CSIInlineEphemeralVolumeChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestCSIInlineEphemeralVolumeChecker_Fixtures(t *testing.T) {
	c := &CSIInlineEphemeralVolumeChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "csi-inline-ephemeral-volume", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "csi-inline-ephemeral-volume", findings[0].Checker)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "csi-inline-ephemeral-volume", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
