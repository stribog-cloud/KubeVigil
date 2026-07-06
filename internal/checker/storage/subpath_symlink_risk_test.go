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

func TestSubPathSymlinkRiskChecker_Metadata(t *testing.T) {
	c := &SubPathSymlinkRiskChecker{}
	assert.Equal(t, "subpath-symlink-risk", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestSubPathSymlinkRiskChecker_Run(t *testing.T) {
	c := &SubPathSymlinkRiskChecker{}
	ctx := context.Background()

	restartAlways := corev1.ContainerRestartPolicyAlways

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantKind     string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
		},
		{
			name: "pod with no volumeMounts produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				}))
				return cache
			},
		},
		{
			name: "volumeMount without subPath or subPathExpr produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app", Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
					}},
				}))
				return cache
			},
		},
		{
			name: "volumeMount with explicit empty subPath produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app", Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", SubPath: ""}},
					}},
				}))
				return cache
			},
		},
		{
			name: "volumeMount with subPath triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app", Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/app/conf/conf.yaml", SubPath: "conf.yaml"}},
					}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
			wantKind:     "Pod",
		},
		{
			name: "volumeMount with subPathExpr triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app", Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{{Name: "logs", MountPath: "/logs", SubPathExpr: "$(POD_NAME)"}},
					}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "multiple volumeMounts on one container each with subPath",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app", Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"},
							{Name: "conf", MountPath: "/a/other.yaml", SubPath: "other.yaml"},
						},
					}},
				}))
				return cache
			},
			wantFindings: 2,
			wantResource: "app",
		},
		{
			name: "second container without subPath does not add findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.25", VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"}}},
						{Name: "sidecar", Image: "sidecar:1.0", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}},
					},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "init container with subPath triggers finding with initContainers field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name: "init", Image: "busybox:1.36",
						VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"}},
					}},
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "native sidecar (restartPolicy Always init container) with subPath triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name: "proxy", Image: "envoy:1.28", RestartPolicy: &restartAlways,
						VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"}},
					}},
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "multiple pods, only one with subPath",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "clean", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}},
				}))
				cache.Add(podGVR, makePodWithSpec(t, "risky", "default", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25", VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"}}}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "risky",
		},
		{
			name: "no containers at all produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "empty-pod", "default", corev1.PodSpec{}))
				return cache
			},
		},
		{
			name: "subPath in namespace other than default is reported with correct namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "prod", corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25", VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"}}}},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "app",
		},
		{
			name: "three containers each with a distinct subPath mount",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "multi", "default", corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", Image: "img:1", VolumeMounts: []corev1.VolumeMount{{Name: "v1", MountPath: "/a/1", SubPath: "one"}}},
						{Name: "c2", Image: "img:2", VolumeMounts: []corev1.VolumeMount{{Name: "v2", MountPath: "/a/2", SubPath: "two"}}},
						{Name: "c3", Image: "img:3", VolumeMounts: []corev1.VolumeMount{{Name: "v3", MountPath: "/a/3"}}},
					},
				}))
				return cache
			},
			wantFindings: 2,
			wantResource: "multi",
		},
		{
			name: "both subPath and subPathExpr checked independently across mounts",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(podGVR, makePodWithSpec(t, "app", "default", corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app", Image: "nginx:1.25",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "conf", MountPath: "/a/conf.yaml", SubPath: "conf.yaml"},
							{Name: "logs", MountPath: "/logs", SubPathExpr: "$(POD_NAME)"},
						},
					}},
				}))
				return cache
			},
			wantFindings: 2,
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
				assert.Equal(t, "subpath-symlink-risk", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
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

func TestSubPathSymlinkRiskChecker_CancelledContext(t *testing.T) {
	c := &SubPathSymlinkRiskChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestSubPathSymlinkRiskChecker_Fixtures(t *testing.T) {
	c := &SubPathSymlinkRiskChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "subpath-symlink-risk", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "subpath-symlink-risk", findings[0].Checker)
		assert.Equal(t, checker.SeverityLow, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "subpath-symlink-risk", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
