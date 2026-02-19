package workload

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

func TestSELinuxOptionsChecker_Metadata(t *testing.T) {
	c := &SELinuxOptionsChecker{}

	assert.Equal(t, "selinux-options", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestSELinuxOptionsChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	c := &SELinuxOptionsChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "unconfined_t triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				container.SecurityContext = &corev1.SecurityContext{
					SELinuxOptions: &corev1.SELinuxOptions{
						Type: "unconfined_t",
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("unconfined-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "unconfined-pod",
		},
		{
			name: "spc_t triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				container.SecurityContext = &corev1.SecurityContext{
					SELinuxOptions: &corev1.SELinuxOptions{
						Type: "spc_t",
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("spc-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "spc-pod",
		},
		{
			name: "no SELinux options produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-selinux"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "safe SELinux type produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				container.SecurityContext = &corev1.SecurityContext{
					SELinuxOptions: &corev1.SELinuxOptions{
						Type: "container_t",
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("safe-selinux"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "SELinux options with empty type produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				container.SecurityContext = &corev1.SecurityContext{
					SELinuxOptions: &corev1.SELinuxOptions{
						Level: "s0:c123,c456",
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("level-only"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "init container with dangerous SELinux triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup")
				initC.SecurityContext = &corev1.SecurityContext{
					SELinuxOptions: &corev1.SELinuxOptions{
						Type: "spc_t",
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("init-selinux"),
					helpers.WithContainer(helpers.NewContainer("app")),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "selinux-options", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "selinux-unconfined-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "selinux-options", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-safe-type.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "selinux-options", "pod-safe-type.yaml")
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
				assert.Equal(t, "selinux-options", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

				if tt.wantContainer != "" {
					helpers.AssertFindingForContainer(t, findings, tt.wantContainer)
				}
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestSELinuxOptionsChecker_CancelledContext(t *testing.T) {
	c := &SELinuxOptionsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}
