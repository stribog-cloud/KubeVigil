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

func TestAppArmorProfileChecker_Metadata(t *testing.T) {
	c := &AppArmorProfileChecker{}

	assert.Equal(t, "apparmor-profile", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestAppArmorProfileChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	c := &AppArmorProfileChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "no AppArmor profile triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-apparmor"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-apparmor",
		},
		{
			name: "AppArmorProfile RuntimeDefault produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				appArmorType := corev1.AppArmorProfileTypeRuntimeDefault
				container.SecurityContext = &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type: appArmorType,
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("apparmor-runtime"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "AppArmorProfile Localhost produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				appArmorType := corev1.AppArmorProfileTypeLocalhost
				profileName := "my-profile"
				container.SecurityContext = &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type:             appArmorType,
						LocalhostProfile: &profileName,
					},
				}
				pod := helpers.GeneratePod(
					helpers.WithName("apparmor-localhost"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "securityContext without AppArmorProfile triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sc-no-apparmor"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "init container without AppArmor triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				appArmorType := corev1.AppArmorProfileTypeRuntimeDefault
				container.SecurityContext = &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type: appArmorType,
					},
				}
				initC := helpers.NewContainer("init-setup")
				pod := helpers.GeneratePod(
					helpers.WithName("init-no-apparmor"),
					helpers.WithContainer(container),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without AppArmor triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				appArmorType := corev1.AppArmorProfileTypeRuntimeDefault
				container.SecurityContext = &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type: appArmorType,
					},
				}
				sidecar := helpers.NewContainer("envoy")
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-no-apparmor"),
					helpers.WithContainer(container),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
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
				return helpers.LoadFixture(t, "apparmor-profile", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "no-apparmor-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "apparmor-profile", "pod-passing.yaml")
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
				assert.Equal(t, "apparmor-profile", findings[0].Checker)
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

func TestAppArmorProfileChecker_CancelledContext(t *testing.T) {
	c := &AppArmorProfileChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}
