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

// withWindowsHostProcess sets securityContext.windowsOptions.hostProcess on a container.
func withWindowsHostProcess(v bool) helpers.ContainerOption {
	return func(c *corev1.Container) {
		if c.SecurityContext == nil {
			c.SecurityContext = &corev1.SecurityContext{}
		}
		c.SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: &v}
	}
}

func TestWindowsHostProcessChecker_Metadata(t *testing.T) {
	c := &WindowsHostProcessChecker{}

	assert.Equal(t, "windows-hostprocess", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestWindowsHostProcessChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &WindowsHostProcessChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "container-level hostProcess: true triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("hostprocess-pod"),
					helpers.WithContainer(helpers.NewContainer("app", withWindowsHostProcess(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "hostprocess-pod",
		},
		{
			name: "container-level hostProcess: false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("safe-pod"),
					helpers.WithContainer(helpers.NewContainer("app", withWindowsHostProcess(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no securityContext produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-sc-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "windowsOptions without hostProcess produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("gmsa-pod"),
					helpers.WithContainer(helpers.NewContainer("app", func(c *corev1.Container) {
						c.SecurityContext = &corev1.SecurityContext{
							WindowsOptions: &corev1.WindowsSecurityContextOptions{
								GMSACredentialSpecName: strPtr("my-spec"),
							},
						}
					})),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod-level hostProcess: true triggers finding for container without override",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("pod-level-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				pod.Spec.SecurityContext = &corev1.PodSecurityContext{
					WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "pod-level-pod",
		},
		{
			name: "container-level false overrides pod-level true",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("override-pod"),
					helpers.WithContainer(helpers.NewContainer("app", withWindowsHostProcess(false))),
				)
				pod.Spec.SecurityContext = &corev1.PodSecurityContext{
					WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with hostProcess container triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", withWindowsHostProcess(true))),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "init container with hostProcess triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup", withWindowsHostProcess(true))
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with hostProcess triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("agent", withWindowsHostProcess(true))
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "agent",
		},
		{
			name: "multiple containers — only hostProcess one triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod1 := helpers.GeneratePod(
					helpers.WithName("safe-pod2"),
					helpers.WithContainer(helpers.NewContainer("safe", withWindowsHostProcess(false))),
				)
				pod2 := helpers.GeneratePod(
					helpers.WithName("unsafe-pod2"),
					helpers.WithContainer(helpers.NewContainer("unsafe", withWindowsHostProcess(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod1))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings: 1,
			wantResource: "unsafe-pod2",
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
				return helpers.LoadFixture(t, "windows-hostprocess", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "windows-hostprocess-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "windows-hostprocess", "passing.yaml")
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
				assert.Equal(t, "windows-hostprocess", findings[0].Checker)
				assert.Equal(t, checker.SeverityCritical, findings[0].Severity)

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

func TestWindowsHostProcessChecker_CancelledContext(t *testing.T) {
	c := &WindowsHostProcessChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", withWindowsHostProcess(true))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestWindowsHostProcessChecker_FieldPath(t *testing.T) {
	c := &WindowsHostProcessChecker{}
	ctx := context.Background()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(helpers.NewContainer("app", withWindowsHostProcess(true))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].FieldPath, "securityContext.windowsOptions.hostProcess")
}

func strPtr(s string) *string { return &s }
