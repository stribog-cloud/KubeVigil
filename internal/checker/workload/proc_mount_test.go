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

func TestProcMountChecker_Metadata(t *testing.T) {
	c := &ProcMountChecker{}

	assert.Equal(t, "proc-mount", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestProcMountChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	c := &ProcMountChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "Unmasked procMount triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				unmasked := corev1.UnmaskedProcMount
				container.SecurityContext = &corev1.SecurityContext{
					ProcMount: &unmasked,
				}
				pod := helpers.GeneratePod(
					helpers.WithName("unmasked-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "unmasked-pod",
		},
		{
			name: "Default procMount produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app")
				defaultMount := corev1.DefaultProcMount
				container.SecurityContext = &corev1.SecurityContext{
					ProcMount: &defaultMount,
				}
				pod := helpers.GeneratePod(
					helpers.WithName("default-proc"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "nil procMount produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("nil-proc"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(false))),
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
				pod := helpers.GeneratePod(
					helpers.WithName("no-sc"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "init container with Unmasked procMount triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup")
				unmasked := corev1.UnmaskedProcMount
				initC.SecurityContext = &corev1.SecurityContext{
					ProcMount: &unmasked,
				}
				pod := helpers.GeneratePod(
					helpers.WithName("init-unmasked"),
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
				return helpers.LoadFixture(t, "proc-mount", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "unmasked-proc-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "proc-mount", "pod-passing.yaml")
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
				assert.Equal(t, "proc-mount", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

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

func TestProcMountChecker_CancelledContext(t *testing.T) {
	c := &ProcMountChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}
