package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestAutomountTokenChecker_Metadata(t *testing.T) {
	c := &AutomountTokenChecker{}

	assert.Equal(t, "automount-token", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestAutomountTokenChecker_Run(t *testing.T) {
	c := &AutomountTokenChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantKind     string
	}{
		{
			name: "pod with no automountServiceAccountToken triggers finding (defaults to true)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-automount-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-automount-pod",
			wantKind:     "Pod",
		},
		{
			name: "pod with automount=true triggers finding",
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
			name: "deployment with no automount triggers finding",
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
			name: "deployment with automount=false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithAutomountServiceAccountToken(false),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple pods mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod1 := helpers.GeneratePod(
					helpers.WithName("automount-default"),
				)
				pod2 := helpers.GeneratePod(
					helpers.WithName("automount-disabled"),
					helpers.WithAutomountServiceAccountToken(false),
				)
				pod3 := helpers.GeneratePod(
					helpers.WithName("automount-enabled"),
					helpers.WithAutomountServiceAccountToken(true),
				)
				cache.Add(podGVR, toUnstructured(t, pod1))
				cache.Add(podGVR, toUnstructured(t, pod2))
				cache.Add(podGVR, toUnstructured(t, pod3))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-automount-true.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "automount-token", "pod-automount-true.yaml")
			},
			wantFindings: 1,
			wantResource: "automount-true-pod",
		},
		{
			name: "fixture: pod-automount-false.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "automount-token", "pod-automount-false.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-automount-default.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "automount-token", "deployment-automount-default.yaml")
			},
			wantFindings: 1,
			wantResource: "automount-default-deploy",
			wantKind:     "Deployment",
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
				assert.Equal(t, "automount-token", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, ".spec.automountServiceAccountToken", findings[0].FieldPath)

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

func TestAutomountTokenChecker_CancelledContext(t *testing.T) {
	c := &AutomountTokenChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod()
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestAutomountTokenChecker_AllWorkloadTypes(t *testing.T) {
	c := &AutomountTokenChecker{}
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
			// Default generator creates pods with nil automount → should trigger
			assert.Len(t, findings, 1, "expected finding for %s with default automount", wt.name)
			if len(findings) > 0 {
				assert.Equal(t, wt.name, findings[0].Kind)
			}
		})
	}
}
