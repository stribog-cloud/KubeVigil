package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func int64Ptr(v int64) *int64 { return &v }

func TestTerminationGracePeriodZeroChecker_Metadata(t *testing.T) {
	c := &TerminationGracePeriodZeroChecker{}

	assert.Equal(t, "termination-grace-period-zero", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestTerminationGracePeriodZeroChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &TerminationGracePeriodZeroChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "terminationGracePeriodSeconds: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("zero-grace-pod"))
				pod.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "zero-grace-pod",
		},
		{
			name: "terminationGracePeriodSeconds unset produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("default-grace-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "terminationGracePeriodSeconds: 30 produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("thirty-grace-pod"))
				pod.Spec.TerminationGracePeriodSeconds = int64Ptr(30)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "terminationGracePeriodSeconds: 1 produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("one-grace-pod"))
				pod.Spec.TerminationGracePeriodSeconds = int64Ptr(1)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with zero grace period triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment()
				dep.Spec.Template.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "deployment without override produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment()
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple pods — only zero grace period one triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				safe := helpers.GeneratePod(helpers.WithName("safe-pod"))
				safe.Spec.TerminationGracePeriodSeconds = int64Ptr(30)
				unsafe := helpers.GeneratePod(helpers.WithName("unsafe-pod"))
				unsafe.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				cache.Add(podGVR, toUnstructured(t, safe))
				cache.Add(podGVR, toUnstructured(t, unsafe))
				return cache
			},
			wantFindings: 1,
			wantResource: "unsafe-pod",
		},
		{
			name: "namespace is propagated to finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("ns-pod"), helpers.WithNamespace("prod"))
				pod.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "ns-pod",
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
				return helpers.LoadFixture(t, "termination-grace-period-zero", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "zero-grace-period-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "termination-grace-period-zero", "passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "two zero-grace-period pods produce two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod1 := helpers.GeneratePod(helpers.WithName("pod-a"))
				pod1.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				pod2 := helpers.GeneratePod(helpers.WithName("pod-b"))
				pod2.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				cache.Add(podGVR, toUnstructured(t, pod1))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings: 2,
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
				assert.Equal(t, "termination-grace-period-zero", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Empty(t, findings[0].Container, "termination-grace-period-zero is a pod-level check")
				assert.Equal(t, ".spec.terminationGracePeriodSeconds", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestTerminationGracePeriodZeroChecker_CancelledContext(t *testing.T) {
	c := &TerminationGracePeriodZeroChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTerminationGracePeriodZeroChecker_AllWorkloadTypes(t *testing.T) {
	c := &TerminationGracePeriodZeroChecker{}
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
				sts := helpers.GenerateStatefulSet()
				sts.Spec.Template.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				return sts
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				ds := helpers.GenerateDaemonSet()
				ds.Spec.Template.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				return ds
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				job := helpers.GenerateJob()
				job.Spec.Template.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				return job
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				cj := helpers.GenerateCronJob()
				cj.Spec.JobTemplate.Spec.Template.Spec.TerminationGracePeriodSeconds = int64Ptr(0)
				return cj
			},
		},
	}

	for _, wt := range workloadTypes {
		t.Run(wt.name, func(t *testing.T) {
			cache := checker.NewResourceCache()
			cache.Add(wt.gvr, toUnstructured(t, wt.generate()))

			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)
			assert.Len(t, findings, 1, "expected finding for %s", wt.name)
			if len(findings) > 0 {
				assert.Equal(t, wt.name, findings[0].Kind)
			}
		})
	}
}
