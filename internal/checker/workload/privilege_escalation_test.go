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

func TestPrivilegeEscalationChecker_Metadata(t *testing.T) {
	c := &PrivilegeEscalationChecker{}

	assert.Equal(t, "privilege-escalation", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPrivilegeEscalationChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &PrivilegeEscalationChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "allowPrivilegeEscalation true triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("esc-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithAllowPrivilegeEscalation(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "esc-pod",
		},
		{
			name: "allowPrivilegeEscalation false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("secure-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithAllowPrivilegeEscalation(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "nil securityContext triggers finding (defaults to true)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("nil-sc-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "securityContext without allowPrivilegeEscalation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-ape-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "deployment with escalation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "init container without allowPrivilegeEscalation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup")
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithAllowPrivilegeEscalation(false))),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without allowPrivilegeEscalation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy")
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithAllowPrivilegeEscalation(false))),
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
				return helpers.LoadFixture(t, "privilege-escalation", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "escalation-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privilege-escalation", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding (no securityContext)",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privilege-escalation", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "escalation-deploy",
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
				assert.Equal(t, "privilege-escalation", findings[0].Checker)
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

func TestPrivilegeEscalationChecker_CancelledContext(t *testing.T) {
	c := &PrivilegeEscalationChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}
