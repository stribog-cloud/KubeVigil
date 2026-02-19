package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPodDisruptionBudgetChecker_Metadata(t *testing.T) {
	c := &PodDisruptionBudgetChecker{}

	assert.Equal(t, "pod-disruption-budget", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPodDisruptionBudgetChecker_Run(t *testing.T) {
	c := &PodDisruptionBudgetChecker{}
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
			wantFindings: 0,
		},
		{
			name: "deployment with 1 replica produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, map[string]string{"app": "web"}, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with 3 replicas and matching PDB produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				labels := map[string]string{"app": "web"}
				dep := makeDeployment(t, "web", "default", 3, labels, nil)
				cache.Add(deployGVR, dep)
				pdb := makePDB(t, "web-pdb", "default", labels)
				cache.Add(PodDisruptionBudgetGVR, pdb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with 3 replicas and no PDB triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 3, map[string]string{"app": "web"}, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
		},
		{
			name: "deployment with 3 replicas and non-matching PDB triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 3, map[string]string{"app": "web"}, nil)
				cache.Add(deployGVR, dep)
				pdb := makePDB(t, "other-pdb", "default", map[string]string{"app": "other"})
				cache.Add(PodDisruptionBudgetGVR, pdb)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
		},
		{
			name: "statefulset with 2 replicas and no PDB triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ssGVR := scalableGVRs[1] // statefulsets
				ss := makeStatefulSet(t, "db", "default", 2, map[string]string{"app": "db"})
				cache.Add(ssGVR, ss)
				return cache
			},
			wantFindings: 1,
			wantResource: "db",
		},
		{
			name: "PDB in different namespace does not cover deployment",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				labels := map[string]string{"app": "web"}
				dep := makeDeployment(t, "web", "prod", 3, labels, nil)
				cache.Add(deployGVR, dep)
				pdb := makePDB(t, "web-pdb", "staging", labels)
				cache.Add(PodDisruptionBudgetGVR, pdb)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
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
				assert.Equal(t, "pod-disruption-budget", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestPodDisruptionBudgetChecker_CancelledContext(t *testing.T) {
	c := &PodDisruptionBudgetChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestPodDisruptionBudgetChecker_Fixtures(t *testing.T) {
	c := &PodDisruptionBudgetChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "pod-disruption-budget", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "pod-disruption-budget", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
