package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// Behavioral regression tests call Run() and assert finding content (audit F9/R5).
func TestClusterCheckers_RunOnEmptyCache(t *testing.T) {
	ctx := context.Background()
	all := []checker.Checker{
		&AdmissionControllersChecker{},
		&APIServerAnonymousChecker{},
		&AuditLoggingChecker{},
		&ComponentVersionsChecker{},
		&DeprecatedAPIUsageChecker{},
		&EtcdEncryptionChecker{},
		&KubeletConfigChecker{},
		&LimitRangeMissingChecker{},
		&NamespaceDefaultUsageChecker{},
		&ResourceQuotaMissingChecker{},
	}
	for _, c := range all {
		c := c
		t.Run(c.Name(), func(t *testing.T) {
			findings, err := c.Run(ctx, checker.NewResourceCache())
			require.NoError(t, err)
			assert.Empty(t, findings)
			if assert.NotEmpty(t, c.Description()) {
				assert.Contains(t, c.Description(), " ")
			}
			assert.NotEmpty(t, c.Categories())
			assert.NotEmpty(t, c.SupportedModes())
			assert.NotEmpty(t, c.RequiredResources())
		})
	}
}

func TestClusterCheckers_BehavioralRegression(t *testing.T) {
	ctx := context.Background()

	t.Run("deprecated-api-usage flags PSP resources", func(t *testing.T) {
		c := &DeprecatedAPIUsageChecker{}
		cache := helpers.LoadFixture(t, "deprecated-api-usage", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		assert.Equal(t, "deprecated-api-usage", findings[0].Checker)
		assert.NotEqual(t, checker.SeverityInfo, findings[0].Severity)
	})

	t.Run("namespace-default-usage flags default namespace workloads", func(t *testing.T) {
		c := &NamespaceDefaultUsageChecker{}
		cache := helpers.LoadFixture(t, "namespace-default-usage", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		assert.Equal(t, "namespace-default-usage", findings[0].Checker)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("limit-range-missing reports missing LimitRange", func(t *testing.T) {
		c := &LimitRangeMissingChecker{}
		cache := checker.NewResourceCache()
		cache.Add(NamespaceGVR, makeNamespace(t, "workloads", nil))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "limit-range-missing", findings[0].Checker)
		assert.Contains(t, findings[0].Message, "LimitRange")
	})
}
