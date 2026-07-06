package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestAPIServiceInsecureSkipVerifyChecker_Run(t *testing.T) {
	c := &APIServiceInsecureSkipVerifyChecker{}
	ctx := context.Background()

	assert.Equal(t, "apiservice-insecure-skip-verify", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), APIServiceGVR)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Run(cancelCtx, checker.NewResourceCache())
		assert.Error(t, err)
	})

	t.Run("insecureSkipTLSVerify true", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "v1beta1.metrics.k8s.io", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
	})

	t.Run("insecureSkipTLSVerify false", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "v1beta1.custom.metrics.k8s.io", false, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("insecureSkipTLSVerify absent with caBundle set", func(t *testing.T) {
		cache := checker.NewResourceCache()
		obj := makeAPIService(t, "v1beta1.custom.metrics.k8s.io", false, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t")
		spec := obj.Object["spec"].(map[string]any)
		delete(spec, "insecureSkipTLSVerify")
		cache.Add(APIServiceGVR, obj)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("insecureSkipTLSVerify absent entirely", func(t *testing.T) {
		cache := checker.NewResourceCache()
		obj := makeAPIService(t, "v1beta1.metrics.k8s.io", false, "")
		spec := obj.Object["spec"].(map[string]any)
		delete(spec, "insecureSkipTLSVerify")
		cache.Add(APIServiceGVR, obj)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("multiple APIServices, only one flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "safe.example.com", false, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"))
		cache.Add(APIServiceGVR, makeAPIService(t, "insecure.example.com", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "insecure.example.com", findings[0].Resource)
	})

	t.Run("two APIServices flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "insecure-a.example.com", true, ""))
		cache.Add(APIServiceGVR, makeAPIService(t, "insecure-b.example.com", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("message contains resource name", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "v1beta1.metrics.k8s.io", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "v1beta1.metrics.k8s.io")
	})

	t.Run("CurrentValue and DesiredValue populated", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "v1beta1.metrics.k8s.io", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, true, findings[0].CurrentValue)
		assert.Equal(t, false, findings[0].DesiredValue)
		assert.Equal(t, ".spec.insecureSkipTLSVerify", findings[0].FieldPath)
	})

	t.Run("Kind is APIService", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "v1beta1.metrics.k8s.io", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "APIService", findings[0].Kind)
	})

	t.Run("no FixHint is set", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(APIServiceGVR, makeAPIService(t, "v1beta1.metrics.k8s.io", true, ""))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Nil(t, findings[0].FixHint)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "apiservice-insecure-skip-verify", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "apiservice-insecure-skip-verify", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
