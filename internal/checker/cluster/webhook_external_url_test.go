package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestWebhookExternalURLChecker_Run(t *testing.T) {
	c := &WebhookExternalURLChecker{}
	ctx := context.Background()

	assert.Equal(t, "webhook-external-url", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), ValidatingWebhookConfigurationGVR)
	assert.Contains(t, c.RequiredResources(), MutatingWebhookConfigurationGVR)

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

	t.Run("ValidatingWebhookConfiguration with external URL", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "external-validator", []map[string]any{
			{"name": "v.example.com", "clientConfig": map[string]any{"url": "https://webhook.external-vendor.com/validate"}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
		assert.Equal(t, "ValidatingWebhookConfiguration", findings[0].Kind)
	})

	t.Run("ValidatingWebhookConfiguration with service reference", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "internal-validator", []map[string]any{
			{"name": "v.example.com", "clientConfig": map[string]any{"service": map[string]any{"name": "v-svc", "namespace": "ns", "path": "/validate"}}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("MutatingWebhookConfiguration with external URL", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "external-mutator", []map[string]any{
			{"name": "m.example.com", "clientConfig": map[string]any{"url": "https://webhook.external-vendor.com/mutate"}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "MutatingWebhookConfiguration", findings[0].Kind)
	})

	t.Run("MutatingWebhookConfiguration with service reference", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "internal-mutator", []map[string]any{
			{"name": "m.example.com", "clientConfig": map[string]any{"service": map[string]any{"name": "m-svc", "namespace": "ns", "path": "/mutate"}}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("clientConfig missing entirely", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "no-clientconfig", []map[string]any{
			{"name": "v.example.com"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("clientConfig url empty string", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "empty-url", []map[string]any{
			{"name": "v.example.com", "clientConfig": map[string]any{"url": ""}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("multiple webhooks in one config, only one external", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "multi-validator", []map[string]any{
			{"name": "internal.example.com", "clientConfig": map[string]any{"service": map[string]any{"name": "svc", "namespace": "ns"}}},
			{"name": "external.example.com", "clientConfig": map[string]any{"url": "https://external.example.com/validate"}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].FieldPath, "webhooks[1]")
	})

	t.Run("both GVRs contribute findings", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "external-validator", []map[string]any{
			{"name": "v.example.com", "clientConfig": map[string]any{"url": "https://external.example.com/validate"}},
		}))
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "external-mutator", []map[string]any{
			{"name": "m.example.com", "clientConfig": map[string]any{"url": "https://external.example.com/mutate"}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("malformed webhook entry does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		obj := makeValidatingWebhookConfig(t, "bad-validator", []map[string]any{
			{"name": "v.example.com", "clientConfig": map[string]any{"url": "https://external.example.com/validate"}},
		})
		obj.Object["webhooks"] = []interface{}{"not-a-map"}
		cache.Add(ValidatingWebhookConfigurationGVR, obj)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("CurrentValue reflects the URL", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "external-validator", []map[string]any{
			{"name": "v.example.com", "clientConfig": map[string]any{"url": "https://webhook.external-vendor.com/validate"}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "https://webhook.external-vendor.com/validate", findings[0].CurrentValue)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "webhook-external-url", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "webhook-external-url", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
