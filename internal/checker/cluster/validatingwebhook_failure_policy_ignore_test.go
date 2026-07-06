package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestValidatingWebhookFailurePolicyIgnoreChecker_Run(t *testing.T) {
	c := &ValidatingWebhookFailurePolicyIgnoreChecker{}
	ctx := context.Background()

	assert.Equal(t, "validatingwebhook-failure-policy-ignore", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), ValidatingWebhookConfigurationGVR)

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

	t.Run("webhook with failurePolicy Ignore", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com", "failurePolicy": "Ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "policy-webhook")
		assert.Contains(t, findings[0].Message, "policy.example.com")
	})

	t.Run("webhook with failurePolicy Fail", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com", "failurePolicy": "Fail"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("webhook with no failurePolicy set", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("multiple webhooks, one Ignore one Fail, one finding per config", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "multi-webhook", []map[string]any{
			{"name": "a.example.com", "failurePolicy": "Fail"},
			{"name": "b.example.com", "failurePolicy": "Ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].FieldPath, "webhooks[1]")
	})

	t.Run("two separate configs each with an offending webhook", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "webhook-a", []map[string]any{
			{"name": "a.example.com", "failurePolicy": "Ignore"},
		}))
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "webhook-b", []map[string]any{
			{"name": "b.example.com", "failurePolicy": "Ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("empty webhooks list", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "empty-webhook", []map[string]any{}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("FixHint populated correctly", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com", "failurePolicy": "Ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.NotNil(t, findings[0].FixHint)
		assert.Equal(t, checker.FixLikelySafe, findings[0].FixHint.Safety)
		assert.Equal(t, checker.FixOpSet, findings[0].FixHint.Operation)
	})

	t.Run("CurrentValue and DesiredValue populated", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com", "failurePolicy": "Ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "Ignore", findings[0].CurrentValue)
		assert.Equal(t, "Fail", findings[0].DesiredValue)
	})

	t.Run("Kind is set from object", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com", "failurePolicy": "Ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "ValidatingWebhookConfiguration", findings[0].Kind)
	})

	t.Run("malformed webhook entry does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		obj := makeValidatingWebhookConfig(t, "bad-webhook", []map[string]any{
			{"name": "a.example.com", "failurePolicy": "Ignore"},
		})
		obj.Object["webhooks"] = []interface{}{"not-a-map"}
		cache.Add(ValidatingWebhookConfigurationGVR, obj)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("failurePolicy value is case-sensitive", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingWebhookConfigurationGVR, makeValidatingWebhookConfig(t, "policy-webhook", []map[string]any{
			{"name": "policy.example.com", "failurePolicy": "ignore"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "validatingwebhook-failure-policy-ignore", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "validatingwebhook-failure-policy-ignore", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
