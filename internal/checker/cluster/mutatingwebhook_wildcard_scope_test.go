package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestMutatingWebhookWildcardScopeChecker_Run(t *testing.T) {
	c := &MutatingWebhookWildcardScopeChecker{}
	ctx := context.Background()

	assert.Equal(t, "mutatingwebhook-wildcard-scope", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), MutatingWebhookConfigurationGVR)

	wildcardRule := map[string]any{
		"apiGroups":   []any{"*"},
		"apiVersions": []any{"*"},
		"resources":   []any{"*"},
	}

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

	t.Run("wildcard rule with no namespaceSelector", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "wide-mutator", []map[string]any{
			{"name": "wide.example.com", "rules": []any{wildcardRule}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
	})

	t.Run("wildcard rule with matchLabels namespaceSelector", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "scoped-mutator", []map[string]any{
			{
				"name":              "scoped.example.com",
				"rules":             []any{wildcardRule},
				"namespaceSelector": map[string]any{"matchLabels": map[string]any{"team": "checkout"}},
			},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("wildcard rule with matchExpressions namespaceSelector", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "scoped-mutator-2", []map[string]any{
			{
				"name":  "scoped2.example.com",
				"rules": []any{wildcardRule},
				"namespaceSelector": map[string]any{"matchExpressions": []any{
					map[string]any{"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": []any{"kube-system"}},
				}},
			},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("wildcard rule with empty namespaceSelector still flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "empty-selector-mutator", []map[string]any{
			{"name": "empty.example.com", "rules": []any{wildcardRule}, "namespaceSelector": map[string]any{}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("scoped resources, not wildcard", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "narrow-mutator", []map[string]any{
			{"name": "narrow.example.com", "rules": []any{
				map[string]any{"apiGroups": []any{"apps"}, "apiVersions": []any{"v1"}, "resources": []any{"deployments"}},
			}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("apiGroups wildcard but resources scoped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "partial-mutator", []map[string]any{
			{"name": "partial.example.com", "rules": []any{
				map[string]any{"apiGroups": []any{"*"}, "apiVersions": []any{"*"}, "resources": []any{"deployments"}},
			}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("multiple rules, one wildcard one scoped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "mixed-mutator", []map[string]any{
			{"name": "mixed.example.com", "rules": []any{
				map[string]any{"apiGroups": []any{"apps"}, "apiVersions": []any{"v1"}, "resources": []any{"deployments"}},
				wildcardRule,
			}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].FieldPath, "rules[1]")
	})

	t.Run("multiple webhooks in one config, only one wildcard", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "multi-webhook-mutator", []map[string]any{
			{"name": "safe.example.com", "rules": []any{
				map[string]any{"apiGroups": []any{"apps"}, "apiVersions": []any{"v1"}, "resources": []any{"deployments"}},
			}},
			{"name": "wide.example.com", "rules": []any{wildcardRule}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].FieldPath, "webhooks[1]")
	})

	t.Run("two separate configs each with a wildcard webhook", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "mutator-a", []map[string]any{
			{"name": "a.example.com", "rules": []any{wildcardRule}},
		}))
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "mutator-b", []map[string]any{
			{"name": "b.example.com", "rules": []any{wildcardRule}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("malformed rule entry does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "bad-mutator", []map[string]any{
			{"name": "bad.example.com", "rules": []any{"not-a-map"}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("no rules at all", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "no-rules-mutator", []map[string]any{
			{"name": "norules.example.com"},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("Kind is set from object", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(MutatingWebhookConfigurationGVR, makeMutatingWebhookConfig(t, "wide-mutator", []map[string]any{
			{"name": "wide.example.com", "rules": []any{wildcardRule}},
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "MutatingWebhookConfiguration", findings[0].Kind)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "mutatingwebhook-wildcard-scope", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "mutatingwebhook-wildcard-scope", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
