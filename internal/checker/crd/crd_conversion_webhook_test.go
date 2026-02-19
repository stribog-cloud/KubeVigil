package crd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestConversionWebhookChecker_Run(t *testing.T) {
	c := &ConversionWebhookChecker{}
	ctx := context.Background()

	assert.Equal(t, "crd-conversion-webhook", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryCRD)

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

	t.Run("CRD with external URL webhook", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "widgets.example.com",
			[]map[string]interface{}{{
				"name": "v1", "served": true, "storage": true,
			}},
			map[string]interface{}{
				"strategy": "Webhook",
				"webhook": map[string]interface{}{
					"clientConfig": map[string]interface{}{
						"url": "https://external.example.com/convert",
					},
				},
			})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "external URL")
	})

	t.Run("CRD with service webhook", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "gadgets.example.com",
			[]map[string]interface{}{{
				"name": "v1", "served": true, "storage": true,
			}},
			map[string]interface{}{
				"strategy": "Webhook",
				"webhook": map[string]interface{}{
					"clientConfig": map[string]interface{}{
						"service": map[string]interface{}{
							"name":      "my-converter",
							"namespace": "default",
						},
					},
				},
			})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "conversion webhook")
	})

	t.Run("CRD without conversion webhook", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "safe.example.com",
			[]map[string]interface{}{{
				"name": "v1", "served": true, "storage": true,
			}}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-conversion-webhook", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-conversion-webhook", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
