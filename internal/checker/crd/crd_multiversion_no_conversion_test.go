package crd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestMultiversionNoConversionChecker_Run(t *testing.T) {
	c := &MultiversionNoConversionChecker{}
	ctx := context.Background()

	assert.Equal(t, "crd-multiversion-no-conversion", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryCRD)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), CustomResourceDefinitionGVR)

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

	t.Run("single served version, no conversion field", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "single.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("2 served versions, no conversion field", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "multiversion.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("2 served versions, strategy None explicit", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "explicitnone.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, map[string]interface{}{"strategy": "None"})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("2 served versions, strategy Webhook", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "webhookconv.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, map[string]interface{}{
			"strategy": "Webhook",
			"webhook": map[string]interface{}{
				"clientConfig": map[string]interface{}{
					"service": map[string]interface{}{"name": "converter", "namespace": "default"},
				},
			},
		})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("2 versions but only 1 served", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "onlyoneserved.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": false, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("3 served versions, no conversion", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "three.example.com", []map[string]interface{}{
			{"name": "v1alpha1", "served": true, "storage": false},
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("multiple CRDs, only one flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "safe.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true},
		}, nil))
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "unsafe.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "unsafe.example.com", findings[0].Resource)
	})

	t.Run("two CRDs flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "a.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil))
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "b.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("malformed version entry does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "malformed.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		crd.Object["spec"].(map[string]interface{})["versions"] = []interface{}{"not-a-map", "also-not-a-map"}
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("message notes None strategy when absent", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "multiversion.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, `strategy: "None"`)
	})

	t.Run("Kind is CustomResourceDefinition", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "multiversion.example.com", []map[string]interface{}{
			{"name": "v1beta1", "served": true, "storage": false},
			{"name": "v1", "served": true, "storage": true},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "CustomResourceDefinition", findings[0].Kind)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-multiversion-no-conversion", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-multiversion-no-conversion", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
