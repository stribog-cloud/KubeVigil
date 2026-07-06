package crd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func schemaWithStatus() map[string]interface{} {
	return map[string]interface{}{
		"openAPIV3Schema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"spec":   map[string]interface{}{"type": "object"},
				"status": map[string]interface{}{"type": "object"},
			},
		},
	}
}

func schemaWithoutStatus() map[string]interface{} {
	return map[string]interface{}{
		"openAPIV3Schema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"spec": map[string]interface{}{"type": "object"},
			},
		},
	}
}

func TestStatusSubresourceMissingChecker_Run(t *testing.T) {
	c := &StatusSubresourceMissingChecker{}
	ctx := context.Background()

	assert.Equal(t, "crd-status-subresource-missing", c.Name())
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

	t.Run("status property present, subresources missing", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "widgets.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("status property present, subresources.status enabled", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "gadgets.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus(), "subresources": map[string]interface{}{"status": map[string]interface{}{}}},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("no status property, no subresources", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "safe.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithoutStatus()},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("subresources.status enabled but no status property", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "noschema.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithoutStatus(), "subresources": map[string]interface{}{"status": map[string]interface{}{}}},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("only scale subresource enabled, status still missing", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "scaleonly.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus(), "subresources": map[string]interface{}{"scale": map[string]interface{}{}}},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("multiple versions, only one flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "multiversion.example.com", []map[string]interface{}{
			{"name": "v1alpha1", "served": true, "storage": false, "schema": schemaWithStatus(), "subresources": map[string]interface{}{"status": map[string]interface{}{}}},
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "v1")
		assert.Contains(t, findings[0].FieldPath, "versions[1]")
	})

	t.Run("multiple versions both flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "bothflagged.example.com", []map[string]interface{}{
			{"name": "v1alpha1", "served": true, "storage": false, "schema": schemaWithStatus()},
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("multiple CRDs produce independent findings", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "a.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil))
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "b.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("malformed version entry does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "malformed.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil)
		crd.Object["spec"].(map[string]interface{})["versions"] = []interface{}{"not-a-map"}
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("Kind is CustomResourceDefinition", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "widgets.example.com", []map[string]interface{}{
			{"name": "v1", "served": true, "storage": true, "schema": schemaWithStatus()},
		}, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "CustomResourceDefinition", findings[0].Kind)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-status-subresource-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-status-subresource-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
