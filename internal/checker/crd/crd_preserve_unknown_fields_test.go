package crd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPreserveUnknownFieldsChecker_Run(t *testing.T) {
	c := &PreserveUnknownFieldsChecker{}
	ctx := context.Background()

	assert.Equal(t, "crd-preserve-unknown-fields", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryCRD)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), CustomResourceDefinitionGVR)

	versions := []map[string]interface{}{{"name": "v1", "served": true, "storage": true}}

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

	t.Run("preserveUnknownFields true", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "widgets.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("preserveUnknownFields false", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "gadgets.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": false})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("preserveUnknownFields absent", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRD(t, "safe.example.com", versions, nil)
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("multiple CRDs, only one flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(CustomResourceDefinitionGVR, makeCRD(t, "safe.example.com", versions, nil))
		cache.Add(CustomResourceDefinitionGVR, makeCRDWithSpec(t, "unsafe.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "unsafe.example.com", findings[0].Resource)
	})

	t.Run("two CRDs flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(CustomResourceDefinitionGVR, makeCRDWithSpec(t, "a.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true}))
		cache.Add(CustomResourceDefinitionGVR, makeCRDWithSpec(t, "b.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("FixHint populated correctly", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "widgets.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.NotNil(t, findings[0].FixHint)
		assert.Equal(t, checker.FixPotentiallyBreaking, findings[0].FixHint.Safety)
		assert.Equal(t, checker.FixOpSet, findings[0].FixHint.Operation)
	})

	t.Run("CurrentValue and DesiredValue populated", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "widgets.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, true, findings[0].CurrentValue)
		assert.Equal(t, false, findings[0].DesiredValue)
		assert.Equal(t, ".spec.preserveUnknownFields", findings[0].FieldPath)
	})

	t.Run("Kind is CustomResourceDefinition", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "widgets.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "CustomResourceDefinition", findings[0].Kind)
	})

	t.Run("message contains CRD name", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "widgets.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": true})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "widgets.example.com")
	})

	t.Run("preserveUnknownFields with wrong type does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		crd := makeCRDWithSpec(t, "wrongtype.example.com", versions, nil, map[string]interface{}{"preserveUnknownFields": "true"})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("preserveUnknownFields true with multiple versions", func(t *testing.T) {
		cache := checker.NewResourceCache()
		multiVersions := []map[string]interface{}{
			{"name": "v1", "served": true, "storage": false},
			{"name": "v2", "served": true, "storage": true},
		}
		crd := makeCRDWithSpec(t, "multiversion.example.com", multiVersions, nil, map[string]interface{}{"preserveUnknownFields": true})
		cache.Add(CustomResourceDefinitionGVR, crd)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-preserve-unknown-fields", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "crd-preserve-unknown-fields", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
