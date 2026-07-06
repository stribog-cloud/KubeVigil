package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestValidatingAdmissionPolicyAuditOnlyChecker_Run(t *testing.T) {
	c := &ValidatingAdmissionPolicyAuditOnlyChecker{}
	ctx := context.Background()

	assert.Equal(t, "validatingadmissionpolicy-audit-only", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), ValidatingAdmissionPolicyBindingGVR)
	assert.Contains(t, c.RequiredResources(), ValidatingAdmissionPolicyGVR)

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

	t.Run("validationActions with Deny passes", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "replica-limit-binding", "replica-limit-policy", []string{"Deny"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("validationActions Warn and Audit only", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "replica-limit-binding", "replica-limit-policy", []string{"Warn", "Audit"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("validationActions Audit only", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "audit-binding", "audit-policy", []string{"Audit"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("validationActions Warn only", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "warn-binding", "warn-policy", []string{"Warn"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("validationActions Deny and Audit passes", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "mixed-binding", "mixed-policy", []string{"Deny", "Audit"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("empty validationActions flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "empty-binding", "empty-policy", []string{}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("message references known policy", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyGVR, makeValidatingAdmissionPolicy(t, "replica-limit-policy"))
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "replica-limit-binding", "replica-limit-policy", []string{"Warn"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "replica-limit-policy")
		assert.NotContains(t, findings[0].Message, "not found")
	})

	t.Run("message notes unresolved policy", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "dangling-binding", "missing-policy", []string{"Warn"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "missing-policy")
		assert.Contains(t, findings[0].Message, "not found among scanned resources")
	})

	t.Run("binding with no policyName does not panic", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "no-policy-binding", "", []string{"Warn"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})

	t.Run("multiple bindings produce multiple findings", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "binding-a", "policy-a", []string{"Warn"}))
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "binding-b", "policy-b", []string{"Audit"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("CurrentValue and DesiredValue populated", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "replica-limit-binding", "replica-limit-policy", []string{"Warn", "Audit"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, []string{"Warn", "Audit"}, findings[0].CurrentValue)
		assert.Equal(t, []string{"Deny"}, findings[0].DesiredValue)
	})

	t.Run("Kind is set from object", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(ValidatingAdmissionPolicyBindingGVR, makeValidatingAdmissionPolicyBinding(t, "replica-limit-binding", "replica-limit-policy", []string{"Warn"}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "ValidatingAdmissionPolicyBinding", findings[0].Kind)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "validatingadmissionpolicy-audit-only", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "validatingadmissionpolicy-audit-only", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
