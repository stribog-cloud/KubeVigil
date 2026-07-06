package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// immutableSecretObj builds an unstructured Secret with an arbitrary set of
// top-level extra fields (e.g. "immutable") merged in for testing.
func immutableSecretObj(name, namespace string, extra map[string]interface{}) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"type":       "Opaque",
		"data":       map[string]interface{}{"password": "dGVzdA=="},
	}
	for k, v := range extra {
		obj[k] = v
	}
	return unstructured.Unstructured{Object: obj}
}

func TestImmutableMissingChecker_Metadata(t *testing.T) {
	c := &ImmutableMissingChecker{}

	assert.Equal(t, "secrets-immutable-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, SecretGVR, c.RequiredResources()[0])
}

func TestImmutableMissingChecker_Run(t *testing.T) {
	c := &ImmutableMissingChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "immutable true produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, immutableSecretObj("rotated", "default", map[string]interface{}{"immutable": true}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "immutable false triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, immutableSecretObj("explicit-mutable", "default", map[string]interface{}{"immutable": false}))
				return cache
			},
			wantFindings: 1,
			wantResource: "explicit-mutable",
		},
		{
			name: "immutable absent triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, immutableSecretObj("no-immutable-field", "default", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-immutable-field",
		},
		{
			name: "immutable field with non-bool type is treated as mutable",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, immutableSecretObj("bad-type", "default", map[string]interface{}{"immutable": "true"}))
				return cache
			},
			wantFindings: 1,
			wantResource: "bad-type",
		},
		{
			name: "multiple secrets with mixed immutability",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, immutableSecretObj("s1", "ns1", map[string]interface{}{"immutable": true}))
				cache.Add(SecretGVR, immutableSecretObj("s2", "ns2", nil))
				cache.Add(SecretGVR, immutableSecretObj("s3", "ns2", map[string]interface{}{"immutable": false}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)

			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				helpers.AssertAllFindingsHaveRequiredFields(t, findings)
				assert.Equal(t, "secrets-immutable-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Equal(t, ".immutable", findings[0].FieldPath)
				assert.NotNil(t, findings[0].FixHint)
				assert.Equal(t, checker.FixPotentiallyBreaking, findings[0].FixHint.Safety)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestImmutableMissingChecker_CancelledContext(t *testing.T) {
	c := &ImmutableMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(SecretGVR, immutableSecretObj("s1", "default", nil))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestImmutableMissingChecker_Fixtures(t *testing.T) {
	c := &ImmutableMissingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-immutable-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "mutable-config-secret")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-immutable-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
