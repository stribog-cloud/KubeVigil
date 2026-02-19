package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// makeSecretWithTimestamp builds an unstructured Secret with a creation timestamp.
func makeSecretWithTimestamp(name, namespace, secretType string, created time.Time, annotations map[string]string) unstructured.Unstructured {
	obj := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"data": map[string]interface{}{
			"key": "dmFsdWU=", // base64("value")
		},
	}}
	if secretType != "" {
		obj.Object["type"] = secretType
	}
	if !created.IsZero() {
		obj.SetCreationTimestamp(metav1.NewTime(created))
	}
	if len(annotations) > 0 {
		obj.SetAnnotations(annotations)
	}
	return obj
}

func TestStaleChecker_Metadata(t *testing.T) {
	c := &StaleChecker{}

	assert.Equal(t, "secrets-stale", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotContains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, SecretGVR, c.RequiredResources()[0])
}

func TestStaleChecker_Run(t *testing.T) {
	c := &StaleChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "secret created 100 days ago triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -100)
				secret := makeSecretWithTimestamp("old-secret", "default", "Opaque", created, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "old-secret",
		},
		{
			name: "secret created 30 days ago produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -30)
				secret := makeSecretWithTimestamp("recent-secret", "default", "Opaque", created, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "secret with recent kubevigil rotation annotation produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -200)
				rotated := time.Now().AddDate(0, 0, -10).Format(time.RFC3339)
				secret := makeSecretWithTimestamp("rotated-secret", "default", "Opaque", created, map[string]string{
					"kubevigil.io/last-rotated": rotated,
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "secret with old kubevigil rotation annotation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -200)
				rotated := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
				secret := makeSecretWithTimestamp("old-rotated", "default", "Opaque", created, map[string]string{
					"kubevigil.io/last-rotated": rotated,
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "old-rotated",
		},
		{
			name: "secret with recent secret-rotated-at annotation produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -200)
				rotated := time.Now().AddDate(0, 0, -5).Format(time.RFC3339)
				secret := makeSecretWithTimestamp("alt-rotated", "default", "Opaque", created, map[string]string{
					"secret-rotated-at": rotated,
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "secret in kube-system namespace is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -200)
				secret := makeSecretWithTimestamp("system-secret", "kube-system", "Opaque", created, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "service-account-token type is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				created := time.Now().AddDate(0, 0, -200)
				secret := makeSecretWithTimestamp("sa-token", "default", "kubernetes.io/service-account-token", created, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "custom max age via policies respects threshold",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Secrets: checker.SecretPolicies{MaxAgeDays: 30},
				})
				created := time.Now().AddDate(0, 0, -45)
				secret := makeSecretWithTimestamp("custom-age", "default", "Opaque", created, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "custom-age",
		},
		{
			name: "custom max age no violation when within threshold",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Secrets: checker.SecretPolicies{MaxAgeDays: 30},
				})
				created := time.Now().AddDate(0, 0, -25)
				secret := makeSecretWithTimestamp("within-threshold", "default", "Opaque", created, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "zero creation timestamp is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithTimestamp("zero-ts", "default", "Opaque", time.Time{}, nil)
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "multiple secrets with mixed ages",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				// Old secret - should trigger.
				cache.Add(SecretGVR, makeSecretWithTimestamp("old", "prod", "Opaque", time.Now().AddDate(0, 0, -120), nil))
				// Recent secret - should not trigger.
				cache.Add(SecretGVR, makeSecretWithTimestamp("new", "prod", "Opaque", time.Now().AddDate(0, 0, -10), nil))
				// Old but in kube-system - skip.
				cache.Add(SecretGVR, makeSecretWithTimestamp("sys", "kube-system", "Opaque", time.Now().AddDate(0, 0, -200), nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "old",
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
				assert.Equal(t, "secrets-stale", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, ".metadata.creationTimestamp", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestStaleChecker_CancelledContext(t *testing.T) {
	c := &StaleChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	created := time.Now().AddDate(0, 0, -100)
	cache.Add(SecretGVR, makeSecretWithTimestamp("test", "default", "Opaque", created, nil))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestStaleChecker_Fixtures(t *testing.T) {
	c := &StaleChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-stale", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "stale-database-creds")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-stale", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
