package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestServiceAccountTokenSecretLegacyChecker_Metadata(t *testing.T) {
	c := &ServiceAccountTokenSecretLegacyChecker{}

	assert.Equal(t, "serviceaccount-token-secret-legacy", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, SecretGVR, c.RequiredResources()[0])
}

func TestServiceAccountTokenSecretLegacyChecker_Run(t *testing.T) {
	c := &ServiceAccountTokenSecretLegacyChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantMessage  string
	}{
		{
			name: "legacy service-account-token secret triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("legacy-sa-token", "default", serviceAccountTokenSecretType, []string{"token", "ca.crt", "namespace"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "legacy-sa-token",
			wantMessage:  `Secret "legacy-sa-token" is of legacy type "kubernetes.io/service-account-token", a long-lived, non-expiring ServiceAccount token.`,
		},
		{
			name: "opaque secret produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("app-config", "default", "Opaque", []string{"password"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "tls secret produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("tls-secret", "default", "kubernetes.io/tls", []string{"tls.crt", "tls.key"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty type produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("no-type", "default", "", []string{"data"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple secrets with one legacy token",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, makeSecret("legacy-1", "ns1", serviceAccountTokenSecretType, []string{"token"}))
				cache.Add(SecretGVR, makeSecret("clean-1", "ns1", "Opaque", []string{"password"}))
				cache.Add(SecretGVR, makeSecret("legacy-2", "ns2", serviceAccountTokenSecretType, []string{"token"}))
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
				assert.Equal(t, "serviceaccount-token-secret-legacy", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, ".type", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantMessage != "" {
					assert.Equal(t, tt.wantMessage, findings[0].Message)
				}
			}
		})
	}
}

func TestServiceAccountTokenSecretLegacyChecker_CancelledContext(t *testing.T) {
	c := &ServiceAccountTokenSecretLegacyChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(SecretGVR, makeSecret("legacy", "default", serviceAccountTokenSecretType, []string{"token"}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestServiceAccountTokenSecretLegacyChecker_Fixtures(t *testing.T) {
	c := &ServiceAccountTokenSecretLegacyChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "serviceaccount-token-secret-legacy", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "legacy-sa-token")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "serviceaccount-token-secret-legacy", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
