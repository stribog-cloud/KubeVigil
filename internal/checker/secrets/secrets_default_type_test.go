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

// makeSecret builds an unstructured Secret for testing.
func makeSecret(name, namespace, secretType string, dataKeys []string) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
	}
	if secretType != "" {
		obj["type"] = secretType
	}
	if len(dataKeys) > 0 {
		data := make(map[string]interface{}, len(dataKeys))
		for _, k := range dataKeys {
			data[k] = "dGVzdA==" // base64("test")
		}
		obj["data"] = data
	}
	return unstructured.Unstructured{Object: obj}
}

func TestDefaultTypeChecker_Metadata(t *testing.T) {
	c := &DefaultTypeChecker{}

	assert.Equal(t, "secrets-default-type", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, SecretGVR, c.RequiredResources()[0])
}

func TestDefaultTypeChecker_Run(t *testing.T) {
	c := &DefaultTypeChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantResource  string
		wantMessage   string
		wantFieldPath string
	}{
		{
			name: "Opaque secret with tls.crt and tls.key triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("my-tls", "default", "Opaque", []string{"tls.crt", "tls.key"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings:  1,
			wantResource:  "my-tls",
			wantMessage:   `Secret "my-tls" uses Opaque type but data keys suggest it should be "kubernetes.io/tls".`,
			wantFieldPath: ".type",
		},
		{
			name: "Opaque secret with .dockerconfigjson triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("docker-reg", "default", "Opaque", []string{".dockerconfigjson"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "docker-reg",
			wantMessage:  `Secret "docker-reg" uses Opaque type but data keys suggest it should be "kubernetes.io/dockerconfigjson".`,
		},
		{
			name: "Opaque secret with username and password triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("basic-auth-secret", "default", "Opaque", []string{"username", "password"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "basic-auth-secret",
			wantMessage:  `Secret "basic-auth-secret" uses Opaque type but data keys suggest it should be "kubernetes.io/basic-auth".`,
		},
		{
			name: "Opaque secret with ssh-privatekey triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("ssh-key", "default", "Opaque", []string{"ssh-privatekey"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "ssh-key",
			wantMessage:  `Secret "ssh-key" uses Opaque type but data keys suggest it should be "kubernetes.io/ssh-auth".`,
		},
		{
			name: "Opaque secret with random keys produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("app-config", "default", "Opaque", []string{"config.yaml", "settings.json"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "TLS typed secret with tls keys produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("correct-tls", "default", "kubernetes.io/tls", []string{"tls.crt", "tls.key"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty type with tls keys triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				// Empty type defaults to Opaque.
				secret := makeSecret("empty-type-tls", "default", "", []string{"tls.crt", "tls.key"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "empty-type-tls",
			wantMessage:  `Secret "empty-type-tls" uses Opaque type but data keys suggest it should be "kubernetes.io/tls".`,
		},
		{
			name: "secret with no data produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("no-data", "default", "Opaque", nil)
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
			name: "dockercfg type secret produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("docker-cfg", "default", "kubernetes.io/dockercfg", []string{".dockercfg"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple secrets with some violations",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				// Violation: Opaque with TLS keys.
				cache.Add(SecretGVR, makeSecret("bad-tls", "ns1", "Opaque", []string{"tls.crt", "tls.key"}))
				// Clean: properly typed.
				cache.Add(SecretGVR, makeSecret("good-tls", "ns1", "kubernetes.io/tls", []string{"tls.crt", "tls.key"}))
				// Violation: Opaque with basic-auth keys.
				cache.Add(SecretGVR, makeSecret("bad-auth", "ns2", "Opaque", []string{"username", "password"}))
				// Clean: random keys.
				cache.Add(SecretGVR, makeSecret("normal", "ns2", "Opaque", []string{"data", "config"}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "Opaque secret with .dockercfg triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("old-docker", "default", "Opaque", []string{".dockercfg"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "old-docker",
			wantMessage:  `Secret "old-docker" uses Opaque type but data keys suggest it should be "kubernetes.io/dockercfg".`,
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
				assert.Equal(t, "secrets-default-type", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantMessage != "" {
					assert.Equal(t, tt.wantMessage, findings[0].Message)
				}
				if tt.wantFieldPath != "" {
					assert.Equal(t, tt.wantFieldPath, findings[0].FieldPath)
				}
			}
		})
	}
}

func TestDefaultTypeChecker_CancelledContext(t *testing.T) {
	c := &DefaultTypeChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(SecretGVR, makeSecret("test", "default", "Opaque", []string{"tls.crt", "tls.key"}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestDefaultTypeChecker_Fixtures(t *testing.T) {
	c := &DefaultTypeChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-default-type", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "opaque-tls-secret")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-default-type", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
