package secrets

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// makeSecretWithData builds an unstructured Secret with base64-encoded .data values.
func makeSecretWithData(name, namespace string, data map[string]string) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"type":       "Opaque",
	}
	if len(data) > 0 {
		encoded := make(map[string]interface{}, len(data))
		for k, v := range data {
			encoded[k] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		obj["data"] = encoded
	}
	return unstructured.Unstructured{Object: obj}
}

// makeSecretWithStringData builds an unstructured Secret with plaintext .stringData values.
func makeSecretWithStringData(name, namespace string, stringData map[string]string) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"type":       "Opaque",
	}
	if len(stringData) > 0 {
		sd := make(map[string]interface{}, len(stringData))
		for k, v := range stringData {
			sd[k] = v
		}
		obj["stringData"] = sd
	}
	return unstructured.Unstructured{Object: obj}
}

// makeSecretWithRawData builds an unstructured Secret with pre-encoded .data values (raw strings).
func makeSecretWithRawData(name, namespace string, rawData map[string]string) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"type":       "Opaque",
	}
	if len(rawData) > 0 {
		data := make(map[string]interface{}, len(rawData))
		for k, v := range rawData {
			data[k] = v
		}
		obj["data"] = data
	}
	return unstructured.Unstructured{Object: obj}
}

func TestHardcodedManifestsChecker_Metadata(t *testing.T) {
	c := &HardcodedManifestsChecker{}

	assert.Equal(t, "secrets-hardcoded-manifests", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotContains(t, c.SupportedModes(), checker.ScanModeLive)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, SecretGVR, c.RequiredResources()[0])
}

func TestHardcodedManifestsChecker_Run(t *testing.T) {
	c := &HardcodedManifestsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		checkMessage string
	}{
		{
			name: "base64-encoded JWT in .data triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("jwt-secret", "default", map[string]string{
					"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "jwt-secret",
			checkMessage: `Secret "jwt-secret" contains hardcoded value in key "token" that appears to be a real secret.`,
		},
		{
			name: "base64-encoded AWS key in .data triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("aws-secret", "default", map[string]string{
					"access-key": "AKIAIOSFODNN7EXAMPLE",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "aws-secret",
			checkMessage: `Secret "aws-secret" contains hardcoded value in key "access-key" that appears to be a real secret.`,
		},
		{
			name: "high-entropy base64 value triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("entropy-secret", "default", map[string]string{
					"api-key": "aB3$kL9mNp2QrS5tUv8WxYz1fG7hJ0kL",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "entropy-secret",
		},
		{
			name: "stringData containing JWT triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithStringData("sd-jwt-secret", "default", map[string]string{
					"auth": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "sd-jwt-secret",
		},
		{
			name: "short values produce no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("short-secret", "default", map[string]string{
					"pin": "123",
					"tag": "ab",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "low-entropy base64 values produce no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("low-entropy", "default", map[string]string{
					"config": "this is just a normal configuration value for the app",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "invalid base64 in .data is skipped gracefully",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				// Use raw data to inject invalid base64.
				secret := makeSecretWithRawData("bad-b64", "default", map[string]string{
					"broken": "!!!not-valid-base64!!!",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty secret produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata":   map[string]interface{}{"name": "empty-secret", "namespace": "default"},
					"type":       "Opaque",
				}}
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
			name: "PEM private key in stringData triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithStringData("pem-secret", "default", map[string]string{
					"private.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "pem-secret",
		},
		{
			name: "GitHub PAT in data triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("github-secret", "default", map[string]string{
					"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "github-secret",
		},
		{
			name: "multiple keys with some secrets",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecretWithData("multi-key", "default", map[string]string{
					"jwt":    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
					"config": "debug=true",
				})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-key",
		},
		{
			name: "custom entropy threshold via policies",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Secrets: checker.SecretPolicies{
						EntropyThreshold: 6.0,
					},
				})
				// High entropy but below 6.0 threshold, and no known pattern match.
				secret := makeSecretWithData("custom-threshold", "default", map[string]string{
					"token": "aB3$kL9mNp2QrS5tUv8WxYz1",
				})
				cache.Add(SecretGVR, secret)
				return cache
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
				assert.Equal(t, "secrets-hardcoded-manifests", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMessage != "" {
					assert.Equal(t, tt.checkMessage, findings[0].Message)
				}
			}
		})
	}
}

func TestHardcodedManifestsChecker_CancelledContext(t *testing.T) {
	c := &HardcodedManifestsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	secret := makeSecretWithData("test", "default", map[string]string{
		"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
	})
	cache.Add(SecretGVR, secret)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHardcodedManifestsChecker_FieldPath(t *testing.T) {
	c := &HardcodedManifestsChecker{}
	ctx := context.Background()

	t.Run("data field path", func(t *testing.T) {
		cache := checker.NewResourceCache()
		secret := makeSecretWithData("fp-data", "default", map[string]string{
			"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
		})
		cache.Add(SecretGVR, secret)

		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, ".data.token", findings[0].FieldPath)
	})

	t.Run("stringData field path", func(t *testing.T) {
		cache := checker.NewResourceCache()
		secret := makeSecretWithStringData("fp-sd", "default", map[string]string{
			"secret-key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
		})
		cache.Add(SecretGVR, secret)

		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, ".stringData.secret-key", findings[0].FieldPath)
	})
}

func TestHardcodedManifestsChecker_Fixtures(t *testing.T) {
	c := &HardcodedManifestsChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-hardcoded-manifests", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "hardcoded-secret")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-hardcoded-manifests", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
