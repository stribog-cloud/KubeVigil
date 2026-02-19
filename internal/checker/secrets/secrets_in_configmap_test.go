package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestInConfigMapChecker_Metadata(t *testing.T) {
	c := &InConfigMapChecker{}

	assert.Equal(t, "secrets-in-configmap", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, ConfigMapGVR, c.RequiredResources()[0])
}

func TestInConfigMapChecker_Run(t *testing.T) {
	c := &InConfigMapChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		checkMessage string
	}{
		{
			name: "ConfigMap with password key triggers finding (key match)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "app-config", Namespace: "default"},
					Data:       map[string]string{"db_password": "mysecretpassword123"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			wantResource: "app-config",
			checkMessage: `ConfigMap "app-config" has key "db_password" that appears to contain a secret`,
		},
		{
			name: "ConfigMap with JWT value triggers finding (pattern match)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "jwt-config", Namespace: "default"},
					Data:       map[string]string{"config_data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			wantResource: "jwt-config",
			checkMessage: `ConfigMap "jwt-config" has value in key "config_data" matching known secret pattern`,
		},
		{
			name: "ConfigMap with high-entropy value triggers finding (entropy match)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "entropy-config", Namespace: "default"},
					Data:       map[string]string{"data_blob": "aB3$kL9mNp2QrS5tUv8WxYz1"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			wantResource: "entropy-config",
			checkMessage: `ConfigMap "entropy-config" has high-entropy value in key "data_blob" (possible secret)`,
		},
		{
			name: "ConfigMap with normal config values produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "normal-config", Namespace: "default"},
					Data: map[string]string{
						"log_level":    "info",
						"port":         "8080",
						"host":         "localhost",
						"debug":        "false",
						"max_replicas": "10",
					},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ConfigMap with short high-entropy value produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "short-entropy", Namespace: "default"},
					Data:       map[string]string{"code": "aB3$kL9m"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ConfigMap with AWS key value triggers finding (pattern match)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "aws-config", Namespace: "default"},
					Data:       map[string]string{"cloud_key": "AKIAIOSFODNN7EXAMPLE"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			wantResource: "aws-config",
			checkMessage: `ConfigMap "aws-config" has value in key "cloud_key" matching known secret pattern`,
		},
		{
			name: "ConfigMap with PEM private key triggers finding (pattern match)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "pem-config", Namespace: "default"},
					Data:       map[string]string{"cert_data": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			wantResource: "pem-config",
			checkMessage: `ConfigMap "pem-config" has value in key "cert_data" matching known secret pattern`,
		},
		{
			name: "empty ConfigMap produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "empty-config", Namespace: "default"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "custom entropy threshold via policies respects threshold",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				// Set a very high threshold so entropy-only detection does not fire.
				cache.SetPolicies(&checker.Policies{
					Secrets: checker.SecretPolicies{
						EntropyThreshold: 6.0,
					},
				})
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "custom-threshold", Namespace: "default"},
					// This value has entropy ~4.7 (above default 4.5 but below custom 6.0).
					Data: map[string]string{"data_blob": "aB3$kL9mNp2QrS5tUv8WxYz1"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
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
			name: "key name match takes priority over pattern match",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "priority-config", Namespace: "default"},
					// Key matches "password" and value is a JWT — should report key match message.
					Data: map[string]string{"password": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			checkMessage: `ConfigMap "priority-config" has key "password" that appears to contain a secret`,
		},
		{
			name: "config file key skips entropy analysis (nginx.conf)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "nginx-config", Namespace: "default"},
					Data: map[string]string{
						"nginx.conf":   "server { listen 80; location / { proxy_pass http://backend:8080; proxy_set_header X-Real-IP $remote_addr; } }",
						"default.conf": "upstream backend { server 10.0.0.1:8080 weight=5; server 10.0.0.2:8080 weight=3; keepalive 32; }",
					},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "config file key skips entropy but key-name match still fires",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "mixed-config", Namespace: "default"},
					Data: map[string]string{
						"grafana.ini": "some high entropy xYz123$!@AbCdEf config content here padding",
						"db_password": "hunter2",
					},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			checkMessage: `ConfigMap "mixed-config" has key "db_password" that appears to contain a secret`,
		},
		{
			name: "config file key skips entropy but pattern match still fires",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := &corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "jwt-in-json", Namespace: "default"},
					Data: map[string]string{
						"config.json": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
					},
				}
				cache.Add(ConfigMapGVR, toUnstructured(t, cm))
				return cache
			},
			wantFindings: 1,
			checkMessage: `ConfigMap "jwt-in-json" has value in key "config.json" matching known secret pattern`,
		},
		{
			name: "fixture: failing.yaml triggers findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "secrets-in-configmap", "failing.yaml")
			},
			wantFindings: 3,
			wantResource: "suspicious-config",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "secrets-in-configmap", "passing.yaml")
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
				assert.Equal(t, "secrets-in-configmap", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMessage != "" {
					found := false
					for i := range findings {
						if findings[i].Message == tt.checkMessage {
							found = true
							break
						}
					}
					assert.True(t, found, "expected message %q in findings", tt.checkMessage)
				}
			}
		})
	}
}

func TestInConfigMapChecker_CancelledContext(t *testing.T) {
	c := &InConfigMapChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-cm", Namespace: "default"},
		Data:       map[string]string{"password": "secret123"},
	}
	cache.Add(ConfigMapGVR, toUnstructured(t, cm))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestInConfigMapChecker_FieldPath(t *testing.T) {
	c := &InConfigMapChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "field-path-cm", Namespace: "default"},
		Data:       map[string]string{"db_password": "secret123"},
	}
	cache.Add(ConfigMapGVR, toUnstructured(t, cm))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, ".data.db_password", findings[0].FieldPath)
}

func TestInConfigMapChecker_MultipleKeysOneFinding(t *testing.T) {
	// A key that matches by name should not also report pattern or entropy matches.
	c := &InConfigMapChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "dedup-cm", Namespace: "default"},
		Data:       map[string]string{"api_key": "AKIAIOSFODNN7EXAMPLE"},
	}
	cache.Add(ConfigMapGVR, toUnstructured(t, cm))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	// Only one finding per key, even though both key name and value pattern match.
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "has key")
}
