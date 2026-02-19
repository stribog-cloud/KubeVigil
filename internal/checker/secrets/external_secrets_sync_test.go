package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func toInterfaceSlice(maps []map[string]interface{}) []interface{} {
	result := make([]interface{}, len(maps))
	for i, m := range maps {
		result[i] = m
	}
	return result
}

func makeExternalSecret(name, namespace string, conditions []map[string]interface{}, storeRef map[string]interface{}) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "external-secrets.io/v1beta1",
		"kind":       "ExternalSecret",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{},
	}

	if storeRef != nil {
		obj["spec"] = map[string]interface{}{
			"secretStoreRef": storeRef,
		}
	}

	if conditions != nil {
		obj["status"] = map[string]interface{}{
			"conditions": toInterfaceSlice(conditions),
		}
	}

	return unstructured.Unstructured{Object: obj}
}

func makeSecretStore(name, namespace string) unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "external-secrets.io/v1beta1",
			"kind":       "SecretStore",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
		},
	}
}

func makeClusterSecretStore(name string) unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "external-secrets.io/v1beta1",
			"kind":       "ClusterSecretStore",
			"metadata": map[string]interface{}{
				"name": name,
			},
		},
	}
}

func TestExternalSecretsSyncChecker_Metadata(t *testing.T) {
	c := &ExternalSecretsSyncChecker{}

	assert.Equal(t, "external-secrets-sync", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotContains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.Contains(t, c.RequiredResources(), ExternalSecretGVR)
	assert.Contains(t, c.RequiredResources(), SecretStoreGVR)
	assert.Contains(t, c.RequiredResources(), ClusterSecretStoreGVR)
}

func TestExternalSecretsSyncChecker_Run(t *testing.T) {
	c := &ExternalSecretsSyncChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantMessages []string
	}{
		{
			name: "no ExternalSecrets in cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "ExternalSecret with Ready=True produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("my-secret", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				// Add the referenced SecretStore.
				cache.Add(SecretStoreGVR, makeSecretStore("my-store", "default"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalSecret with Ready=False produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("failing-secret", "production",
					[]map[string]interface{}{
						{"type": "Ready", "status": "False"},
					},
					map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				cache.Add(SecretStoreGVR, makeSecretStore("my-store", "production"))
				return cache
			},
			wantFindings: 1,
			wantMessages: []string{"sync failure", "Ready is False"},
		},
		{
			name: "ExternalSecret with no status conditions produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("no-status-secret", "default",
					nil, // no conditions
					map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				cache.Add(SecretStoreGVR, makeSecretStore("my-store", "default"))
				return cache
			},
			wantFindings: 1,
			wantMessages: []string{"no status conditions"},
		},
		{
			name: "ExternalSecret referencing missing SecretStore produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("orphan-secret", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "missing-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				// Do NOT add the referenced SecretStore.
				return cache
			},
			wantFindings: 1,
			wantMessages: []string{"SecretStore", "does not exist"},
		},
		{
			name: "ExternalSecret referencing existing SecretStore produces no store finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("good-secret", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "existing-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				cache.Add(SecretStoreGVR, makeSecretStore("existing-store", "default"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalSecret referencing existing ClusterSecretStore produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("cluster-secret", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "global-store", "kind": "ClusterSecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				cache.Add(ClusterSecretStoreGVR, makeClusterSecretStore("global-store"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalSecret referencing missing ClusterSecretStore produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("cluster-orphan", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "missing-cluster-store", "kind": "ClusterSecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				return cache
			},
			wantFindings: 1,
			wantMessages: []string{"ClusterSecretStore", "does not exist"},
		},
		{
			name: "multiple ExternalSecrets with mixed status produces findings only for failures",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				// Good one.
				esGood := makeExternalSecret("good-secret", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
				)
				// Bad one — sync failure.
				esBad := makeExternalSecret("bad-secret", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "False"},
					},
					map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, esGood)
				cache.Add(ExternalSecretGVR, esBad)
				cache.Add(SecretStoreGVR, makeSecretStore("my-store", "default"))
				return cache
			},
			wantFindings: 1,
			wantMessages: []string{"bad-secret"},
		},
		{
			name: "ExternalSecret with default store kind (no kind specified) checks SecretStore",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("default-kind", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{"name": "my-store"},
				)
				cache.Add(ExternalSecretGVR, es)
				cache.Add(SecretStoreGVR, makeSecretStore("my-store", "default"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalSecret with no storeRef name produces no store finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("no-store-ref", "default",
					[]map[string]interface{}{
						{"type": "Ready", "status": "True"},
					},
					map[string]interface{}{},
				)
				cache.Add(ExternalSecretGVR, es)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalSecret with Ready=False AND missing store produces two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				es := makeExternalSecret("double-bad", "staging",
					[]map[string]interface{}{
						{"type": "Ready", "status": "False"},
					},
					map[string]interface{}{"name": "ghost-store", "kind": "SecretStore"},
				)
				cache.Add(ExternalSecretGVR, es)
				return cache
			},
			wantFindings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)

			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				for i := range findings {
					assert.Equal(t, "external-secrets-sync", findings[i].Checker)
					assert.Equal(t, checker.SeverityMedium, findings[i].Severity)
					assert.Equal(t, "ExternalSecret", findings[i].Kind)
					assert.NotEmpty(t, findings[i].Message)
					assert.NotEmpty(t, findings[i].Remediation)
					assert.NotEmpty(t, findings[i].FieldPath)
				}
			}

			for _, msg := range tt.wantMessages {
				found := false
				for i := range findings {
					if assert.ObjectsAreEqual(true, true) {
						if containsStr(findings[i].Message, msg) {
							found = true
							break
						}
					}
				}
				if !found {
					t.Errorf("expected at least one finding message to contain %q", msg)
				}
			}
		})
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestExternalSecretsSyncChecker_CancelledContext(t *testing.T) {
	c := &ExternalSecretsSyncChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	es := makeExternalSecret("my-secret", "default",
		[]map[string]interface{}{
			{"type": "Ready", "status": "True"},
		},
		map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
	)
	cache.Add(ExternalSecretGVR, es)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestExternalSecretsSyncChecker_FindingFields(t *testing.T) {
	c := &ExternalSecretsSyncChecker{}
	ctx := context.Background()

	t.Run("sync failure finding has correct fields", func(t *testing.T) {
		cache := checker.NewResourceCache()
		es := makeExternalSecret("test-es", "my-ns",
			[]map[string]interface{}{
				{"type": "Ready", "status": "False", "reason": "SecretSyncError"},
			},
			map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
		)
		cache.Add(ExternalSecretGVR, es)
		cache.Add(SecretStoreGVR, makeSecretStore("my-store", "my-ns"))

		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)

		f := findings[0]
		assert.Equal(t, "external-secrets-sync", f.Checker)
		assert.Equal(t, checker.SeverityMedium, f.Severity)
		assert.Equal(t, "test-es", f.Resource)
		assert.Equal(t, "my-ns", f.Namespace)
		assert.Equal(t, "ExternalSecret", f.Kind)
		assert.Equal(t, ".status.conditions", f.FieldPath)
		assert.Contains(t, f.Message, "test-es")
		assert.Contains(t, f.Message, "my-ns")
		assert.Contains(t, f.Remediation, "kubectl describe")
	})

	t.Run("missing store finding has correct fields", func(t *testing.T) {
		cache := checker.NewResourceCache()
		es := makeExternalSecret("test-es", "my-ns",
			[]map[string]interface{}{
				{"type": "Ready", "status": "True"},
			},
			map[string]interface{}{"name": "nonexistent", "kind": "SecretStore"},
		)
		cache.Add(ExternalSecretGVR, es)

		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)

		f := findings[0]
		assert.Equal(t, "external-secrets-sync", f.Checker)
		assert.Equal(t, "test-es", f.Resource)
		assert.Equal(t, "my-ns", f.Namespace)
		assert.Equal(t, ".spec.secretStoreRef", f.FieldPath)
		assert.Contains(t, f.Message, "nonexistent")
		assert.Contains(t, f.Message, "does not exist")
		assert.Contains(t, f.Remediation, "SecretStore")
	})
}

func TestExternalSecretsSyncChecker_NamespaceIsolation(t *testing.T) {
	c := &ExternalSecretsSyncChecker{}
	ctx := context.Background()

	// SecretStore exists in "default" but ExternalSecret is in "production" — should find missing store.
	cache := checker.NewResourceCache()
	es := makeExternalSecret("cross-ns-es", "production",
		[]map[string]interface{}{
			{"type": "Ready", "status": "True"},
		},
		map[string]interface{}{"name": "my-store", "kind": "SecretStore"},
	)
	cache.Add(ExternalSecretGVR, es)
	cache.Add(SecretStoreGVR, makeSecretStore("my-store", "default"))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "does not exist")
}
