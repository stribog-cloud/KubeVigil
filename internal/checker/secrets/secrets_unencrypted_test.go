package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	require.NoError(t, err)
	return unstructured.Unstructured{Object: data}
}

func makeNamespace(t *testing.T, name string, labels map[string]string) unstructured.Unstructured {
	t.Helper()
	ns := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	return toUnstructured(t, ns)
}

func makeNamespaceWithAnnotations(t *testing.T, name string, labels, annotations map[string]string) unstructured.Unstructured {
	t.Helper()
	ns := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels, Annotations: annotations},
	}
	return toUnstructured(t, ns)
}

func TestUnencryptedChecker_Metadata(t *testing.T) {
	c := &UnencryptedChecker{}

	assert.Equal(t, "secrets-unencrypted", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotContains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), namespaceGVR)
}

func TestUnencryptedChecker_Run(t *testing.T) {
	c := &UnencryptedChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantMessage  string
	}{
		{
			name: "no namespaces in cache produces no finding",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "kube-system with EKS label produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name": "kube-system",
					"eks.amazonaws.com/component": "kube-proxy",
				})
				cache.Add(namespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system with GKE label produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name":  "kube-system",
					"cloud.google.com/gke-version": "1.28",
				})
				cache.Add(namespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system with AKS label produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name":    "kube-system",
					"kubernetes.azure.com/managedby": "aks",
				})
				cache.Add(namespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system with addon manager label produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name":     "kube-system",
					"addonmanager.kubernetes.io/mode": "Reconcile",
				})
				cache.Add(namespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system with managed annotation produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespaceWithAnnotations(t, "kube-system",
					map[string]string{"kubernetes.io/metadata.name": "kube-system"},
					map[string]string{"eks.amazonaws.com/nodegroup": "my-nodegroup"},
				)
				cache.Add(namespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system without cloud labels produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name": "kube-system",
				})
				cache.Add(namespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantMessage:  "Cluster etcd encryption at rest could not be verified",
		},
		{
			name: "multiple namespaces with no cloud labels produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(namespaceGVR, makeNamespace(t, "default", map[string]string{
					"kubernetes.io/metadata.name": "default",
				}))
				cache.Add(namespaceGVR, makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name": "kube-system",
				}))
				cache.Add(namespaceGVR, makeNamespace(t, "production", map[string]string{
					"kubernetes.io/metadata.name": "production",
				}))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple namespaces with one having EKS label produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(namespaceGVR, makeNamespace(t, "default", map[string]string{
					"kubernetes.io/metadata.name": "default",
				}))
				cache.Add(namespaceGVR, makeNamespace(t, "kube-system", map[string]string{
					"kubernetes.io/metadata.name": "kube-system",
					"eks.amazonaws.com/component": "kube-proxy",
				}))
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
				f := findings[0]
				assert.Equal(t, "secrets-unencrypted", f.Checker)
				assert.Equal(t, checker.SeverityCritical, f.Severity)
				assert.Equal(t, "etcd", f.Resource)
				assert.Equal(t, "Cluster", f.Kind)
				assert.Empty(t, f.Namespace)
				assert.NotEmpty(t, f.Message)
				assert.NotEmpty(t, f.Remediation)
				if tt.wantMessage != "" {
					assert.Contains(t, f.Message, tt.wantMessage)
				}
			}
		})
	}
}

func TestUnencryptedChecker_CancelledContext(t *testing.T) {
	c := &UnencryptedChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(namespaceGVR, makeNamespace(t, "kube-system", map[string]string{
		"kubernetes.io/metadata.name": "kube-system",
	}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestUnencryptedChecker_FindingFields(t *testing.T) {
	c := &UnencryptedChecker{}
	ctx := context.Background()

	// Use a cache with a namespace but no cloud provider labels to trigger the finding.
	cache := checker.NewResourceCache()
	cache.Add(namespaceGVR, makeNamespace(t, "kube-system", map[string]string{
		"kubernetes.io/metadata.name": "kube-system",
	}))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "secrets-unencrypted", f.Checker)
	assert.Equal(t, checker.SeverityCritical, f.Severity)
	assert.Equal(t, "etcd", f.Resource)
	assert.Equal(t, "Cluster", f.Kind)
	assert.Empty(t, f.Namespace)
	assert.Empty(t, f.FieldPath)
	assert.Contains(t, f.Message, "EncryptionConfiguration")
	assert.Contains(t, f.Remediation, "KMS")
	assert.Contains(t, f.Remediation, "secretbox")
}
