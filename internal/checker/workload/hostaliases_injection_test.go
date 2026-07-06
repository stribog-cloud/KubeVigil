package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestHostAliasesInjectionChecker_Metadata(t *testing.T) {
	c := &HostAliasesInjectionChecker{}

	assert.Equal(t, "hostaliases-injection", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestHostAliasesInjectionChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &HostAliasesInjectionChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "hostAliases overriding kubernetes.default triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("injected-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "injected-pod",
		},
		{
			name: "hostAliases overriding kubernetes.default.svc triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("svc-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default.svc"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "svc-pod",
		},
		{
			name: "hostAliases overriding kubernetes.default.svc.cluster.local triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("full-svc-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default.svc.cluster.local"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "full-svc-pod",
		},
		{
			name: "hostAliases overriding arbitrary *.cluster.local triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("cluster-local-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"internal-api.default.svc.cluster.local"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-local-pod",
		},
		{
			name: "hostAliases for external hostname produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("benign-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "203.0.113.10", Hostnames: []string{"legacy-vendor.example.com"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no hostAliases produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-aliases-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple hostnames — only protected one flags the entry",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("mixed-hostnames-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"external.example.com", "kubernetes.default"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "mixed-hostnames-pod",
		},
		{
			name: "multiple alias entries — only the offending entry triggers a finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("multi-entry-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "203.0.113.10", Hostnames: []string{"legacy-vendor.example.com"}},
					{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-entry-pod",
		},
		{
			name: "deployment with injected hostAliases triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment()
				dep.Spec.Template.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default"}},
				}
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "namespace is propagated to finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("ns-pod"), helpers.WithNamespace("prod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "ns-pod",
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "hostaliases-injection", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "hostaliases-injection-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "hostaliases-injection", "passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "bare hostname 'cluster.local' (no subdomain) does not match the suffix rule",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("bare-cluster-local-pod"))
				pod.Spec.HostAliases = []corev1.HostAlias{
					{IP: "10.0.0.5", Hostnames: []string{"cluster.local"}},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
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
				assert.Equal(t, "hostaliases-injection", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Empty(t, findings[0].Container, "hostaliases-injection is a pod-level check")

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestHostAliasesInjectionChecker_CancelledContext(t *testing.T) {
	c := &HostAliasesInjectionChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHostAliasesInjectionChecker_FieldPath(t *testing.T) {
	c := &HostAliasesInjectionChecker{}
	ctx := context.Background()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(helpers.WithName("fp-pod"))
	pod.Spec.HostAliases = []corev1.HostAlias{
		{IP: "10.0.0.99", Hostnames: []string{"kubernetes.default"}},
	}
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".spec.hostAliases[0]", findings[0].FieldPath)
}

func TestMatchedProtectedHostname(t *testing.T) {
	tests := []struct {
		name      string
		hostnames []string
		want      string
	}{
		{name: "empty list", hostnames: nil, want: ""},
		{name: "no match", hostnames: []string{"example.com"}, want: ""},
		{name: "exact kubernetes.default", hostnames: []string{"kubernetes.default"}, want: "kubernetes.default"},
		{name: "exact kubernetes.default.svc", hostnames: []string{"kubernetes.default.svc"}, want: "kubernetes.default.svc"},
		{
			name:      "exact kubernetes.default.svc.cluster.local",
			hostnames: []string{"kubernetes.default.svc.cluster.local"},
			want:      "kubernetes.default.svc.cluster.local",
		},
		{name: "cluster.local suffix", hostnames: []string{"my-svc.ns.svc.cluster.local"}, want: "my-svc.ns.svc.cluster.local"},
		{name: "mixed, second entry matches", hostnames: []string{"example.com", "kubernetes.default"}, want: "kubernetes.default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchedProtectedHostname(tt.hostnames))
		})
	}
}
