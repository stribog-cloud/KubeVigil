package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestDNSSecurityChecker_Metadata(t *testing.T) {
	c := &DNSSecurityChecker{}

	assert.Equal(t, "dns-security", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, ConfigMapGVR, c.RequiredResources()[0])
}

func TestDNSSecurityChecker_Run(t *testing.T) {
	c := &DNSSecurityChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		checkMessage string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "non-coredns configmap is ignored",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "other-config", "kube-system", map[string]string{
					"Corefile": "forward . 8.8.8.8",
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "coredns in wrong namespace is ignored",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "default", map[string]string{
					"Corefile": "forward . 8.8.8.8",
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "insecure forward triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"Corefile": `.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . 8.8.8.8 8.8.4.4
    cache 30
    reload
}`,
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 1,
			checkMessage: "insecure",
		},
		{
			name: "TLS forward does not trigger insecure finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"Corefile": `.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . tls://1.1.1.1 tls://1.0.0.1
    cache 30
    reload
}`,
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "debug plugin triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"Corefile": `.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . tls://1.1.1.1 tls://1.0.0.1
    debug
    cache 30
    reload
}`,
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 1,
			checkMessage: "debug plugin",
		},
		{
			name: "missing cache triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"Corefile": `.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . tls://1.1.1.1 tls://1.0.0.1
    reload
}`,
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 1,
			checkMessage: "no cache plugin",
		},
		{
			name: "cache with TTL does not trigger missing cache finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"Corefile": `.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . tls://1.1.1.1 tls://1.0.0.1
    cache 60
    reload
}`,
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple issues trigger multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"Corefile": `.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa
    forward . 8.8.8.8 8.8.4.4
    debug
    reload
}`,
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 3, // insecure forward + debug + missing cache
		},
		{
			name: "configmap with no Corefile key is ignored",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
					"other-key": "some data",
				})
				cache.Add(ConfigMapGVR, cm)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "fixture: failing.yaml triggers findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "dns-security", "failing.yaml")
			},
			wantFindings: 3, // insecure forward + debug + missing cache
		},
		{
			name: "fixture: passing.yaml does not trigger findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "dns-security", "passing.yaml")
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
				for _, f := range findings {
					assert.Equal(t, "dns-security", f.Checker)
					assert.Equal(t, checker.SeverityMedium, f.Severity)
					assert.Equal(t, "ConfigMap", f.Kind)
					assert.Equal(t, "coredns", f.Resource)
					assert.Equal(t, "kube-system", f.Namespace)
					assert.Equal(t, ".data.Corefile", f.FieldPath)
				}

				if tt.checkMessage != "" {
					found := false
					for _, f := range findings {
						if containsSubstring(f.Message, tt.checkMessage) {
							found = true
							break
						}
					}
					assert.True(t, found, "expected message containing %q in findings", tt.checkMessage)
				}
			}
		})
	}
}

func TestDNSSecurityChecker_CancelledContext(t *testing.T) {
	c := &DNSSecurityChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
		"Corefile": "forward . 8.8.8.8",
	})
	cache.Add(ConfigMapGVR, cm)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestDNSSecurityChecker_SecureConfig(t *testing.T) {
	c := &DNSSecurityChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
		"Corefile": `.:53 {
    errors
    health {
        lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153
    forward . tls://1.1.1.1 tls://1.0.0.1 {
        tls_servername cloudflare-dns.com
    }
    cache 30
    loop
    reload
    loadbalance
}`,
	})
	cache.Add(ConfigMapGVR, cm)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDNSSecurityChecker_ForwardWithSlashResolver(t *testing.T) {
	c := &DNSSecurityChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cm := makeConfigMap(t, "coredns", "kube-system", map[string]string{
		"Corefile": `.:53 {
    errors
    forward . /etc/resolv.conf
    cache 30
}`,
	})
	cache.Add(ConfigMapGVR, cm)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	// /etc/resolv.conf is not tls:// so it triggers insecure forward
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "/etc/resolv.conf")
}
