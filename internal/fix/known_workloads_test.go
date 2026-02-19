package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchKnownWorkload_ExactPatternMatch(t *testing.T) {
	tests := []struct {
		name         string
		images       []string
		wantMatch    bool
		wantCategory string
		wantPattern  string
	}{
		{
			name:         "calico/node exact",
			images:       []string{"calico/node"},
			wantMatch:    true,
			wantCategory: "CNI plugin",
			wantPattern:  "calico/node",
		},
		{
			name:         "cilium/cilium exact",
			images:       []string{"cilium/cilium"},
			wantMatch:    true,
			wantCategory: "CNI plugin",
			wantPattern:  "cilium/cilium",
		},
		{
			name:         "rook/ceph exact",
			images:       []string{"rook/ceph"},
			wantMatch:    true,
			wantCategory: "Storage operator",
			wantPattern:  "rook/ceph",
		},
		{
			name:         "kube-proxy exact",
			images:       []string{"registry.k8s.io/kube-proxy"},
			wantMatch:    true,
			wantCategory: "Core component",
			wantPattern:  "registry.k8s.io/kube-proxy",
		},
		{
			name:         "istio proxyv2",
			images:       []string{"istio/proxyv2"},
			wantMatch:    true,
			wantCategory: "Service mesh",
			wantPattern:  "istio/proxyv2",
		},
		{
			name:         "ingress-nginx controller",
			images:       []string{"ingress-nginx/controller"},
			wantMatch:    true,
			wantCategory: "Ingress controller",
			wantPattern:  "ingress-nginx/controller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl, matched := MatchKnownWorkload(tt.images)
			assert.Equal(t, tt.wantMatch, matched)
			if tt.wantMatch {
				assert.Equal(t, tt.wantCategory, wl.Category)
				assert.Equal(t, tt.wantPattern, wl.Pattern)
				assert.NotEmpty(t, wl.Reason)
			}
		})
	}
}

func TestMatchKnownWorkload_PartialMatchWithTag(t *testing.T) {
	tests := []struct {
		name         string
		images       []string
		wantMatch    bool
		wantCategory string
	}{
		{
			name:         "calico/node with tag",
			images:       []string{"docker.io/calico/node:v3.27.0"},
			wantMatch:    true,
			wantCategory: "CNI plugin",
		},
		{
			name:         "cilium with registry and tag",
			images:       []string{"quay.io/cilium/cilium:v1.15.0"},
			wantMatch:    true,
			wantCategory: "CNI plugin",
		},
		{
			name:         "kube-proxy with tag",
			images:       []string{"registry.k8s.io/kube-proxy:v1.30.0"},
			wantMatch:    true,
			wantCategory: "Core component",
		},
		{
			name:         "node-exporter with registry prefix",
			images:       []string{"quay.io/prometheus/node-exporter:v1.7.0"},
			wantMatch:    true,
			wantCategory: "Monitoring agent",
		},
		{
			name:         "traefik with tag matches traefik: pattern",
			images:       []string{"traefik:v3.0.0"},
			wantMatch:    true,
			wantCategory: "Ingress controller",
		},
		{
			name:         "openebs with specific image",
			images:       []string{"openebs/provisioner-localpv:3.5.0"},
			wantMatch:    true,
			wantCategory: "Storage operator",
		},
		{
			name:         "longhorn with tag",
			images:       []string{"longhornio/longhorn-manager:v1.6.0"},
			wantMatch:    true,
			wantCategory: "Storage operator",
		},
		{
			name:         "linkerd proxy-init with registry",
			images:       []string{"cr.l5d.io/linkerd/proxy-init:v2.3.0"},
			wantMatch:    true,
			wantCategory: "Service mesh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl, matched := MatchKnownWorkload(tt.images)
			assert.Equal(t, tt.wantMatch, matched)
			if tt.wantMatch {
				assert.Equal(t, tt.wantCategory, wl.Category)
			}
		})
	}
}

func TestMatchKnownWorkload_NoMatch(t *testing.T) {
	tests := []struct {
		name   string
		images []string
	}{
		{name: "regular app image", images: []string{"my-app:v1.2.3"}},
		{name: "nginx web server", images: []string{"nginx:1.25"}},
		{name: "postgres database", images: []string{"postgres:16"}},
		{name: "redis cache", images: []string{"redis:7-alpine"}},
		{name: "custom registry image", images: []string{"registry.example.com/team/service:latest"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl, matched := MatchKnownWorkload(tt.images)
			assert.False(t, matched)
			assert.Equal(t, KnownWorkload{}, wl)
		})
	}
}

func TestMatchKnownWorkload_EmptyImageList(t *testing.T) {
	wl, matched := MatchKnownWorkload(nil)
	assert.False(t, matched)
	assert.Equal(t, KnownWorkload{}, wl)

	wl, matched = MatchKnownWorkload([]string{})
	assert.False(t, matched)
	assert.Equal(t, KnownWorkload{}, wl)
}

func TestMatchKnownWorkload_MultipleImagesOneMatches(t *testing.T) {
	images := []string{
		"my-app:v1.0.0",
		"calico/node:v3.27.0",
		"sidecar:latest",
	}

	wl, matched := MatchKnownWorkload(images)
	require.True(t, matched)
	assert.Equal(t, "calico/node", wl.Pattern)
	assert.Equal(t, "CNI plugin", wl.Category)
}

func TestMatchKnownWorkload_FirstMatchWins(t *testing.T) {
	// When multiple images match, the first matched image's workload is returned.
	images := []string{
		"calico/node:v3.27.0",
		"registry.k8s.io/kube-proxy:v1.30.0",
	}

	wl, matched := MatchKnownWorkload(images)
	require.True(t, matched)
	assert.Equal(t, "calico/node", wl.Pattern)
}

func TestMatchKnownWorkload_CaseSensitive(t *testing.T) {
	// Image names are case-sensitive. "Calico/Node" should not match "calico/node".
	wl, matched := MatchKnownWorkload([]string{"Calico/Node:v3.27.0"})
	assert.False(t, matched)
	assert.Equal(t, KnownWorkload{}, wl)
}

func TestDefaultKnownWorkloads_AllHaveRequiredFields(t *testing.T) {
	for i, wl := range DefaultKnownWorkloads {
		assert.NotEmpty(t, wl.Pattern, "workload at index %d has empty Pattern", i)
		assert.NotEmpty(t, wl.Category, "workload at index %d (%s) has empty Category", i, wl.Pattern)
		assert.NotEmpty(t, wl.Reason, "workload at index %d (%s) has empty Reason", i, wl.Pattern)
	}
}

func TestDefaultKnownWorkloads_CategoriesAreKnown(t *testing.T) {
	knownCategories := map[string]bool{
		"CNI plugin":          true,
		"Storage operator":    true,
		"Storage provisioner": true,
		"Core component":      true,
		"Monitoring agent":    true,
		"Ingress controller":  true,
		"Service mesh":        true,
	}

	for _, wl := range DefaultKnownWorkloads {
		assert.True(t, knownCategories[wl.Category],
			"workload %q has unknown category %q", wl.Pattern, wl.Category)
	}
}

func TestDefaultKnownWorkloads_NoDuplicatePatterns(t *testing.T) {
	seen := make(map[string]bool, len(DefaultKnownWorkloads))
	for _, wl := range DefaultKnownWorkloads {
		assert.False(t, seen[wl.Pattern], "duplicate pattern: %q", wl.Pattern)
		seen[wl.Pattern] = true
	}
}
