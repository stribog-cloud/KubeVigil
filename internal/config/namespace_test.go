package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyNamespace(t *testing.T) {
	cfg := Default()

	tests := []struct {
		ns   string
		want NamespaceType
	}{
		// Empty → cluster-scoped.
		{"", NamespaceClusterScoped},
		// System namespaces.
		{"kube-system", NamespaceSystem},
		{"kube-public", NamespaceSystem},
		{"kube-node-lease", NamespaceSystem},
		// Infrastructure namespaces (built-in).
		{"rook-ceph", NamespaceInfrastructure},
		{"monitoring", NamespaceInfrastructure},
		{"calico-system", NamespaceInfrastructure},
		{"tigera-operator", NamespaceInfrastructure},
		{"cert-manager", NamespaceInfrastructure},
		{"istio-system", NamespaceInfrastructure},
		{"argocd", NamespaceInfrastructure},
		{"flux-system", NamespaceInfrastructure},
		{"ingress-nginx", NamespaceInfrastructure},
		// Application namespaces.
		{"default", NamespaceApplication},
		{"my-app", NamespaceApplication},
		{"production", NamespaceApplication},
		{"backend", NamespaceApplication},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			got := ClassifyNamespace(cfg, tt.ns)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifyNamespace_CustomInfra(t *testing.T) {
	cfg := Default()
	cfg.Settings.InfraNamespaces = []string{"my-infra", "custom-monitoring"}

	assert.Equal(t, NamespaceInfrastructure, ClassifyNamespace(cfg, "my-infra"))
	assert.Equal(t, NamespaceInfrastructure, ClassifyNamespace(cfg, "custom-monitoring"))
	// Built-in infra still works.
	assert.Equal(t, NamespaceInfrastructure, ClassifyNamespace(cfg, "rook-ceph"))
	// Non-infra still application.
	assert.Equal(t, NamespaceApplication, ClassifyNamespace(cfg, "my-app"))
}

func TestNamespaceType_String(t *testing.T) {
	tests := []struct {
		nt   NamespaceType
		want string
	}{
		{NamespaceApplication, "application"},
		{NamespaceInfrastructure, "infrastructure"},
		{NamespaceSystem, "system"},
		{NamespaceClusterScoped, "cluster-scoped"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.nt.String())
		})
	}
}

func TestIsInfraNamespace(t *testing.T) {
	cfg := Default()
	assert.True(t, IsInfraNamespace(cfg, "rook-ceph"))
	assert.False(t, IsInfraNamespace(cfg, "default"))
	assert.False(t, IsInfraNamespace(cfg, "kube-system")) // system, not infra
}

func TestNamespaceType_String_AllValues(t *testing.T) {
	testCases := []struct {
		name string
		nt   NamespaceType
		want string
	}{
		{name: "application", nt: NamespaceApplication, want: "application"},
		{name: "infrastructure", nt: NamespaceInfrastructure, want: "infrastructure"},
		{name: "system", nt: NamespaceSystem, want: "system"},
		{name: "cluster-scoped", nt: NamespaceClusterScoped, want: "cluster-scoped"},
		{name: "unknown value", nt: NamespaceType(99), want: "unknown"},
		{name: "negative value", nt: NamespaceType(-1), want: "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.nt.String()
			assert.Equal(t, tc.want, got, "NamespaceType(%d).String()", tc.nt)
		})
	}
}
