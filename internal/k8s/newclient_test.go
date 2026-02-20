package k8s

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	kubetesting "k8s.io/client-go/testing"
)

func TestClusterVersion_Error(t *testing.T) {
	fakeDisc := &fakediscovery.FakeDiscovery{
		Fake: &kubetesting.Fake{},
	}
	fakeDisc.PrependReactor("*", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("connection refused")
	})
	_, err := ClusterVersion(fakeDisc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting server version")
}

func writeKubeconfig(t *testing.T, dir, server string) string {
	t.Helper()
	content := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: %s\n    insecure-skip-tls-verify: true\n  name: test-cluster\ncontexts:\n- context:\n    cluster: test-cluster\n    user: test-user\n  name: test-context\ncurrent-context: test-context\nusers:\n- name: test-user\n  user:\n    token: fake-token\n", server)
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestNewClient_InvalidKubeconfig(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad-config")
	require.NoError(t, os.WriteFile(badPath, []byte("not valid{{{"), 0o600))
	_, _, err := NewClient(badPath, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating kubeconfig client")
}

func TestNewClient_NonexistentPath(t *testing.T) {
	_, _, err := NewClient("/nonexistent/path/kubeconfig-xyz", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating kubeconfig client")
}

func TestNewClient_EmptyPathInClusterFallbackFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBECONFIG", filepath.Join(dir, "nonexistent"))
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	_, _, err := NewClient("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating in-cluster config")
}

func TestNewClient_ValidKubeconfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	dir := t.TempDir()
	kubeconfigPath := writeKubeconfig(t, dir, srv.URL)
	dynClient, discClient, err := NewClient(kubeconfigPath, "")
	require.NoError(t, err)
	assert.NotNil(t, dynClient)
	assert.NotNil(t, discClient)
}

func TestNewClient_ValidKubeconfigWithContext(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	dir := t.TempDir()
	kubeconfigPath := writeKubeconfig(t, dir, srv.URL)
	dynClient, discClient, err := NewClient(kubeconfigPath, "test-context")
	require.NoError(t, err)
	assert.NotNil(t, dynClient)
	assert.NotNil(t, discClient)
}

func TestNewClient_ValidKubeconfigBadContext(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	dir := t.TempDir()
	kubeconfigPath := writeKubeconfig(t, dir, srv.URL)
	_, _, err := NewClient(kubeconfigPath, "nonexistent-context")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating kubeconfig client")
}

func TestClusterVersion_WithVersion(t *testing.T) {
	fakeDisc := &fakediscovery.FakeDiscovery{
		Fake:               &kubetesting.Fake{},
		FakedServerVersion: &version.Info{GitVersion: "v1.30.2", Major: "1", Minor: "30"},
	}
	ver, err := ClusterVersion(fakeDisc)
	require.NoError(t, err)
	assert.Equal(t, "v1.30.2", ver)
}
