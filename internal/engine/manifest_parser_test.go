package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func fixturesDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(projectRoot, "test", "fixtures", "manifest-parser")
}

func TestParseFile(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	t.Run("single pod YAML", func(t *testing.T) {
		cache, errs := ParseFile(filepath.Join(fixturesDir(), "single-pod.yaml"))
		require.Empty(t, errs)
		require.NotNil(t, cache)

		pods := cache.List(podGVR)
		require.Len(t, pods, 1)
		assert.Equal(t, "single-pod", pods[0].GetName())
	})

	t.Run("multi-document YAML", func(t *testing.T) {
		cache, errs := ParseFile(filepath.Join(fixturesDir(), "multi-doc.yaml"))
		require.Empty(t, errs)

		pods := cache.List(podGVR)
		require.Len(t, pods, 1)
		deploys := cache.List(deployGVR)
		require.Len(t, deploys, 1)
		assert.Equal(t, 2, cache.Len())
	})

	t.Run("multi-document with empty documents", func(t *testing.T) {
		cache, errs := ParseFile(filepath.Join(fixturesDir(), "multi-doc-with-empty.yaml"))
		require.Empty(t, errs)

		pods := cache.List(podGVR)
		assert.Len(t, pods, 2)
	})

	t.Run("empty YAML file produces empty cache", func(t *testing.T) {
		cache, errs := ParseFile(filepath.Join(fixturesDir(), "empty.yaml"))
		assert.Empty(t, errs)
		assert.Equal(t, 0, cache.Len())
	})

	t.Run("malformed YAML returns error", func(t *testing.T) {
		cache, errs := ParseFile(filepath.Join(fixturesDir(), "malformed.yaml"))
		require.NotEmpty(t, errs)
		// Cache should still be returned (may be empty or partial)
		require.NotNil(t, cache)
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		_, errs := ParseFile(filepath.Join(fixturesDir(), "does-not-exist.yaml"))
		require.NotEmpty(t, errs)
	})
}

func TestParseDir(t *testing.T) {
	t.Run("loads all YAML files from directory", func(t *testing.T) {
		cache, errs := ParseDir(fixturesDir())
		// malformed.yaml will produce an error but other files should parse
		require.NotNil(t, cache)
		// Should have parsed pods and deployments from valid files
		assert.Greater(t, cache.Len(), 0)
		// Should have at least one error from malformed.yaml
		assert.NotEmpty(t, errs)
	})

	t.Run("skips non-YAML files", func(t *testing.T) {
		// not-yaml.txt should be skipped, not cause errors
		cache, errs := ParseDir(fixturesDir())
		require.NotNil(t, cache)
		// Only malformed.yaml should cause errors, not the .txt file
		for _, e := range errs {
			assert.NotContains(t, e.Error(), "not-yaml.txt")
		}
		_ = cache
	})

	t.Run("nonexistent directory returns error", func(t *testing.T) {
		_, errs := ParseDir("/nonexistent/path")
		require.NotEmpty(t, errs)
	})
}

func TestParseBytes(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	t.Run("parses valid YAML bytes", func(t *testing.T) {
		yamlData := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: byte-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
`)
		cache, errs := ParseBytes(yamlData)
		require.Empty(t, errs)
		pods := cache.List(podGVR)
		require.Len(t, pods, 1)
		assert.Equal(t, "byte-pod", pods[0].GetName())
	})

	t.Run("parses multi-document bytes", func(t *testing.T) {
		yamlData := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: pod-1
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-2
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
`)
		cache, errs := ParseBytes(yamlData)
		require.Empty(t, errs)
		pods := cache.List(podGVR)
		assert.Len(t, pods, 2)
	})

	t.Run("empty bytes returns empty cache", func(t *testing.T) {
		cache, errs := ParseBytes([]byte{})
		assert.Empty(t, errs)
		assert.Equal(t, 0, cache.Len())
	})

	t.Run("nil bytes returns empty cache", func(t *testing.T) {
		cache, errs := ParseBytes(nil)
		assert.Empty(t, errs)
		assert.Equal(t, 0, cache.Len())
	})
}

func TestParsePath(t *testing.T) {
	t.Run("file path dispatches to ParseFile", func(t *testing.T) {
		cache, errs := ParsePath(filepath.Join(fixturesDir(), "single-pod.yaml"))
		require.Empty(t, errs)
		assert.Greater(t, cache.Len(), 0)
	})

	t.Run("directory path dispatches to ParseDir", func(t *testing.T) {
		cache, errs := ParsePath(fixturesDir())
		require.NotNil(t, cache)
		assert.Greater(t, cache.Len(), 0)
		// malformed.yaml produces errors
		_ = errs
	})

	t.Run("nonexistent path returns error", func(t *testing.T) {
		_, errs := ParsePath("/nonexistent/path/thing.yaml")
		require.NotEmpty(t, errs)
	})
}

func TestParseDir_Recursive(t *testing.T) {
	// Create a temp dir with subdirectories
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "sub")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	podYAML := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: nested-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
`)
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "pod.yaml"), podYAML, 0o644))

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	cache, errs := ParseDir(tmpDir)
	require.Empty(t, errs)
	pods := cache.List(podGVR)
	assert.Len(t, pods, 1)
	assert.Equal(t, "nested-pod", pods[0].GetName())
}
