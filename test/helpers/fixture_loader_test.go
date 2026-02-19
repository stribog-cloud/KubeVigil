package helpers

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestFixturesDir(t *testing.T) {
	dir := FixturesDir()
	assert.NotEmpty(t, dir)
	assert.True(t, filepath.IsAbs(dir), "FixturesDir should return absolute path")
	assert.Contains(t, dir, "test/fixtures")
}

func TestLoadFixtureRaw(t *testing.T) {
	t.Run("loads existing file", func(t *testing.T) {
		data := LoadFixtureRaw(t, "test-helper", "simple-pod.yaml")
		assert.Contains(t, string(data), "simple-pod")
		assert.Contains(t, string(data), "apiVersion: v1")
	})
}

func TestLoadFixture(t *testing.T) {
	t.Run("loads single pod YAML into ResourceCache", func(t *testing.T) {
		cache := LoadFixture(t, "test-helper", "simple-pod.yaml")
		require.NotNil(t, cache)

		podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
		pods := cache.List(podGVR)
		require.Len(t, pods, 1)
		assert.Equal(t, "simple-pod", pods[0].GetName())
		assert.Equal(t, "default", pods[0].GetNamespace())
	})
}

func TestLoadFixtureDir(t *testing.T) {
	t.Run("loads all YAML files from directory", func(t *testing.T) {
		cache := LoadFixtureDir(t, "test-helper")
		require.NotNil(t, cache)
		assert.Greater(t, cache.Len(), 0)
	})
}
