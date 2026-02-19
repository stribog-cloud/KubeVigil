package helpers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// FixturesDir returns the absolute path to the test/fixtures directory.
func FixturesDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile = .../test/helpers/fixture_loader.go
	// project root = .../
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(projectRoot, "test", "fixtures")
}

// LoadFixtureRaw reads a fixture file and returns its raw bytes.
func LoadFixtureRaw(t *testing.T, checkID, filename string) []byte {
	t.Helper()
	path := filepath.Join(FixturesDir(), checkID, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("loading fixture %s/%s: %v", checkID, filename, err)
	}
	return data
}

// LoadFixture parses a single YAML fixture file into a ResourceCache.
// Handles multi-document YAML files (separated by ---).
func LoadFixture(t *testing.T, checkID, filename string) *checker.ResourceCache {
	t.Helper()
	data := LoadFixtureRaw(t, checkID, filename)
	cache := checker.NewResourceCache()
	parseYAMLIntoCache(t, data, cache)
	return cache
}

// LoadFixtureDir loads all YAML files from a check's fixture directory into a ResourceCache.
func LoadFixtureDir(t *testing.T, checkID string) *checker.ResourceCache {
	t.Helper()
	dir := filepath.Join(FixturesDir(), checkID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading fixture dir %s: %v", checkID, err)
	}

	cache := checker.NewResourceCache()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading fixture %s/%s: %v", checkID, name, err)
		}
		parseYAMLIntoCache(t, data, cache)
	}
	return cache
}

// parseYAMLIntoCache parses potentially multi-document YAML into a ResourceCache.
func parseYAMLIntoCache(t *testing.T, data []byte, cache *checker.ResourceCache) {
	t.Helper()

	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading YAML document: %v", err)
		}

		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		// Convert YAML to JSON for unstructured parsing.
		jsonData, err := yaml.ToJSON(doc)
		if err != nil {
			t.Fatalf("converting YAML to JSON: %v", err)
		}

		var obj unstructured.Unstructured
		if err := json.Unmarshal(jsonData, &obj.Object); err != nil {
			t.Fatalf("unmarshaling JSON to unstructured: %v", err)
		}

		if len(obj.Object) == 0 {
			continue
		}

		apiVersion := obj.GetAPIVersion()
		kind := obj.GetKind()
		if apiVersion == "" || kind == "" {
			continue
		}

		gvr, err := checker.GVRForKind(apiVersion, kind)
		if err != nil {
			t.Fatalf("resolving GVR for %s/%s: %v", apiVersion, kind, err)
		}

		cache.Add(gvr, obj)
	}
}
