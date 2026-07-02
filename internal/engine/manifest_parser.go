// Package engine provides the scan orchestration and manifest parsing logic.
package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ParsePath parses a file or directory at the given path into a ResourceCache.
// If the path is a directory, it recursively walks all YAML files.
// Returns the populated cache and any non-fatal errors encountered.
func ParsePath(path string) (*checker.ResourceCache, []error) {
	info, err := os.Stat(path)
	if err != nil {
		return checker.NewResourceCache(), []error{fmt.Errorf("stat %s: %w", path, err)}
	}

	if info.IsDir() {
		return ParseDir(path)
	}
	return ParseFile(path)
}

// maxManifestFileSize is the maximum allowed size for a single YAML manifest file (10 MiB).
const maxManifestFileSize = 10 << 20

// ParseFile parses a single YAML file into a ResourceCache.
// Handles multi-document YAML files (separated by ---).
// Rejects files larger than maxManifestFileSize to prevent resource exhaustion.
func ParseFile(path string) (*checker.ResourceCache, []error) {
	info, err := os.Stat(path)
	if err != nil {
		return checker.NewResourceCache(), []error{fmt.Errorf("reading %s: %w", path, err)}
	}
	if info.Size() > maxManifestFileSize {
		return checker.NewResourceCache(), []error{
			fmt.Errorf("reading %s: file size %d bytes exceeds maximum of %d bytes",
				path, info.Size(), maxManifestFileSize),
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return checker.NewResourceCache(), []error{fmt.Errorf("reading %s: %w", path, err)}
	}
	return ParseBytes(data)
}

// ParseDir recursively walks a directory and parses all YAML files into a ResourceCache.
// Non-YAML files are skipped. Malformed files produce errors but do not stop processing.
func ParseDir(dir string) (*checker.ResourceCache, []error) {
	cache := checker.NewResourceCache()
	var errs []error

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("walking %s: %w", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		fi, fiErr := d.Info()
		if fiErr != nil {
			errs = append(errs, fmt.Errorf("stat %s: %w", path, fiErr))
			return nil
		}
		if fi.Size() > maxManifestFileSize {
			errs = append(errs, fmt.Errorf("reading %s: file size %d bytes exceeds maximum of %d bytes",
				path, fi.Size(), maxManifestFileSize))
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // WalkDir callback; caller-supplied scan root; size bounded above.
		if readErr != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", path, readErr))
			return nil
		}

		parseErrs := parseYAMLBytes(data, cache)
		for _, e := range parseErrs {
			errs = append(errs, fmt.Errorf("%s: %w", path, e))
		}
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("walking directory %s: %w", dir, err))
	}

	return cache, errs
}

// ParseBytes parses raw YAML bytes into a ResourceCache.
// Handles multi-document YAML (separated by ---).
func ParseBytes(data []byte) (*checker.ResourceCache, []error) {
	cache := checker.NewResourceCache()
	if len(data) == 0 {
		return cache, nil
	}
	errs := parseYAMLBytes(data, cache)
	return cache, errs
}

// maxDocumentCount is the maximum number of YAML documents allowed in a single file.
// Combined with the 10 MiB file size limit, this prevents excessive memory use
// from files with many tiny documents.
const maxDocumentCount = 10000

// parseYAMLBytes parses potentially multi-document YAML into an existing ResourceCache.
func parseYAMLBytes(data []byte, cache *checker.ResourceCache) []error {
	var errs []error

	docCount := 0
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("reading YAML document: %w", err))
			break
		}

		docCount++
		if docCount > maxDocumentCount {
			errs = append(errs, fmt.Errorf("YAML contains more than %d documents, stopping", maxDocumentCount))
			break
		}

		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		jsonData, err := yaml.ToJSON(doc)
		if err != nil {
			errs = append(errs, fmt.Errorf("converting YAML to JSON: %w", err))
			continue
		}

		var obj unstructured.Unstructured
		if err := json.Unmarshal(jsonData, &obj.Object); err != nil {
			errs = append(errs, fmt.Errorf("unmarshaling to unstructured: %w", err))
			continue
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
			errs = append(errs, fmt.Errorf("resolving GVR for %s/%s: %w", apiVersion, kind, err))
			continue
		}

		cache.Add(gvr, obj)
	}

	return errs
}
