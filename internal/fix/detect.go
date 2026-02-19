package fix

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DetectHelmManaged checks plan files for Helm-managed resources.
// It inspects each file's OriginalContent for Kubernetes resources that have
// Helm management labels (app.kubernetes.io/managed-by: Helm or any helm.sh/ label).
// Returns file paths that contain at least one Helm-managed resource, sorted
// for deterministic output.
func DetectHelmManaged(plan *Plan) []string {
	if plan == nil || len(plan.Files) == 0 {
		return nil
	}

	// Sort file paths for deterministic iteration order.
	paths := make([]string, 0, len(plan.Files))
	for p := range plan.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	seen := make(map[string]bool)
	var result []string

	for _, p := range paths {
		fp := plan.Files[p]
		if fp == nil || len(fp.OriginalContent) == 0 {
			continue
		}

		if seen[p] {
			continue
		}

		docs, err := ParseDocuments(fp.OriginalContent)
		if err != nil {
			slog.Debug("detect: error parsing YAML for Helm detection",
				"file", p,
				"error", err,
			)
			continue
		}

		if hasHelmLabels(docs) {
			seen[p] = true
			result = append(result, p)
		}
	}

	return result
}

// hasHelmLabels checks whether any document in the slice contains Helm management labels.
func hasHelmLabels(docs []*Document) bool {
	for _, doc := range docs {
		if doc == nil || doc.Node == nil {
			continue
		}

		labelsNode, err := FindNode(doc.Node, "metadata.labels")
		if err != nil {
			slog.Debug("detect: error finding metadata.labels", "error", err)
			continue
		}
		if labelsNode == nil {
			continue
		}

		if labelsNode.Kind != yaml.MappingNode {
			continue
		}

		// Iterate key-value pairs in the labels mapping.
		for i := 0; i < len(labelsNode.Content)-1; i += 2 {
			key := labelsNode.Content[i].Value
			val := labelsNode.Content[i+1].Value

			// Check for app.kubernetes.io/managed-by: Helm (case-insensitive value).
			if key == "app.kubernetes.io/managed-by" && strings.EqualFold(val, "Helm") {
				return true
			}

			// Check for any helm.sh/ prefixed label key.
			if strings.HasPrefix(key, "helm.sh/") {
				return true
			}
		}
	}

	return false
}

// DetectKustomize checks paths for Kustomize configuration files.
// For each path, if it is a directory, it checks for kustomization.yaml or
// kustomization.yml within it. If it is a file, it checks the parent directory.
// Returns unique directory paths that contain a kustomization file, sorted
// for deterministic output.
func DetectKustomize(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var result []string

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			slog.Debug("detect: error stating path for Kustomize detection",
				"path", p,
				"error", err,
			)
			continue
		}

		var dir string
		if info.IsDir() {
			dir = p
		} else {
			dir = filepath.Dir(p)
		}

		if seen[dir] {
			continue
		}

		if hasKustomizationFile(dir) {
			seen[dir] = true
			result = append(result, dir)
		}
	}

	sort.Strings(result)
	return result
}

// hasKustomizationFile checks whether the given directory contains a
// kustomization.yaml or kustomization.yml file.
func hasKustomizationFile(dir string) bool {
	for _, name := range []string{"kustomization.yaml", "kustomization.yml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}
