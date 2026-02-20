package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
	"github.com/stribog-cloud/kubevigil/internal/k8s"
)

// maxInputPathLen is the maximum length for user-supplied paths in MCP inputs.
const maxInputPathLen = 4096

// handleScanCluster scans a live Kubernetes cluster and returns a summary.
func (kv *KubeVigilMCP) handleScanCluster(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input ScanClusterInput, //nolint:gocritic // value required by MCP SDK ToolHandlerFor signature
) (*mcp.CallToolResult, ScanSummaryOutput, error) {
	if err := validateKubeconfig(input.Kubeconfig); err != nil {
		return nil, ScanSummaryOutput{}, fmt.Errorf("scan_cluster: %w", err)
	}

	cfg := kv.configWithOverrides(input.Severity, input.Framework, input.ExcludeInfra, input.Namespace)
	scanner := engine.NewScanner(kv.registry, cfg)

	dynClient, discClient, err := k8s.NewClient(input.Kubeconfig, input.Context)
	if err != nil {
		return nil, ScanSummaryOutput{}, fmt.Errorf("scan_cluster: connecting to cluster: %w", err)
	}

	result, err := scanner.ScanLive(ctx, dynClient, discClient)
	if err != nil {
		return nil, ScanSummaryOutput{}, fmt.Errorf("scan_cluster: running scan: %w", err)
	}

	result.Findings = applyFilters(result.Findings, cfg, input.Namespace, input.Severity, input.Framework)

	kv.mu.Lock()
	kv.lastResult = result
	kv.mu.Unlock()

	return nil, buildSummary(result), nil
}

// handleScanManifests scans YAML manifests at a path and returns a summary.
func (kv *KubeVigilMCP) handleScanManifests(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input ScanManifestsInput,
) (*mcp.CallToolResult, ScanSummaryOutput, error) {
	if input.Path == "" {
		return nil, ScanSummaryOutput{}, fmt.Errorf("scan_manifests: path is required")
	}
	cleanPath, err := validateManifestPath(input.Path)
	if err != nil {
		return nil, ScanSummaryOutput{}, fmt.Errorf("scan_manifests: %w", err)
	}

	cfg := kv.configWithOverrides(input.Severity, input.Framework, false, "")
	scanner := engine.NewScanner(kv.registry, cfg)

	result, err := scanner.ScanManifest(ctx, cleanPath)
	if err != nil {
		return nil, ScanSummaryOutput{}, fmt.Errorf("scan_manifests: scanning path %q: %w", input.Path, err)
	}

	result.Findings = applyFilters(result.Findings, cfg, "", input.Severity, input.Framework)

	kv.mu.Lock()
	kv.lastResult = result
	kv.mu.Unlock()

	return nil, buildSummary(result), nil
}

// configWithOverrides returns a shallow copy of the base config with MCP input
// overrides applied. The original config is not modified.
func (kv *KubeVigilMCP) configWithOverrides(severity, framework string, excludeInfra bool, namespace string) *config.Config {
	// Shallow copy — we only modify scalar fields in Settings.
	cfg := *kv.config
	cfg.Settings = kv.config.Settings

	if severity != "" {
		cfg.Settings.SeverityThreshold = severity
	}
	if excludeInfra {
		cfg.Settings.ExcludeInfra = true
	}
	// Namespace filtering is done post-scan in applyFilters, not in config.
	_ = namespace
	_ = framework
	return &cfg
}

// applyFilters applies the standard filtering pipeline to findings:
// severity threshold, system namespace exclusion, infra namespace exclusion,
// namespace restriction, and framework filtering.
func applyFilters(findings []checker.Finding, cfg *config.Config, namespace, severity, framework string) []checker.Finding {
	// Severity threshold filter.
	if severity != "" && !strings.EqualFold(severity, "info") {
		threshold, err := checker.ParseSeverity(severity)
		if err == nil {
			filtered := findings[:0:0]
			for i := range findings {
				if findings[i].Severity >= threshold {
					filtered = append(filtered, findings[i])
				}
			}
			findings = filtered
		}
	}

	// Exclude system namespaces by default.
	if !cfg.Settings.IncludeSystemNamespaces {
		filtered := findings[:0:0]
		for i := range findings {
			if !config.IsSystemNamespace(findings[i].Namespace) {
				filtered = append(filtered, findings[i])
			}
		}
		findings = filtered
	}

	// Exclude infrastructure namespaces if requested.
	if cfg.Settings.ExcludeInfra {
		filtered := findings[:0:0]
		for i := range findings {
			if !config.IsInfraNamespace(cfg, findings[i].Namespace) {
				filtered = append(filtered, findings[i])
			}
		}
		findings = filtered
	}

	// Namespace restriction.
	if namespace != "" {
		filtered := findings[:0:0]
		for i := range findings {
			if findings[i].Namespace == namespace {
				filtered = append(filtered, findings[i])
			}
		}
		findings = filtered
	}

	// Framework filter.
	if framework != "" {
		findings = frameworks.FilterByFramework(findings, framework)
	}

	return findings
}

// buildSummary constructs a ScanSummaryOutput from a scan result in O(n).
func buildSummary(result *checker.ScanResult) ScanSummaryOutput {
	summary := ScanSummaryOutput{
		Cluster:        result.ClusterInfo.ContextName,
		ServerVersion:  result.ClusterInfo.ServerVersion,
		NodeCount:      result.ClusterInfo.NodeCount,
		ChecksRun:      result.ScanMeta.ChecksRun,
		ChecksErrored:  result.ScanMeta.ChecksErrored,
		TotalFindings:  len(result.Findings),
		SeverityCounts: make(map[string]int),
		CategoryCounts: make(map[string]int),
	}

	// Single pass over findings for severity, category, and per-checker counts.
	checkerCounts := make(map[string]int)
	checkerSeverity := make(map[string]string)
	for i := range result.Findings {
		f := &result.Findings[i]
		sevName := f.Severity.String()
		summary.SeverityCounts[sevName]++

		// Use the check-to-category mapping from scan metadata.
		if cat, ok := result.ScanMeta.CheckCategories[f.Checker]; ok {
			summary.CategoryCounts[cat]++
		}

		checkerCounts[f.Checker]++
		if _, exists := checkerSeverity[f.Checker]; !exists {
			checkerSeverity[f.Checker] = sevName
		}
	}

	// Build top issues sorted by count descending, limited to 10.
	type checkerCount struct {
		name  string
		count int
	}
	pairs := make([]checkerCount, 0, len(checkerCounts))
	for name, count := range checkerCounts {
		pairs = append(pairs, checkerCount{name, count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].name < pairs[j].name
	})
	limit := 10
	if len(pairs) < limit {
		limit = len(pairs)
	}
	summary.TopIssues = make([]TopIssue, limit)
	for i := 0; i < limit; i++ {
		summary.TopIssues[i] = TopIssue{
			Checker:  pairs[i].name,
			Severity: checkerSeverity[pairs[i].name],
			Count:    pairs[i].count,
		}
	}

	// Compliance stats: count unique controls per framework from the findings.
	fwControls := make(map[string]map[string]bool)
	for i := range result.Findings {
		for _, ref := range result.Findings[i].Frameworks {
			if fwControls[ref.Framework] == nil {
				fwControls[ref.Framework] = make(map[string]bool)
			}
			fwControls[ref.Framework][ref.ControlID] = true
		}
	}
	if len(fwControls) > 0 {
		summary.ComplianceStats = make(map[string]int, len(fwControls))
		for fw, ids := range fwControls {
			summary.ComplianceStats[fw] = len(ids)
		}
	}

	return summary
}

// validateManifestPath validates and cleans a user-supplied manifest path.
func validateManifestPath(path string) (string, error) {
	if len(path) > maxInputPathLen {
		return "", fmt.Errorf("path exceeds maximum length of %d characters", maxInputPathLen)
	}
	return filepath.Clean(path), nil
}

// validateKubeconfig validates a user-supplied kubeconfig path.
// Empty string is allowed (uses default kubeconfig).
func validateKubeconfig(path string) error {
	if path == "" {
		return nil
	}
	if len(path) > maxInputPathLen {
		return fmt.Errorf("kubeconfig path exceeds maximum length of %d characters", maxInputPathLen)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("kubeconfig path %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("kubeconfig path %q is not a regular file", path)
	}
	return nil
}
