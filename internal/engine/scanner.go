// Package engine provides the scan orchestration and manifest parsing logic.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/k8s"
)

// Scanner orchestrates security scans by coordinating checkers, resource loading,
// configuration, and result collection.
type Scanner struct {
	registry *checker.Registry
	config   *config.Config
}

// NewScanner creates a Scanner with the given checker registry and configuration.
func NewScanner(registry *checker.Registry, cfg *config.Config) *Scanner {
	return &Scanner{
		registry: registry,
		config:   cfg,
	}
}

// ScanManifest scans YAML manifests at the given path (file or directory).
func (s *Scanner) ScanManifest(ctx context.Context, path string) (*checker.ScanResult, error) {
	start := time.Now()

	enabled := s.enabledChecks(checker.ScanModeManifest)

	cache, parseErrs := ParsePath(path)
	for _, err := range parseErrs {
		slog.Warn("manifest parse error", "error", err)
	}
	if cache.Len() == 0 && len(parseErrs) > 0 {
		return nil, fmt.Errorf("scanning manifests at %s: %w", path, parseErrs[0])
	}

	annotations := collectAnnotations(cache)
	findings, errCount := s.runChecks(ctx, enabled, cache)
	findings = s.applySeverityOverrides(findings)
	findings = config.FilterFindings(findings, s.config.Exemptions, annotations)

	skipped := s.registry.Len() - len(enabled)

	return &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			StartTime:     start,
			Duration:      time.Since(start),
			ChecksRun:     len(enabled),
			ChecksSkipped: skipped,
			ChecksErrored: errCount,
			ScanMode:      checker.ScanModeManifest,
		},
	}, nil
}

// ScanLive scans a running Kubernetes cluster.
func (s *Scanner) ScanLive(ctx context.Context, client dynamic.Interface, disc discovery.DiscoveryInterface) (*checker.ScanResult, error) {
	start := time.Now()

	enabled := s.enabledChecks(checker.ScanModeLive)
	gvrs := collectGVRs(enabled)

	cache, skippedGVRs := k8s.FetchResources(ctx, client, gvrs)
	for _, sr := range skippedGVRs {
		slog.Warn("skipped resource", "gvr", sr.GVR, "error", sr.Error)
	}

	enabled, _ = filterByAvailableGVRs(enabled, skippedGVRs)

	annotations := collectAnnotations(cache)
	findings, errCount := s.runChecks(ctx, enabled, cache)
	findings = s.applySeverityOverrides(findings)
	findings = config.FilterFindings(findings, s.config.Exemptions, annotations)

	version, err := k8s.ClusterVersion(disc)
	if err != nil {
		slog.Warn("could not get cluster version", "error", err)
	}

	return &checker.ScanResult{
		Findings: findings,
		ClusterInfo: checker.ClusterInfo{
			ServerVersion: version,
		},
		ScanMeta: checker.ScanMeta{
			StartTime:     start,
			Duration:      time.Since(start),
			ChecksRun:     len(enabled),
			ChecksSkipped: s.registry.Len() - len(enabled),
			ChecksErrored: errCount,
			ScanMode:      checker.ScanModeLive,
		},
	}, nil
}

// enabledChecks returns checkers that support the given mode and are not disabled in config.
func (s *Scanner) enabledChecks(mode checker.ScanMode) []checker.Checker {
	var enabled []checker.Checker
	for _, c := range s.registry.All() {
		if config.IsCheckDisabled(s.config, c.Name()) {
			continue
		}
		if supportsMode(c, mode) {
			enabled = append(enabled, c)
		}
	}
	return enabled
}

// supportsMode returns true if the checker supports the given scan mode.
func supportsMode(c checker.Checker, mode checker.ScanMode) bool {
	for _, m := range c.SupportedModes() {
		if m == mode {
			return true
		}
	}
	return false
}

// collectGVRs returns the deduplicated union of RequiredResources from all checks.
func collectGVRs(checks []checker.Checker) []schema.GroupVersionResource {
	seen := make(map[schema.GroupVersionResource]bool)
	var gvrs []schema.GroupVersionResource
	for _, c := range checks {
		for _, gvr := range c.RequiredResources() {
			if !seen[gvr] {
				seen[gvr] = true
				gvrs = append(gvrs, gvr)
			}
		}
	}
	return gvrs
}

// runChecks executes all checks concurrently using errgroup.
// Individual checker errors are non-fatal: they are logged and counted.
// Returns the collected findings and the number of checks that errored.
func (s *Scanner) runChecks(ctx context.Context, checks []checker.Checker, cache *checker.ResourceCache) (allFindings []checker.Finding, errCount int) {
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.config.Settings.Concurrency)

	for _, c := range checks {
		g.Go(func() error {
			result, err := c.Run(gctx, cache)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Warn("checker error", "checker", c.Name(), "error", err)
				errCount++
				return nil // non-fatal
			}
			allFindings = append(allFindings, result...)
			return nil
		})
	}

	_ = g.Wait() // errors are already handled per-checker
	return allFindings, errCount
}

// applySeverityOverrides replaces severity on findings where the config has an override.
func (s *Scanner) applySeverityOverrides(findings []checker.Finding) []checker.Finding {
	result := make([]checker.Finding, len(findings))
	for i := range findings {
		result[i] = findings[i]
		if sev, ok := config.SeverityOverride(s.config, findings[i].Checker); ok {
			parsed, err := checker.ParseSeverity(sev)
			if err == nil {
				result[i].Severity = parsed
			}
		}
	}
	return result
}

// collectAnnotations builds a map from ExemptionKey to resource annotations.
func collectAnnotations(cache *checker.ResourceCache) map[string]map[string]string {
	annotations := make(map[string]map[string]string)
	for _, gvr := range cache.GVRs() {
		for _, obj := range cache.List(gvr) {
			key := config.ExemptionKey(obj.GetNamespace(), obj.GetKind(), obj.GetName())
			if a := obj.GetAnnotations(); len(a) > 0 {
				annotations[key] = a
			}
		}
	}
	return annotations
}

// filterByAvailableGVRs removes checks that require any skipped GVR.
// Returns the filtered checks and the count of checks removed.
func filterByAvailableGVRs(checks []checker.Checker, skipped []k8s.SkippedResource) (filtered []checker.Checker, removedCount int) {
	if len(skipped) == 0 {
		return checks, 0
	}

	skippedSet := make(map[schema.GroupVersionResource]bool, len(skipped))
	for _, sr := range skipped {
		skippedSet[sr.GVR] = true
	}

	for _, c := range checks {
		needsSkipped := false
		for _, gvr := range c.RequiredResources() {
			if skippedSet[gvr] {
				needsSkipped = true
				break
			}
		}
		if needsSkipped {
			removedCount++
			slog.Info("skipping checker due to unavailable resources", "checker", c.Name())
		} else {
			filtered = append(filtered, c)
		}
	}
	return filtered, removedCount
}
