package report

import (
	"sort"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

// NamespaceStats holds severity counts for a namespace tier.
type NamespaceStats struct {
	// Count is the number of namespaces in this tier.
	Count int
	// SeverityCounts maps severity to finding count.
	SeverityCounts map[checker.Severity]int
}

// ExecutiveSummary provides a high-level overview of scan results.
type ExecutiveSummary struct {
	// PostureScore is a 0-100 score where 100 means no findings.
	PostureScore int
	// AppPostureScore is the posture score for application namespaces only.
	AppPostureScore int
	// InfraPostureScore is the posture score for infrastructure namespaces only.
	InfraPostureScore int
	// SeverityCounts maps each severity level to its finding count.
	SeverityCounts map[checker.Severity]int
	// TopRisks contains the top 5 most severe findings.
	TopRisks []checker.Finding
	// UniqueResources is the count of distinct resources with findings.
	UniqueResources int
	// UniqueNamespaces is the count of distinct namespaces with findings.
	UniqueNamespaces int
	// CheckCoverage summarises check execution.
	CheckCoverage CheckCoverage
	// CheckAggregates groups findings by check, sorted by severity then count.
	CheckAggregates []CheckAggregate
	// PassedChecks lists the names of checks that ran with zero findings.
	PassedChecks []string
	// AppStats holds statistics for application namespaces.
	AppStats NamespaceStats
	// InfraStats holds statistics for infrastructure namespaces.
	InfraStats NamespaceStats
	// ClusterScopedCounts holds severity counts for cluster-scoped findings.
	ClusterScopedCounts map[checker.Severity]int
}

// CheckAggregate summarises findings for a single check.
type CheckAggregate struct {
	// Checker is the check name.
	Checker string
	// Severity is the check's severity level.
	Severity checker.Severity
	// Count is the number of findings for this check.
	Count int
	// Resources is the number of unique resources affected.
	Resources int
	// Namespaces is the number of unique namespaces affected.
	Namespaces int
	// AppCount is the finding count from application namespaces.
	AppCount int
	// InfraCount is the finding count from infrastructure namespaces.
	InfraCount int
	// ClusterCount is the finding count from cluster-scoped resources.
	ClusterCount int
}

// CheckCoverage summarises which checks ran and their outcomes.
type CheckCoverage struct {
	TotalRun     int
	Skipped      int
	Errored      int
	WithFindings int
	Clean        int
}

// ComputeSummary derives an executive summary from a scan result.
// The optional cfg parameter enables namespace classification; pass nil for
// default behaviour (all namespaces treated as application).
//
// Performance: uses a single pass over findings to compute severity counts,
// unique resources/namespaces, namespace classification, check aggregation,
// worst severity per check, top-5 risks (via insertion into a small buffer),
// and per-tier findings. ClassifyNamespace results are cached per namespace.
func ComputeSummary(result *checker.ScanResult, cfg ...*config.Config) ExecutiveSummary {
	findings := result.Findings

	// Resolve config (variadic for backwards compatibility).
	var scanCfg *config.Config
	if len(cfg) > 0 {
		scanCfg = cfg[0]
	}
	if scanCfg == nil {
		scanCfg = config.Default()
	}

	// Pre-allocate data structures for the single-pass loop.
	counts := make(map[checker.Severity]int)
	resources := make(map[string]struct{})
	namespaces := make(map[string]struct{})
	appNS := make(map[string]struct{})
	infraNS := make(map[string]struct{})
	appCounts := make(map[checker.Severity]int)
	infraCounts := make(map[checker.Severity]int)
	clusterCounts := make(map[checker.Severity]int)
	checkersWithFindings := make(map[string]struct{})
	worstSeverity := make(map[string]checker.Severity) // for posture score
	appWorstSev := make(map[string]checker.Severity)   // for app tier score
	infraWorstSev := make(map[string]checker.Severity) // for infra tier score

	// Check aggregation data, built in the same loop.
	type aggData struct {
		severity     checker.Severity
		count        int
		appCount     int
		infraCount   int
		clusterCount int
		resources    map[string]struct{}
		namespaces   map[string]struct{}
	}
	aggMap := make(map[string]*aggData)

	// Namespace classification cache: avoids repeated ClassifyNamespace calls
	// for the same namespace.
	nsTypeCache := make(map[string]config.NamespaceType)

	// Top-5 risks buffer: maintained in sorted order (severity desc, namespace
	// asc, resource asc, checker asc) without copying/sorting the full slice.
	var topRisks []checker.Finding

	// --- Single pass over all findings ---
	for i := range findings {
		f := &findings[i]

		// Severity counts.
		counts[f.Severity]++

		// Unique resources and namespaces.
		resKey := f.Namespace + "/" + f.Kind + "/" + f.Resource
		resources[resKey] = struct{}{}
		if f.Namespace != "" {
			namespaces[f.Namespace] = struct{}{}
		}

		// Classify namespace (cached).
		nsType, cached := nsTypeCache[f.Namespace]
		if !cached {
			nsType = config.ClassifyNamespace(scanCfg, f.Namespace)
			nsTypeCache[f.Namespace] = nsType
		}

		// Per-tier severity counts and namespace sets.
		switch nsType {
		case config.NamespaceApplication:
			appCounts[f.Severity]++
			appNS[f.Namespace] = struct{}{}
			// Track worst severity per check for app tier posture score.
			if cur, ok := appWorstSev[f.Checker]; !ok || f.Severity > cur {
				appWorstSev[f.Checker] = f.Severity
			}
		case config.NamespaceInfrastructure:
			infraCounts[f.Severity]++
			infraNS[f.Namespace] = struct{}{}
			// Track worst severity per check for infra tier posture score.
			if cur, ok := infraWorstSev[f.Checker]; !ok || f.Severity > cur {
				infraWorstSev[f.Checker] = f.Severity
			}
		case config.NamespaceClusterScoped:
			clusterCounts[f.Severity]++
		}

		// Unique checkers with findings + worst severity for posture score.
		checkersWithFindings[f.Checker] = struct{}{}
		if cur, ok := worstSeverity[f.Checker]; !ok || f.Severity > cur {
			worstSeverity[f.Checker] = f.Severity
		}

		// Check aggregation.
		agg, ok := aggMap[f.Checker]
		if !ok {
			agg = &aggData{
				severity:   f.Severity,
				resources:  make(map[string]struct{}),
				namespaces: make(map[string]struct{}),
			}
			aggMap[f.Checker] = agg
		}
		agg.count++
		agg.resources[resKey] = struct{}{}
		if f.Namespace != "" {
			agg.namespaces[f.Namespace] = struct{}{}
		}
		switch nsType {
		case config.NamespaceApplication:
			agg.appCount++
		case config.NamespaceInfrastructure:
			agg.infraCount++
		case config.NamespaceClusterScoped:
			agg.clusterCount++
		}

		// Top-5 insertion: maintain a small sorted buffer.
		topRisks = insertTopRisk(topRisks, &findings[i])
	}

	// --- Post-loop computations ---

	// Posture scores computed from the per-check worst severity maps.
	score := scoreFromWorstMap(worstSeverity, result.ScanMeta.ChecksRun)
	appScore := scoreFromWorstMap(appWorstSev, result.ScanMeta.ChecksRun)
	infraScore := scoreFromWorstMap(infraWorstSev, result.ScanMeta.ChecksRun)

	// Check coverage.
	coverage := CheckCoverage{
		TotalRun:     result.ScanMeta.ChecksRun,
		Skipped:      result.ScanMeta.ChecksSkipped,
		Errored:      result.ScanMeta.ChecksErrored,
		WithFindings: len(checkersWithFindings),
		Clean:        result.ScanMeta.ChecksRun - len(checkersWithFindings),
	}
	if coverage.Clean < 0 {
		coverage.Clean = 0
	}

	// Build and sort check aggregates.
	aggregates := make([]CheckAggregate, 0, len(aggMap))
	for name, agg := range aggMap {
		aggregates = append(aggregates, CheckAggregate{
			Checker:      name,
			Severity:     agg.severity,
			Count:        agg.count,
			Resources:    len(agg.resources),
			Namespaces:   len(agg.namespaces),
			AppCount:     agg.appCount,
			InfraCount:   agg.infraCount,
			ClusterCount: agg.clusterCount,
		})
	}
	sort.Slice(aggregates, func(i, j int) bool {
		if aggregates[i].Severity != aggregates[j].Severity {
			return aggregates[i].Severity > aggregates[j].Severity
		}
		if aggregates[i].Count != aggregates[j].Count {
			return aggregates[i].Count > aggregates[j].Count
		}
		return aggregates[i].Checker < aggregates[j].Checker
	})

	// Passed checks: checks that ran but produced no findings.
	var passedChecks []string
	for _, name := range result.ScanMeta.CheckNames {
		if _, hasFinding := checkersWithFindings[name]; !hasFinding {
			passedChecks = append(passedChecks, name)
		}
	}
	sort.Strings(passedChecks)

	return ExecutiveSummary{
		PostureScore:        score,
		AppPostureScore:     appScore,
		InfraPostureScore:   infraScore,
		SeverityCounts:      counts,
		TopRisks:            topRisks,
		UniqueResources:     len(resources),
		UniqueNamespaces:    len(namespaces),
		CheckCoverage:       coverage,
		CheckAggregates:     aggregates,
		PassedChecks:        passedChecks,
		AppStats:            NamespaceStats{Count: len(appNS), SeverityCounts: appCounts},
		InfraStats:          NamespaceStats{Count: len(infraNS), SeverityCounts: infraCounts},
		ClusterScopedCounts: clusterCounts,
	}
}

// insertTopRisk inserts a finding into the top-5 buffer, maintaining sorted
// order (severity descending, then namespace ascending, then resource
// ascending, then checker ascending). The buffer never exceeds 5 elements.
// This avoids copying and sorting the entire findings slice.
func insertTopRisk(buf []checker.Finding, f *checker.Finding) []checker.Finding {
	const maxTop = 5

	// Find the insertion position using the same sort order as sortFindings.
	pos := len(buf)
	for k := range buf {
		if findingLess(f, &buf[k]) {
			pos = k
			break
		}
	}

	if pos >= maxTop {
		// Finding is not in the top 5.
		return buf
	}

	// Insert at position.
	if len(buf) < maxTop {
		buf = append(buf, checker.Finding{})
	}
	copy(buf[pos+1:], buf[pos:])
	buf[pos] = *f

	// Trim to maxTop.
	if len(buf) > maxTop {
		buf = buf[:maxTop]
	}
	return buf
}

// findingLess returns true if a should sort before b, using the same ordering
// as sortFindings: severity descending, namespace ascending, resource
// ascending, checker ascending.
func findingLess(a, b *checker.Finding) bool {
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Resource != b.Resource {
		return a.Resource < b.Resource
	}
	return a.Checker < b.Checker
}

// scoreFromWorstMap computes a posture score from a pre-built map of
// checker name -> worst severity. This avoids re-iterating findings.
func scoreFromWorstMap(worstSev map[string]checker.Severity, checksRun int) int {
	if checksRun == 0 {
		return 0
	}

	checksWithFindings := len(worstSev)
	cleanChecks := max(0, checksRun-checksWithFindings)
	totalScore := cleanChecks * 100

	for _, sev := range worstSev {
		switch {
		case sev >= checker.SeverityCritical:
			// 0 points
		case sev >= checker.SeverityHigh:
			totalScore += 10
		case sev >= checker.SeverityMedium:
			totalScore += 30
		default: // Low, Info
			totalScore += 60
		}
	}

	return totalScore / checksRun
}
