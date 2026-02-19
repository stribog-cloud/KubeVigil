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
func ComputeSummary(result *checker.ScanResult, cfg ...*config.Config) ExecutiveSummary {
	findings := result.Findings
	counts := countBySeverity(findings)

	// Resolve config (variadic for backwards compatibility).
	var scanCfg *config.Config
	if len(cfg) > 0 {
		scanCfg = cfg[0]
	}
	if scanCfg == nil {
		scanCfg = config.Default()
	}

	// Posture score: weighted check pass rate.
	// Each check contributes to the score based on whether it passed (no findings)
	// and the severity of its findings if it failed:
	//   - Clean check (no findings):         100 points
	//   - Check with only Low/Info findings:   60 points
	//   - Check with Medium findings:          30 points
	//   - Check with High findings:            10 points
	//   - Check with Critical findings:         0 points
	// Score = average of all check scores. If no checks ran, score is 0.
	score := computePostureScore(findings, result.ScanMeta.ChecksRun)

	// Top risks: up to 5, sorted by severity descending.
	sorted := make([]checker.Finding, len(findings))
	copy(sorted, findings)
	sortFindings(sorted)
	topN := min(5, len(sorted))
	topRisks := sorted[:topN]

	// Unique resources, namespaces, and namespace classification.
	resources := make(map[string]struct{})
	namespaces := make(map[string]struct{})
	appNS := make(map[string]struct{})
	infraNS := make(map[string]struct{})
	appCounts := make(map[checker.Severity]int)
	infraCounts := make(map[checker.Severity]int)
	clusterCounts := make(map[checker.Severity]int)

	for i := range findings {
		key := findings[i].Namespace + "/" + findings[i].Kind + "/" + findings[i].Resource
		resources[key] = struct{}{}
		if findings[i].Namespace != "" {
			namespaces[findings[i].Namespace] = struct{}{}
		}

		// Classify and aggregate by namespace type.
		nsType := config.ClassifyNamespace(scanCfg, findings[i].Namespace)
		switch nsType {
		case config.NamespaceApplication:
			appCounts[findings[i].Severity]++
			appNS[findings[i].Namespace] = struct{}{}
		case config.NamespaceInfrastructure:
			infraCounts[findings[i].Severity]++
			infraNS[findings[i].Namespace] = struct{}{}
		case config.NamespaceClusterScoped:
			clusterCounts[findings[i].Severity]++
		}
	}

	// Check coverage: count unique checkers that produced findings.
	checkersWithFindings := make(map[string]struct{})
	for i := range findings {
		checkersWithFindings[findings[i].Checker] = struct{}{}
	}

	coverage := CheckCoverage{
		TotalRun:     result.ScanMeta.ChecksRun,
		Skipped:      result.ScanMeta.ChecksSkipped,
		Errored:      result.ScanMeta.ChecksErrored,
		WithFindings: len(checkersWithFindings),
		Clean:        result.ScanMeta.ChecksRun - len(checkersWithFindings),
	}
	// Clean can't be negative if checksRun is somehow less than checkers with findings.
	if coverage.Clean < 0 {
		coverage.Clean = 0
	}

	// Check aggregation: group findings by checker.
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
	for i := range findings {
		name := findings[i].Checker
		agg, ok := aggMap[name]
		if !ok {
			agg = &aggData{
				severity:   findings[i].Severity,
				resources:  make(map[string]struct{}),
				namespaces: make(map[string]struct{}),
			}
			aggMap[name] = agg
		}
		agg.count++
		resKey := findings[i].Namespace + "/" + findings[i].Kind + "/" + findings[i].Resource
		agg.resources[resKey] = struct{}{}
		if findings[i].Namespace != "" {
			agg.namespaces[findings[i].Namespace] = struct{}{}
		}
		// Per-tier counts.
		nsType := config.ClassifyNamespace(scanCfg, findings[i].Namespace)
		switch nsType {
		case config.NamespaceApplication:
			agg.appCount++
		case config.NamespaceInfrastructure:
			agg.infraCount++
		case config.NamespaceClusterScoped:
			agg.clusterCount++
		}
	}
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

	// Compute passed checks: checks that ran but produced no findings.
	var passedChecks []string
	for _, name := range result.ScanMeta.CheckNames {
		if _, hasFinding := checkersWithFindings[name]; !hasFinding {
			passedChecks = append(passedChecks, name)
		}
	}
	sort.Strings(passedChecks)

	// Compute per-tier posture scores by filtering findings per tier.
	var appFindings, infraFindings []checker.Finding
	for i := range findings {
		nsType := config.ClassifyNamespace(scanCfg, findings[i].Namespace)
		switch nsType {
		case config.NamespaceApplication:
			appFindings = append(appFindings, findings[i])
		case config.NamespaceInfrastructure:
			infraFindings = append(infraFindings, findings[i])
		}
	}
	appScore := computeTierPostureScore(appFindings, result.ScanMeta.ChecksRun)
	infraScore := computeTierPostureScore(infraFindings, result.ScanMeta.ChecksRun)

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

// computePostureScore calculates a 0–100 posture score based on weighted
// check pass rates. Each check gets a score based on its worst finding
// severity, and the overall score is the average across all checks.
//
// Per-check scores:
//   - No findings (clean):  100 points
//   - Low/Info only:         60 points
//   - Medium (worst):        30 points
//   - High (worst):          10 points
//   - Critical (worst):       0 points
//
// Overall score = sum(check_scores) / total_checks.
func computePostureScore(findings []checker.Finding, checksRun int) int {
	if checksRun == 0 {
		return 0
	}

	// Find the worst severity per check.
	worstSeverity := make(map[string]checker.Severity)
	for i := range findings {
		name := findings[i].Checker
		if cur, ok := worstSeverity[name]; !ok || findings[i].Severity > cur {
			worstSeverity[name] = findings[i].Severity
		}
	}

	// Score each check.
	totalScore := 0
	checksWithFindings := len(worstSeverity)
	cleanChecks := max(0, checksRun-checksWithFindings)
	totalScore += cleanChecks * 100

	for _, sev := range worstSeverity {
		switch {
		case sev >= checker.SeverityCritical:
			totalScore += 0
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

// computeTierPostureScore computes a posture score for a subset of findings
// (e.g., only app-tier or infra-tier). It uses the same check count as the
// overall score so that tiers with fewer failing checks score higher.
func computeTierPostureScore(findings []checker.Finding, checksRun int) int {
	return computePostureScore(findings, checksRun)
}
