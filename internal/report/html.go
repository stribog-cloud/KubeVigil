package report

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// HTMLReporter writes a self-contained HTML report with collapsible namespace
// sections, severity filtering buttons, and a search box.
type HTMLReporter struct {
	// Config is optional; when set, enables namespace classification.
	Config *config.Config
}

// Name returns "html".
func (r *HTMLReporter) Name() string { return "html" }

// SetConfig sets the config for namespace classification.
func (r *HTMLReporter) SetConfig(cfg *config.Config) { r.Config = cfg }

// Generate writes an HTML report to w.
func (r *HTMLReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)
	counts := countBySeverity(sorted)
	summary := ComputeSummary(result, r.Config)

	cfg := r.Config
	if cfg == nil {
		cfg = config.Default()
	}

	// Collect unique remediations per checker for deduplication.
	remMap := make(map[string]string)           // checker name -> remediation body HTML
	remSev := make(map[string]checker.Severity) // checker name -> worst severity
	for i := range sorted {
		if _, ok := remMap[sorted[i].Checker]; !ok && sorted[i].Remediation != "" {
			remMap[sorted[i].Checker] = formatRemediationBody(sorted[i].Remediation)
		}
		if sorted[i].Severity > remSev[sorted[i].Checker] {
			remSev[sorted[i].Checker] = sorted[i].Severity
		}
	}
	var remEntries []htmlRemediationEntry
	for ch, body := range remMap {
		remEntries = append(remEntries, htmlRemediationEntry{
			Checker:  ch,
			Severity: remSev[ch].String(),
			HTML:     template.HTML(body),
		})
	}
	// Sort remediations by severity weight descending, then alphabetical.
	sort.Slice(remEntries, func(i, j int) bool {
		si := parseSev(remEntries[i].Severity)
		sj := parseSev(remEntries[j].Severity)
		if si != sj {
			return si > sj
		}
		return remEntries[i].Checker < remEntries[j].Checker
	})

	// Collect unique framework refs per checker for the By Check tab.
	fwMap := make(map[string]template.HTML) // checker name -> framework badges HTML
	for i := range sorted {
		if _, ok := fwMap[sorted[i].Checker]; !ok && len(sorted[i].Frameworks) > 0 {
			fwMap[sorted[i].Checker] = formatFrameworksHTML(sorted[i].Frameworks)
		}
	}

	// Build checker description map for tooltips.
	descMap := result.ScanMeta.CheckDescriptions
	if descMap == nil {
		descMap = make(map[string]string)
	}

	// Group by namespace and classify.
	nsGroups := groupByNamespace(sorted)
	namespaces := sortedNamespaces(nsGroups)
	aggregate := !cfg.Settings.NoAggregate

	var appSections, infraSections, clusterSections []htmlSection
	for _, ns := range namespaces {
		label := namespaceSectionLabel(ns)
		if ns == "" {
			label = "Cluster-Scoped"
		}
		nsFindings := nsGroups[ns]
		nsCounts := countBySeverity(nsFindings)
		items := make([]htmlFinding, len(nsFindings))
		for i := range nsFindings {
			items[i] = htmlFinding{
				Severity:       nsFindings[i].Severity.String(),
				Checker:        nsFindings[i].Checker,
				Description:    descMap[nsFindings[i].Checker],
				Resource:       stripNamespacePrefix(formatResource(&nsFindings[i]), ns),
				Container:      nsFindings[i].Container,
				Message:        nsFindings[i].Message,
				HasRemediation: remMap[nsFindings[i].Checker] != "",
				FieldPath:      nsFindings[i].FieldPath,
				Frameworks:     formatFrameworksHTML(nsFindings[i].Frameworks),
			}
		}

		var aggGroups []htmlAggGroup
		if aggregate {
			aggs := aggregateFindings(nsFindings)
			for i := range aggs {
				resources := make([]htmlAggResource, len(aggs[i].Resources))
				for j := range aggs[i].Resources {
					resources[j] = htmlAggResource{
						Name:      stripNamespacePrefix(aggs[i].Resources[j].Name, ns),
						Container: aggs[i].Resources[j].Container,
					}
				}
				aggGroups = append(aggGroups, htmlAggGroup{
					Severity:       aggs[i].Severity.String(),
					Checker:        aggs[i].Checker,
					Description:    descMap[aggs[i].Checker],
					Message:        aggs[i].Message,
					HasRemediation: remMap[aggs[i].Checker] != "",
					Frameworks:     formatFrameworksHTML(aggs[i].Frameworks),
					Count:          len(aggs[i].Resources),
					Resources:      resources,
				})
			}
		}

		section := htmlSection{
			Label:     label,
			Namespace: ns,
			Count:     len(nsFindings),
			Critical:  nsCounts[checker.SeverityCritical],
			High:      nsCounts[checker.SeverityHigh],
			Medium:    nsCounts[checker.SeverityMedium],
			Low:       nsCounts[checker.SeverityLow],
			Info:      nsCounts[checker.SeverityInfo],
			Findings:  items,
			Groups:    aggGroups,
		}

		nsType := config.ClassifyNamespace(cfg, ns)
		switch nsType {
		case config.NamespaceInfrastructure:
			infraSections = append(infraSections, section)
		case config.NamespaceClusterScoped:
			clusterSections = append(clusterSections, section)
		default:
			appSections = append(appSections, section)
		}
	}
	// Sort sections within each tier by severity weight (most critical first).
	sortSectionsBySeverity(appSections)
	sortSectionsBySeverity(infraSections)

	sections := make([]htmlSection, 0, len(appSections)+len(infraSections)+len(clusterSections))
	sections = append(sections, appSections...)
	sections = append(sections, infraSections...)
	sections = append(sections, clusterSections...)

	// SVG gauge: circle with r=45, circumference = 2*pi*45 ≈ 282.74
	const circumference = 282.74
	dashOffset := circumference * (1.0 - float64(summary.PostureScore)/100.0)

	scoreColor := scoreToColor(summary.PostureScore)
	appScoreColor := scoreToColor(summary.AppPostureScore)
	infraScoreColor := scoreToColor(summary.InfraPostureScore)

	appDash := circumference * (1.0 - float64(summary.AppPostureScore)/100.0)
	infraDash := circumference * (1.0 - float64(summary.InfraPostureScore)/100.0)

	// Tier mini-gauges: r=28, circumference = 2*pi*28 ≈ 175.93
	const tierCircumference = 175.93
	appTierDash := tierCircumference * (1.0 - float64(summary.AppPostureScore)/100.0)
	infraTierDash := tierCircumference * (1.0 - float64(summary.InfraPostureScore)/100.0)

	contextName := result.ClusterInfo.ContextName
	appTotal := sumCounts(summary.AppStats.SeverityCounts)
	infraTotal := sumCounts(summary.InfraStats.SeverityCounts)
	clusterTotal := sumCounts(summary.ClusterScopedCounts)
	allAggs := makeHTMLAggregates(summary.CheckAggregates, fwMap, descMap)
	topN := min(10, len(allAggs))

	data := htmlData{
		ToolVersion:       version.Version,
		ContextName:       contextName,
		GeneratedAt:       formatTimestamp(result.ScanMeta.StartTime),
		PostureScore:      summary.PostureScore,
		ScoreColor:        scoreColor,
		ScoreGrade:        scoreToGrade(summary.PostureScore),
		ScoreDashOffset:   dashOffset,
		AppPostureScore:   summary.AppPostureScore,
		AppScoreColor:     appScoreColor,
		AppScoreGrade:     scoreToGrade(summary.AppPostureScore),
		AppScoreDash:      appDash,
		AppTierDash:       appTierDash,
		InfraPostureScore: summary.InfraPostureScore,
		InfraScoreColor:   infraScoreColor,
		InfraScoreGrade:   scoreToGrade(summary.InfraPostureScore),
		InfraScoreDash:    infraDash,
		InfraTierDash:     infraTierDash,
		ServerVersion:     result.ClusterInfo.ServerVersion,
		NodeCount:         result.ClusterInfo.NodeCount,
		ScanMode:          result.ScanMeta.ScanMode.String(),
		Duration:          formatDuration(result.ScanMeta.Duration),
		ChecksRun:         summary.CheckCoverage.TotalRun,
		ChecksWithFind:    summary.CheckCoverage.WithFindings,
		ChecksClean:       summary.CheckCoverage.Clean,
		ChecksSkipped:     summary.CheckCoverage.Skipped,
		ChecksErrored:     summary.CheckCoverage.Errored,
		TotalFindings:     len(sorted),
		FindingsColor:     findingsColor(counts[checker.SeverityCritical], counts[checker.SeverityHigh], counts[checker.SeverityMedium], counts[checker.SeverityLow], counts[checker.SeverityInfo]),
		UniqueResources:   summary.UniqueResources,
		UniqueNamespaces:  summary.UniqueNamespaces,
		Critical:          counts[checker.SeverityCritical],
		High:              counts[checker.SeverityHigh],
		Medium:            counts[checker.SeverityMedium],
		Low:               counts[checker.SeverityLow],
		Info:              counts[checker.SeverityInfo],
		AppSections:       appSections,
		InfraSections:     infraSections,
		ClusterSections:   clusterSections,
		Sections:          sections,
		Aggregates:        allAggs,
		PassedChecks:      summary.PassedChecks,
		AutoExpand:        len(sorted) < 50,
		Aggregate:         aggregate,
		AppStats: htmlNamespaceStats{
			Count:    summary.AppStats.Count,
			Critical: summary.AppStats.SeverityCounts[checker.SeverityCritical],
			High:     summary.AppStats.SeverityCounts[checker.SeverityHigh],
			Medium:   summary.AppStats.SeverityCounts[checker.SeverityMedium],
			Low:      summary.AppStats.SeverityCounts[checker.SeverityLow],
			Info:     summary.AppStats.SeverityCounts[checker.SeverityInfo],
		},
		InfraStats: htmlNamespaceStats{
			Count:    summary.InfraStats.Count,
			Critical: summary.InfraStats.SeverityCounts[checker.SeverityCritical],
			High:     summary.InfraStats.SeverityCounts[checker.SeverityHigh],
			Medium:   summary.InfraStats.SeverityCounts[checker.SeverityMedium],
			Low:      summary.InfraStats.SeverityCounts[checker.SeverityLow],
			Info:     summary.InfraStats.SeverityCounts[checker.SeverityInfo],
		},
		ClusterStats: htmlNamespaceStats{
			Critical: summary.ClusterScopedCounts[checker.SeverityCritical],
			High:     summary.ClusterScopedCounts[checker.SeverityHigh],
			Medium:   summary.ClusterScopedCounts[checker.SeverityMedium],
			Low:      summary.ClusterScopedCounts[checker.SeverityLow],
			Info:     summary.ClusterScopedCounts[checker.SeverityInfo],
		},
		DonutSegments:     computeDonutSegments(counts),
		PassRate:          passRate(summary.CheckCoverage),
		PassRateColor:     pctColor(passRate(summary.CheckCoverage)),
		AppTotal:          appTotal,
		InfraTotal:        infraTotal,
		ClusterTotal:      clusterTotal,
		FrameworkGroups:   buildFrameworkGroups(sorted),
		AppBars:           buildNamespaceBars(appSections, 10),
		InfraBars:         buildNamespaceBars(infraSections, 0),
		ClusterBars:       buildNamespaceBars(clusterSections, 0),
		TopChecks:         allAggs[:topN],
		CategoryStats:     buildCategoryStats(sorted, result.ScanMeta.CheckCategories),
		ComplianceSummary: buildComplianceSummary(buildFrameworkGroups(sorted)),
		ExecSummary:       buildExecSummary(&summary, allAggs),
		Remediations:      remEntries,
		FindingsJSON:      buildFindingsJSON(sorted, result.ScanMeta.CheckCategories),
		CheckerMetaJSON:   buildCheckerMetaJSON(sorted, result.ScanMeta.CheckCategories),
	}

	data.PrintTriage = buildPrintTriage(appSections, infraSections, clusterSections)
	data.PrintAppRows = buildPrintNamespaceRows(appSections, 3)
	data.PrintInfraRows = buildPrintNamespaceRows(infraSections, 3)
	data.PrintClusterRows = buildPrintNamespaceRows(clusterSections, 3)
	nsDetails, wlTrunc := buildPrintNamespaceDetails(appSections, infraSections, clusterSections)
	data.PrintNamespaceDetails = nsDetails
	data.PrintWorkloadsTrunc = wlTrunc
	data.ExecActions = buildExecActions(allAggs, appSections, infraSections, clusterSections)

	return htmlTmpl.Execute(w, data)
}

type htmlData struct {
	ToolVersion           string
	ContextName           string
	GeneratedAt           string
	PostureScore          int
	ScoreColor            string
	ScoreGrade            string
	ScoreDashOffset       float64
	AppPostureScore       int
	AppScoreColor         string
	AppScoreGrade         string
	AppScoreDash          float64
	AppTierDash           float64
	InfraPostureScore     int
	InfraScoreColor       string
	InfraScoreGrade       string
	InfraScoreDash        float64
	InfraTierDash         float64
	ServerVersion         string
	NodeCount             int
	ScanMode              string
	Duration              string
	ChecksRun             int
	ChecksWithFind        int
	ChecksClean           int
	ChecksSkipped         int
	ChecksErrored         int
	TotalFindings         int
	FindingsColor         string
	UniqueResources       int
	UniqueNamespaces      int
	Critical              int
	High                  int
	Medium                int
	Low                   int
	Info                  int
	AppSections           []htmlSection
	InfraSections         []htmlSection
	ClusterSections       []htmlSection
	Sections              []htmlSection
	Aggregates            []htmlAggregate
	PassedChecks          []string
	AutoExpand            bool
	Aggregate             bool
	AppStats              htmlNamespaceStats
	InfraStats            htmlNamespaceStats
	ClusterStats          htmlNamespaceStats
	AppTotal              int
	InfraTotal            int
	ClusterTotal          int
	DonutSegments         []htmlDonutSegment
	PassRate              int
	PassRateColor         string
	FrameworkGroups       []htmlFrameworkGroup
	AppBars               []htmlNamespaceBar
	InfraBars             []htmlNamespaceBar
	ClusterBars           []htmlNamespaceBar
	TopChecks             []htmlAggregate
	CategoryStats         []htmlCategoryStat
	ComplianceSummary     []htmlComplianceSummary
	ExecSummary           string
	ExecActions           []string
	PrintTriage           []htmlPrintNamespaceTriage
	PrintAppRows          []htmlPrintNamespaceRow
	PrintInfraRows        []htmlPrintNamespaceRow
	PrintClusterRows      []htmlPrintNamespaceRow
	PrintNamespaceDetails []htmlPrintNamespaceDetail
	PrintWorkloadsTrunc   int
	Remediations          []htmlRemediationEntry
	FindingsJSON          template.JS
	CheckerMetaJSON       template.JS
}

// htmlPrintNamespaceTriage represents one row in the Namespace Triage table.
type htmlPrintNamespaceTriage struct {
	Rank      int
	Namespace string
	Tier      string // "App", "Infra", "Cluster"
	Total     int
	Critical  int
	High      int
	Medium    int
	Low       int
	Info      int
	Workloads int    // unique Kind/Name resources
	TopIssue  string // checker name of the worst finding
}

// htmlPrintWorkloadFinding represents one finding row within a workload drilldown.
type htmlPrintWorkloadFinding struct {
	Severity  string
	Checker   string
	Container string
	FieldPath string
	Message   string
}

// htmlPrintWorkload groups crit/high findings for one workload.
type htmlPrintWorkload struct {
	Resource string // "Deployment/nginx"
	Total    int
	Critical int
	High     int
	Findings []htmlPrintWorkloadFinding
}

// htmlPrintNamespaceDetail groups workloads within a namespace for the workload drilldown.
type htmlPrintNamespaceDetail struct {
	Namespace string
	Tier      string
	Total     int
	Critical  int
	High      int
	Workloads []htmlPrintWorkload
}

// htmlPrintNamespaceRow is one row in the enhanced namespace summary table.
type htmlPrintNamespaceRow struct {
	Label        string
	Total        int
	Critical     int
	High         int
	Medium       int
	Low          int
	Info         int
	TopWorkloads string // "Deployment/nginx, StatefulSet/redis, ..."
}

// htmlCategoryStat holds finding counts for a check category.
type htmlCategoryStat struct {
	Category  string
	Count     int
	Resources int
	Critical  int
	High      int
	Medium    int
	Low       int
	Info      int
}

// htmlComplianceSummary holds a compact compliance framework summary for the dashboard.
type htmlComplianceSummary struct {
	Framework      string
	ControlsFailed int
	ControlsTotal  int
	Pct            int // percentage of controls passing
	PctColor       string
	PassedCount    int
}

// htmlDonutSegment represents one arc of the severity donut chart.
type htmlDonutSegment struct {
	Color      template.CSS
	DashArray  string
	DashOffset string
}

type htmlNamespaceStats struct {
	Count    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

type htmlAggregate struct {
	Severity     string
	Checker      string
	Description  string
	Count        int
	Resources    int
	AppCount     int
	InfraCount   int
	ClusterCount int
	Frameworks   template.HTML
}

type htmlSection struct {
	Label     string
	Namespace string // raw namespace key for JS data lookup
	Count     int
	Critical  int
	High      int
	Medium    int
	Low       int
	Info      int
	Findings  []htmlFinding
	Groups    []htmlAggGroup
}

type htmlFinding struct {
	Severity       string
	Checker        string
	Description    string
	Resource       string
	Container      string
	Message        string
	HasRemediation bool
	FieldPath      string
	Frameworks     template.HTML
}

type htmlAggGroup struct {
	Severity       string
	Checker        string
	Description    string
	Message        string
	HasRemediation bool
	Frameworks     template.HTML
	Count          int
	Resources      []htmlAggResource
}

// htmlRemediationEntry stores a single remediation body by checker name.
type htmlRemediationEntry struct {
	Checker  string
	Severity string
	HTML     template.HTML
}

type htmlAggResource struct {
	Name      string
	Container string
}

// htmlNamespaceBar represents one row in the namespace bar chart.
type htmlNamespaceBar struct {
	Label    string
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	// Width percentages (0-100) for each segment, relative to max total.
	CritW int
	HighW int
	MedW  int
	LowW  int
	InfoW int
	// Tier is "app", "infra", or "cluster".
	Tier string
}

// htmlFrameworkGroup groups findings by compliance framework.
type htmlFrameworkGroup struct {
	Framework        string
	Controls         []htmlControlGroup
	TotalCtrl        int
	PassedCtrl       int
	PassRate         int
	PassRateColor    string
	PassedControlIDs []string
}

// htmlControlGroup groups findings under a single framework control.
type htmlControlGroup struct {
	ControlID string
	Title     string
	Severity  string
	Count     int
	Resources []string
	Truncated int // number of resources hidden (Count - len(Resources))
}

// maxComplianceResources is the maximum number of resources shown inline
// in compliance tab drilldowns. Lists exceeding this are truncated.
const maxComplianceResources = 10

var htmlTmpl = template.Must(template.Must(template.New("report").Funcs(template.FuncMap{
	"barWidth": func(part, total int) int {
		if total == 0 {
			return 0
		}
		w := 100 * part / total
		if w == 0 && part > 0 {
			w = 1
		}
		return w
	},
	"comma":     formatWithCommas,
	"gradeHint": gradeHint,
}).Parse(`{{define "nsSections"}}{{range .}}
<details class="ns-section" data-ns="{{.Namespace}}" data-label="{{.Label}}" data-count="{{.Count}}" data-sev="{{.Critical}},{{.High}},{{.Medium}},{{.Low}},{{.Info}}" ontoggle="if(this.open)loadNsFindings(this)">
<summary>
<span class="ns-label">{{.Label}}</span>
<span class="ns-count">{{.Count}} findings</span>
<span class="ns-bar">
{{if .Critical}}<span class="bar-seg" style="width:{{barWidth .Critical .Count}}%;background:var(--color-critical)"></span>{{end}}
{{if .High}}<span class="bar-seg" style="width:{{barWidth .High .Count}}%;background:var(--color-high)"></span>{{end}}
{{if .Medium}}<span class="bar-seg" style="width:{{barWidth .Medium .Count}}%;background:var(--color-medium)"></span>{{end}}
{{if .Low}}<span class="bar-seg" style="width:{{barWidth .Low .Count}}%;background:var(--color-low)"></span>{{end}}
{{if .Info}}<span class="bar-seg" style="width:{{barWidth .Info .Count}}%;background:var(--color-info)"></span>{{end}}
</span>
<span class="ns-badges">
{{if .Critical}}<span class="ns-badge critical">{{.Critical}}</span>{{end}}
{{if .High}}<span class="ns-badge high">{{.High}}</span>{{end}}
{{if .Medium}}<span class="ns-badge medium">{{.Medium}}</span>{{end}}
{{if .Low}}<span class="ns-badge low">{{.Low}}</span>{{end}}
{{if .Info}}<span class="ns-badge info">{{.Info}}</span>{{end}}
</span>
</summary>
<div class="finding-cards"></div>
</details>
{{end}}{{end}}

{{define "barChart"}}{{range .}}<div class="bar-row">
<span class="bar-label" title="{{.Label}}">{{.Label}}</span>
<div class="bar-track">
{{if .CritW}}<div class="bar-fill" style="width:{{.CritW}}%;background:var(--color-critical)"></div>{{end}}
{{if .HighW}}<div class="bar-fill" style="width:{{.HighW}}%;background:var(--color-high)"></div>{{end}}
{{if .MedW}}<div class="bar-fill" style="width:{{.MedW}}%;background:var(--color-medium)"></div>{{end}}
{{if .LowW}}<div class="bar-fill" style="width:{{.LowW}}%;background:var(--color-low)"></div>{{end}}
{{if .InfoW}}<div class="bar-fill" style="width:{{.InfoW}}%;background:var(--color-info)"></div>{{end}}
</div>
<span class="bar-total">{{.Total}}</span>
</div>
{{end}}{{end}}`)).Parse(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KubeVigil Scan Report — Stribog IT Solutions</title>
<style>
%s
</style>
</head>
<body>
<nav class="sticky-nav">
<div class="sticky-inner">
<div class="header-brand">
<div class="brand-icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div>
<div><span class="brand-name">KubeVigil</span><span class="brand-subtitle">Cluster Security Intelligence</span></div>
</div>
<div class="nav-spacer"></div>
<button class="nav-btn hide-mobile" onclick="exportCSV()" title="Export CSV">CSV</button>
<button class="nav-btn hide-mobile" onclick="exportJSON()" title="Export JSON">JSON</button>
<button class="nav-btn hide-mobile" onclick="window.print()" title="Print">Print</button>
<button class="nav-btn" onclick="toggleHelp()" title="Keyboard shortcuts">?</button>
{{if .ContextName}}<div class="header-cluster hide-mobile">Cluster: <strong>{{.ContextName}}</strong></div>{{end}}
{{if or .ServerVersion .NodeCount}}<div class="header-meta hide-mobile">{{if .ServerVersion}}K8s {{.ServerVersion}}{{end}}{{if .NodeCount}} · {{.NodeCount}} nodes{{end}}</div>{{end}}
<button class="theme-btn" id="theme-toggle" onclick="toggleDarkMode()" aria-label="Toggle theme"><span class="theme-light">☀︎</span><span class="theme-dark">☾</span></button>
</div>
</nav>

<div class="container">

<div id="dashboard" class="hero-grid">
<div class="hero-card hero-card-score" style="border-top-color:{{.ScoreColor}}">
<div class="hero-label">Posture Score</div>
<div class="hero-row"><span class="hero-number" style="color:{{.ScoreColor}}">{{.PostureScore}}</span><span class="hero-suffix" style="color:{{.ScoreColor}}">/100</span></div>
<div class="hero-bottom"><span class="grade-badge" style="color:{{.ScoreColor}}">Grade {{.ScoreGrade}}</span><span class="hero-hint">{{gradeHint .PostureScore}}</span></div>
</div>
<div class="hero-card" style="border-top-color:{{.FindingsColor}}">
<div class="hero-label">Total Findings</div>
<div class="hero-number" style="color:{{.FindingsColor}}">{{comma .TotalFindings}}</div>
<div class="hero-sev-labels">{{if .Critical}}<span class="sev-label-crit">{{.Critical}} CRITICAL</span>{{end}} {{if .High}}<span class="sev-label-high">{{.High}} HIGH</span>{{end}}</div>
<div class="sev-bar">{{if .Critical}}<span class="sev-bar-seg" style="width:{{barWidth .Critical .TotalFindings}}%%;background:var(--color-critical)"></span>{{end}}{{if .High}}<span class="sev-bar-seg" style="width:{{barWidth .High .TotalFindings}}%%;background:var(--color-high)"></span>{{end}}{{if .Medium}}<span class="sev-bar-seg" style="width:{{barWidth .Medium .TotalFindings}}%%;background:var(--color-medium)"></span>{{end}}{{if .Low}}<span class="sev-bar-seg" style="width:{{barWidth .Low .TotalFindings}}%%;background:var(--color-low)"></span>{{end}}{{if .Info}}<span class="sev-bar-seg" style="width:{{barWidth .Info .TotalFindings}}%%;background:var(--color-info)"></span>{{end}}</div>
</div>
<div class="hero-card" style="border-top-color:{{.PassRateColor}}">
<div class="hero-label">Compliance Pass</div>
<div class="hero-number" style="color:{{.PassRateColor}}">{{.PassRate}}%%</div>
<div class="hero-desc">{{.ChecksClean}} of {{.ChecksRun}} control benchmarks successfully verified.</div>
</div>
<div class="hero-card hero-card-detail" style="border-top-color:{{.PassRateColor}}">
<div class="hero-label">Compliance Detail</div>
{{range .ComplianceSummary}}<div class="compliance-row"><span class="compliance-name">{{.Framework}}</span><span class="compliance-pct" style="color:{{.PctColor}}">{{.Pct}}%%</span></div>
{{end}}<div class="hero-scan-time"><svg class="scan-refresh" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> {{.ScanMode}} · {{.Duration}}</div>
</div>
</div>

<div class="print-meta">
<h3 class="print-section-title">Scan Metadata</h3>
<table class="print-table">
<tr><td><strong>Cluster</strong></td><td>{{if .ContextName}}{{.ContextName}}{{else}}&mdash;{{end}}</td><td><strong>K8s Version</strong></td><td>{{if .ServerVersion}}{{.ServerVersion}}{{else}}&mdash;{{end}}</td><td><strong>Nodes</strong></td><td>{{.NodeCount}}</td></tr>
<tr><td><strong>Scan Mode</strong></td><td>{{.ScanMode}}</td><td><strong>Duration</strong></td><td>{{.Duration}}</td><td><strong>Generated</strong></td><td>{{.GeneratedAt}}</td></tr>
<tr><td><strong>Checks Run</strong></td><td>{{.ChecksRun}}</td><td><strong>Clean</strong></td><td>{{.ChecksClean}}</td><td><strong>With Findings</strong></td><td>{{.ChecksWithFind}}</td></tr>
</table>
</div>

{{if .ExecSummary}}<div class="print-exec">
<h3 class="print-section-title">Executive Summary</h3>
<p class="print-exec-text">{{.ExecSummary}}</p>
{{if .ExecActions}}<ul class="print-exec-actions">
{{range .ExecActions}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>{{end}}

{{if .PrintTriage}}<div class="print-triage">
<h3 class="print-section-title">Namespace Triage</h3>
<table class="print-table">
<thead><tr><th>#</th><th>Namespace</th><th>Tier</th><th>Findings</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th><th>Workloads</th><th>Top Issue</th></tr></thead>
<tbody>{{range .PrintTriage}}<tr><td>{{.Rank}}</td><td>{{.Namespace}}</td><td>{{.Tier}}</td><td>{{.Total}}</td><td>{{.Critical}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.Low}}</td><td>{{.Info}}</td><td>{{.Workloads}}</td><td class="mono">{{.TopIssue}}</td></tr>{{end}}</tbody>
</table>
</div>{{end}}

{{if .CategoryStats}}<div class="print-cats">
<h3 class="print-section-title">Findings by Category</h3>
<table class="print-table">
<thead><tr><th>Category</th><th>Total</th><th>Resources</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead>
<tbody>{{range .CategoryStats}}<tr><td>{{.Category}}</td><td>{{.Count}}</td><td>{{.Resources}}</td><td>{{.Critical}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.Low}}</td><td>{{.Info}}</td></tr>{{end}}</tbody>
</table>
</div>{{end}}

<div class="print-ns">
<h3 class="print-section-title">Findings by Namespace</h3>
{{if .PrintAppRows}}<h4>Application Namespaces</h4>
<table class="print-table"><thead><tr><th>Namespace</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Top Workloads</th></tr></thead>
<tbody>{{range .PrintAppRows}}<tr><td>{{.Label}}</td><td>{{.Total}}</td><td>{{.Critical}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.Low}}</td><td>{{.Info}}</td><td class="mono">{{.TopWorkloads}}</td></tr>{{end}}</tbody></table>{{end}}
{{if .PrintInfraRows}}<h4>Infrastructure Namespaces</h4>
<table class="print-table"><thead><tr><th>Namespace</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Top Workloads</th></tr></thead>
<tbody>{{range .PrintInfraRows}}<tr><td>{{.Label}}</td><td>{{.Total}}</td><td>{{.Critical}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.Low}}</td><td>{{.Info}}</td><td class="mono">{{.TopWorkloads}}</td></tr>{{end}}</tbody></table>{{end}}
{{if .PrintClusterRows}}<h4>Cluster-Scoped</h4>
<table class="print-table"><thead><tr><th>Scope</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Top Workloads</th></tr></thead>
<tbody>{{range .PrintClusterRows}}<tr><td>{{.Label}}</td><td>{{.Total}}</td><td>{{.Critical}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.Low}}</td><td>{{.Info}}</td><td class="mono">{{.TopWorkloads}}</td></tr>{{end}}</tbody></table>{{end}}
</div>

<div id="findings" class="explorer">
<div class="explorer-header">
<div>
<h2 class="explorer-title">Vulnerability Explorer</h2>
<p class="explorer-subtitle">Drill down into specific resource misconfigurations and security debt.</p>
</div>
<div class="pill-tabs">
<button class="pill-tab active" data-tab="all-findings" onclick="switchTab(this)">All Findings</button>
<button class="pill-tab" data-tab="by-namespace" onclick="switchTab(this)">By Namespace</button>
<button class="pill-tab" data-tab="by-check" onclick="switchTab(this)">By Check</button>
{{if .FrameworkGroups}}<button class="pill-tab" data-tab="compliance" onclick="switchTab(this)">Compliance</button>{{end}}
</div>
</div>

{{if .Sections}}
<div id="tab-all-findings" class="tab-panel active">
<div class="explorer-toolbar">
<div class="search-wrap">
<svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
<input type="text" id="search" placeholder="Search resources, IDs, or error messages..." oninput="filterAllFindings()">
</div>
<div class="quick-filter">
<span class="qf-label">Quick Filter:</span>
<button class="qf-btn active" data-severity="all" onclick="setQuickFilter(this)">All</button>
<button class="qf-btn qf-critical" data-severity="Critical" onclick="setQuickFilter(this)">Critical</button>
<button class="qf-btn qf-high" data-severity="High" onclick="setQuickFilter(this)">High</button>
<button class="qf-btn qf-others" data-severity="others" onclick="setQuickFilter(this)">Others</button>
</div>
</div>
<div class="table-wrap">
<table class="findings-table">
<thead><tr>
<th class="ft-th">Severity</th>
<th class="ft-th">Security Check &amp; Logic</th>
<th class="ft-th">Resource Origin</th>
<th class="ft-th ft-th-right">Actions</th>
</tr></thead>
<tbody id="findings-tbody"></tbody>
</table>
</div>
<div class="pagination">
<span class="page-info">Showing <span id="page-range">0-0</span> of {{comma .TotalFindings}} findings</span>
<div class="page-btns">
<button class="page-btn" id="prev-page" onclick="prevPage()" disabled>Previous Page</button>
<button class="page-btn" id="next-page" onclick="nextPage()">Next Page</button>
</div>
</div>
</div>

<div id="tab-by-namespace" class="tab-panel" style="padding:24px 32px">
<div class="toolbar">
<input type="text" class="ns-search" placeholder="Search findings..." oninput="filterFindings()" aria-label="Search findings">
<div class="filters">
<button class="filter-btn active" data-severity="all" onclick="toggleSeverity(this)">All</button>
<button class="filter-btn" data-severity="Critical" onclick="toggleSeverity(this)">Critical</button>
<button class="filter-btn" data-severity="High" onclick="toggleSeverity(this)">High</button>
<button class="filter-btn" data-severity="Medium" onclick="toggleSeverity(this)">Medium</button>
<button class="filter-btn" data-severity="Low" onclick="toggleSeverity(this)">Low</button>
<button class="filter-btn" data-severity="Info" onclick="toggleSeverity(this)">Info</button>
</div>
<button class="toggle-btn" id="toggle-all" onclick="toggleAll()">Expand All</button>
<div class="sort-group">
<span class="sort-label">Sort:</span>
<button class="sort-btn active" data-sort="severity" onclick="sortNamespaces(this)">Severity</button>
<button class="sort-btn" data-sort="alpha" onclick="sortNamespaces(this)">A-Z</button>
<button class="sort-btn" data-sort="count" onclick="sortNamespaces(this)">Count</button>
</div>
</div>
{{if .AppSections}}
<details class="tier-section" open>
<summary class="tier-heading">Application Namespaces ({{.AppStats.Count}}) <span class="ns-badges">
{{if .AppStats.Critical}}<span class="ns-badge critical">{{.AppStats.Critical}}</span>{{end}}
{{if .AppStats.High}}<span class="ns-badge high">{{.AppStats.High}}</span>{{end}}
{{if .AppStats.Medium}}<span class="ns-badge medium">{{.AppStats.Medium}}</span>{{end}}
{{if .AppStats.Low}}<span class="ns-badge low">{{.AppStats.Low}}</span>{{end}}
{{if .AppStats.Info}}<span class="ns-badge info">{{.AppStats.Info}}</span>{{end}}
</span></summary>
{{template "nsSections" .AppSections}}
</details>
{{end}}

{{if .InfraSections}}
<details class="tier-section">
<summary class="tier-heading">Infrastructure Namespaces ({{.InfraStats.Count}}) <span class="ns-badges">
{{if .InfraStats.Critical}}<span class="ns-badge critical">{{.InfraStats.Critical}}</span>{{end}}
{{if .InfraStats.High}}<span class="ns-badge high">{{.InfraStats.High}}</span>{{end}}
{{if .InfraStats.Medium}}<span class="ns-badge medium">{{.InfraStats.Medium}}</span>{{end}}
{{if .InfraStats.Low}}<span class="ns-badge low">{{.InfraStats.Low}}</span>{{end}}
{{if .InfraStats.Info}}<span class="ns-badge info">{{.InfraStats.Info}}</span>{{end}}
</span></summary>
{{template "nsSections" .InfraSections}}
</details>
{{end}}

{{if .ClusterSections}}
<details class="tier-section">
<summary class="tier-heading">Cluster-Scoped Resources <span class="ns-badges">
{{if .ClusterStats.Critical}}<span class="ns-badge critical">{{.ClusterStats.Critical}}</span>{{end}}
{{if .ClusterStats.High}}<span class="ns-badge high">{{.ClusterStats.High}}</span>{{end}}
{{if .ClusterStats.Medium}}<span class="ns-badge medium">{{.ClusterStats.Medium}}</span>{{end}}
{{if .ClusterStats.Low}}<span class="ns-badge low">{{.ClusterStats.Low}}</span>{{end}}
{{if .ClusterStats.Info}}<span class="ns-badge info">{{.ClusterStats.Info}}</span>{{end}}
</span></summary>
{{template "nsSections" .ClusterSections}}
</details>
{{end}}

{{if not .AppSections}}{{if not .InfraSections}}{{if not .ClusterSections}}
{{template "nsSections" .Sections}}
{{end}}{{end}}{{end}}
</div>

<div id="tab-by-check" class="tab-panel" style="padding:24px 32px">
{{if or .Aggregates .PassedChecks}}
{{if .Aggregates}}
<table class="data-table sortable">
<thead>
<tr><th data-sort="severity" class="sortable-th">Severity</th><th data-sort="text" class="sortable-th">Check</th><th data-sort="num" class="sortable-th">Total</th><th data-sort="num" class="sortable-th">App</th><th data-sort="num" class="sortable-th">Infra</th><th data-sort="num" class="sortable-th">Cluster</th><th data-sort="num" class="sortable-th">Resources</th><th>Frameworks</th></tr>
</thead>
<tbody>
{{range .Aggregates}}
<tr class="finding-row" data-severity="{{.Severity}}" data-sev-weight="{{.Severity}}"><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td class="mono" title="{{.Description}}">{{.Checker}}</td><td>{{.Count}}</td><td>{{if .AppCount}}{{.AppCount}}{{end}}</td><td>{{if .InfraCount}}{{.InfraCount}}{{end}}</td><td>{{if .ClusterCount}}{{.ClusterCount}}{{end}}</td><td>{{.Resources}}</td><td class="fw">{{.Frameworks}}</td></tr>
{{end}}
</tbody>
</table>
{{end}}
{{if .PassedChecks}}
<details style="margin-top:16px">
<summary><strong>Checks Passed ({{len .PassedChecks}})</strong></summary>
<ul class="passed-list">
{{range .PassedChecks}}<li class="mono">{{.}}</li>
{{end}}</ul>
</details>
{{end}}
{{end}}
</div>

{{if .FrameworkGroups}}
<div id="tab-compliance" class="tab-panel">
{{range .FrameworkGroups}}
<div class="fw-section">
<div class="fw-header">
<h3 class="tier-heading" style="margin:0">{{.Framework}}</h3>
<span class="fw-score" style="color:{{.PassRateColor}}">{{.PassedCtrl}}/{{.TotalCtrl}} passing ({{.PassRate}}%%)</span>
</div>
<table class="data-table fw-table">
<colgroup><col style="width:7%%"><col style="width:10%%"><col style="width:9%%"><col style="width:48%%"><col style="width:26%%"></colgroup>
<thead>
<tr><th scope="col">Status</th><th scope="col">Severity</th><th scope="col">Control</th><th scope="col">Title</th><th scope="col">Resources</th></tr>
</thead>
<tbody>
{{range .Controls}}
<tr class="finding-row" data-severity="{{.Severity}}">
<td><span class="status-fail">FAIL</span></td>
<td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
<td class="mono">{{.ControlID}}</td>
<td>{{.Title}}</td>
<td>{{if eq .Count 1}}{{index .Resources 0}}{{else}}<details class="res-drill"><summary>{{.Count}} resources</summary><ul class="res-list">{{range .Resources}}<li>{{.}}</li>{{end}}{{if .Truncated}}<li class="res-more">&hellip; and {{.Truncated}} more (see By Namespace tab)</li>{{end}}</ul></details>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .PassedCtrl}}<details style="margin-top:12px;padding-left:8px"><summary class="fw-passed-toggle"><span class="status-pass">PASS</span> {{.PassedCtrl}} controls passing</summary>{{if .PassedControlIDs}}<ul class="passed-list">{{range .PassedControlIDs}}<li class="mono">{{.}}</li>
{{end}}</ul>{{else}}<p class="fw-passed-note">These controls have no findings in the current scan.</p>{{end}}</details>{{end}}
</div>
{{end}}
</div>
{{end}}

{{else}}
<p class="no-findings">No findings detected.</p>
{{end}}
</div>

</div>

{{if .ComplianceSummary}}<div class="print-compliance">
<h3 class="print-section-title">Compliance Posture</h3>
<table class="print-table">
<thead><tr><th>Framework</th><th>Pass Rate</th><th>Passed</th><th>Failed</th><th>Total Controls</th></tr></thead>
<tbody>{{range .ComplianceSummary}}<tr><td>{{.Framework}}</td><td>{{.Pct}}%%</td><td>{{.PassedCount}}</td><td>{{.ControlsFailed}}</td><td>{{.ControlsTotal}}</td></tr>{{end}}</tbody>
</table>
</div>{{end}}

{{if .PrintNamespaceDetails}}<div class="print-workloads">
<h3 class="print-section-title">Critical &amp; High Findings by Workload</h3>
{{range .PrintNamespaceDetails}}<div class="print-ns-group">
<div class="print-ns-heading">{{.Namespace}} <span class="print-ns-tier">({{.Tier}})</span><span class="print-ns-stats">{{.Total}} findings &mdash; {{.Critical}} Crit, {{.High}} High</span></div>
{{range .Workloads}}<div class="print-workload">
<div class="print-wl-header"><span class="print-wl-name">{{.Resource}}</span><span class="print-wl-counts">{{.Critical}} Crit / {{.High}} High</span></div>
<table class="print-table print-wl-table">
<thead><tr><th>Sev</th><th>Check</th><th>Container</th><th>Field</th><th>Message</th></tr></thead>
<tbody>{{range .Findings}}<tr><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td class="mono">{{.Checker}}</td><td>{{.Container}}</td><td class="mono">{{.FieldPath}}</td><td>{{.Message}}</td></tr>{{end}}</tbody>
</table>
</div>{{end}}
</div>{{end}}
{{if .PrintWorkloadsTrunc}}<p class="print-truncation">&hellip; and {{.PrintWorkloadsTrunc}} more finding rows not shown.</p>{{end}}
</div>{{end}}

{{if .Remediations}}<div class="print-rem">
<h3 class="print-section-title">Remediation Reference</h3>
{{range .Remediations}}<div class="print-rem-entry"><h4 class="mono"><span class="sev {{.Severity}}">{{.Severity}}</span> {{.Checker}}</h4>{{.HTML}}</div>
{{end}}
</div>{{end}}

<div id="rem-store" style="display:none">{{range .Remediations}}<div id="rem-{{.Checker}}">{{.HTML}}</div>{{end}}</div>
<div id="summary-data" style="display:none">KubeVigil Scan Report — Stribog IT Solutions
{{if .ContextName}}Cluster: {{.ContextName}}
{{end}}Scan Mode: {{.ScanMode}} | Duration: {{.Duration}}{{if .ServerVersion}}
K8s Version: {{.ServerVersion}}{{end}}{{if .NodeCount}} | Nodes: {{.NodeCount}}{{end}}
Posture Score: {{.PostureScore}}/100 ({{.ScoreGrade}})
Total Findings: {{.TotalFindings}} (Critical: {{.Critical}}, High: {{.High}}, Medium: {{.Medium}}, Low: {{.Low}}, Info: {{.Info}})
Resources Affected: {{.UniqueResources}} | Namespaces: {{.UniqueNamespaces}}
{{if .AppTotal}}Application: {{.AppTotal}} findings (score {{.AppPostureScore}}, {{.AppScoreGrade}})
{{end}}{{if .InfraTotal}}Infrastructure: {{.InfraTotal}} findings (score {{.InfraPostureScore}}, {{.InfraScoreGrade}})
{{end}}{{if .ClusterTotal}}Cluster-Scoped: {{.ClusterTotal}} findings
{{end}}Checks Run: {{.ChecksRun}} | Passed: {{.ChecksClean}} | Failed: {{.ChecksWithFind}}
Generated: {{.GeneratedAt}}</div>
<script id="findings-json" type="application/json">{{.FindingsJSON}}</script>
<script id="checker-meta" type="application/json">{{.CheckerMetaJSON}}</script>
<div id="help-overlay" class="help-overlay hidden">
<div class="help-dialog">
<h3>Keyboard Shortcuts</h3>
<table class="help-keys">
<tr><td><kbd>1</kbd></td><td>All Findings tab</td></tr>
<tr><td><kbd>2</kbd></td><td>By Namespace tab</td></tr>
<tr><td><kbd>3</kbd></td><td>By Check tab</td></tr>
<tr><td><kbd>4</kbd></td><td>Compliance tab</td></tr>
<tr><td><kbd>f</kbd></td><td>Focus search</td></tr>
<tr><td><kbd>e</kbd></td><td>Expand / Collapse all</td></tr>
<tr><td><kbd>d</kbd></td><td>Toggle dark mode</td></tr>
<tr><td><kbd>?</kbd></td><td>Show this help</td></tr>
<tr><td><kbd>Esc</kbd></td><td>Close overlay</td></tr>
</table>
<button class="nav-btn" onclick="toggleHelp()" style="margin-top:12px">Close</button>
</div>
</div>
<div id="rem-drawer" class="rem-drawer" aria-hidden="true">
<div class="rem-drawer-backdrop" onclick="closeDrawer()"></div>
<div class="rem-drawer-panel">
<div class="rem-drawer-header">
<span class="rem-drawer-title"></span>
<span class="rem-drawer-sev sev"></span>
<button class="rem-drawer-close" onclick="closeDrawer()" aria-label="Close">&times;</button>
</div>
<div class="rem-drawer-body"></div>
</div>
</div>
<footer class="footer">
<div class="footer-frameworks">
<span class="fw-icon"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> CIS v1.8.0</span>
<span class="fw-icon"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> NSA/CISA Hardened</span>
<span class="fw-icon"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> MITRE Framework</span>
</div>
<div class="footer-tagline">KubeVigil{{if eq .ToolVersion "dev"}} (development build){{else}} {{.ToolVersion}}{{end}} · Stribog IT Solutions Pvt. Ltd.</div>
</footer>
<script>
var AGGREGATE={{if .Aggregate}}true{{else}}false{{end}};
%s
{{if .AutoExpand}}document.querySelectorAll('.ns-section').forEach(function(s){s.open=true;loadNsFindings(s)});{{end}}
</script>
</body>
</html>`, htmlCSS, htmlJS)))

const htmlCSS = `:root{
--color-critical:#dc2626;--color-high:#ea580c;--color-medium:#d97706;--color-low:#0284c7;--color-info:#6b7280;
--color-accent:#4f46e5;--color-success:#10b981;
--surface-0:#f0f2f5;--surface-1:#ffffff;--surface-2:#f8fafc;--surface-3:#f1f5f9;
--text-primary:#0f172a;--text-secondary:#475569;--text-muted:#64748b;--text-faint:#94a3b8;
--border-default:#e2e8f0;--border-subtle:#f1f5f9;
--glass-bg:rgba(255,255,255,0.72);--glass-border:rgba(255,255,255,0.3);--glass-blur:12px;
--ambient-1:rgba(59,130,246,0.08);--ambient-2:rgba(124,58,237,0.06);
--fw-cis:#2563eb;--fw-mitre:#7c3aed;--fw-nsa:#059669;
--status-fail-bg:#fef2f2;--status-fail-color:#dc2626;--status-fail-border:#fecaca;
--status-pass-bg:#f0fdf4;--status-pass-color:#10b981;--status-pass-border:#bbf7d0;
--code-bg:#1e293b;--code-color:#e2e8f0
}
.dark{
--surface-0:#020617;--surface-1:#0f172a;--surface-2:#020617;--surface-3:#1e293b;
--text-primary:#f1f5f9;--text-secondary:#94a3b8;--text-muted:#94a3b8;--text-faint:#64748b;
--border-default:#1e293b;--border-subtle:#0f172a;
--glass-bg:rgba(2,6,23,0.85);--glass-border:rgba(30,41,59,0.6);
--ambient-1:rgba(59,130,246,0.05);--ambient-2:rgba(124,58,237,0.03);
--status-fail-bg:#451a03;--status-fail-color:#fca5a5;--status-fail-border:#dc2626;
--status-pass-bg:#052e16;--status-pass-color:#4ade80;--status-pass-border:#10b981;
--code-bg:#020617;--code-color:#e2e8f0
}
@media(prefers-color-scheme:dark){html:not(.light){
--surface-0:#020617;--surface-1:#0f172a;--surface-2:#020617;--surface-3:#1e293b;
--text-primary:#f1f5f9;--text-secondary:#94a3b8;--text-muted:#94a3b8;--text-faint:#64748b;
--border-default:#1e293b;--border-subtle:#0f172a;
--glass-bg:rgba(2,6,23,0.85);--glass-border:rgba(30,41,59,0.6);
--ambient-1:rgba(59,130,246,0.05);--ambient-2:rgba(124,58,237,0.03);
--status-fail-bg:#451a03;--status-fail-color:#fca5a5;--status-fail-border:#dc2626;
--status-pass-bg:#052e16;--status-pass-color:#4ade80;--status-pass-border:#10b981;
--code-bg:#020617;--code-color:#e2e8f0
}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
::selection{background:#4f46e5;color:#fff}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:0;background:var(--surface-0);color:var(--text-primary);line-height:1.5}
body::before{content:'';position:fixed;inset:0;z-index:-1;background:radial-gradient(ellipse 600px 400px at 20% 30%,var(--ambient-1),transparent),radial-gradient(ellipse 500px 350px at 75% 60%,var(--ambient-2),transparent),var(--surface-0);pointer-events:none}
.header-meta{font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.5px;color:var(--text-faint)}
.sticky-nav{position:sticky;top:0;z-index:100;background:var(--glass-bg);backdrop-filter:blur(var(--glass-blur));-webkit-backdrop-filter:blur(var(--glass-blur));border-bottom:1px solid var(--glass-border);box-shadow:0 1px 3px rgba(0,0,0,.06)}
.sticky-inner{padding:16px 32px;display:flex;align-items:center;gap:16px}
.container{max-width:1280px;margin:0 auto;padding:24px 32px}
.fw-section{padding:24px 32px 0;margin-bottom:0}
.fw-section+.fw-section{border-top:1px solid var(--border-subtle);margin-top:0}
.fw-section:last-child{padding-bottom:24px}
.fw-header{display:flex;align-items:baseline;gap:16px;margin-bottom:16px;padding-left:12px;border-left:4px solid var(--text-faint)}
.fw-header .tier-heading{font-size:18px;font-weight:800;letter-spacing:-.3px;text-transform:uppercase;margin:0}
.fw-section:nth-child(1) .fw-header{border-left-color:var(--fw-cis)}
.fw-section:nth-child(2) .fw-header{border-left-color:var(--fw-mitre)}
.fw-section:nth-child(3) .fw-header{border-left-color:var(--fw-nsa)}
.fw-score{font-size:14px;font-weight:600}
.fw-table{table-layout:fixed}
.fw-table td:nth-child(4){overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fw-table td:nth-child(5){overflow-wrap:break-word;word-break:break-word}
.status-fail{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:var(--status-fail-bg);color:var(--status-fail-color);border:1px solid var(--status-fail-border)}
.status-pass{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:var(--status-pass-bg);color:var(--status-pass-color);border:1px solid var(--status-pass-border)}
.fw-passed-toggle{cursor:pointer;font-size:13px;color:var(--text-secondary);display:flex;align-items:center;gap:8px}
.fw-passed-note{font-size:12px;color:var(--text-faint);margin:4px 0 0 28px}
.help-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:200;display:flex;align-items:center;justify-content:center}
.help-dialog{background:var(--surface-1);border-radius:12px;padding:24px 32px;box-shadow:0 8px 32px rgba(0,0,0,.2);max-width:360px;width:90%}
.help-dialog h3{margin:0 0 16px;font-size:16px;font-weight:700;color:var(--text-primary)}
.help-keys{width:100%;border-collapse:collapse}
.help-keys td{padding:6px 0;font-size:13px;color:var(--text-secondary)}
.help-keys td:first-child{width:60px}
kbd{display:inline-block;padding:2px 8px;background:var(--surface-3);border:1px solid var(--border-default);border-radius:4px;font-family:monospace;font-size:12px;font-weight:600;color:var(--text-primary)}
.sortable-th{cursor:pointer;user-select:none;position:relative;padding-right:18px!important}
.sortable-th:hover{color:var(--text-primary)}
.sortable-th::after{content:'';position:absolute;right:4px;top:50%;transform:translateY(-50%);border:4px solid transparent;opacity:.3}
.sortable-th.sort-asc::after{border-bottom-color:currentColor;opacity:1;top:40%}
.sortable-th.sort-desc::after{border-top-color:currentColor;opacity:1;top:55%}
h2{margin:0 0 16px;font-size:18px;font-weight:700;color:var(--text-primary)}
.data-table{width:100%;border-collapse:collapse;font-size:14px}
.data-table th{text-align:left;padding:10px 8px;background:var(--surface-2);border-bottom:2px solid var(--border-default);font-weight:600;color:var(--text-secondary);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.data-table td{padding:10px 8px;border-bottom:1px solid var(--border-subtle);vertical-align:top}
.data-table tr:hover{background:var(--surface-2)}
.res-col{word-break:break-word}
.mono{font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:13px}
.fw{font-size:12px;color:var(--text-muted)}
.fw-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;color:#fff;margin:1px 2px;white-space:nowrap}
.fw-cis{background:var(--fw-cis)}
.fw-mitre{background:var(--fw-mitre)}
.fw-nsa{background:var(--fw-nsa)}
.sev{padding:6px 10px;border-radius:8px;font-size:10px;font-weight:900;color:#fff;white-space:nowrap;text-transform:uppercase;letter-spacing:.3px;box-shadow:0 1px 2px rgba(0,0,0,.05);min-width:72px;text-align:center;display:inline-block}
.Critical{background:var(--color-critical);box-shadow:0 0 0 4px rgba(220,38,38,.1),0 1px 2px rgba(0,0,0,.05)}
.High{background:var(--color-high);box-shadow:0 0 0 4px rgba(234,88,12,.1),0 1px 2px rgba(0,0,0,.05)}
.Medium{background:var(--color-medium);box-shadow:0 0 0 4px rgba(217,119,6,.1),0 1px 2px rgba(0,0,0,.05)}
.Low{background:var(--color-low);box-shadow:0 0 0 4px rgba(2,132,199,.1),0 1px 2px rgba(0,0,0,.05)}
.Info{background:var(--color-info);box-shadow:0 0 0 4px rgba(107,114,128,.1),0 1px 2px rgba(0,0,0,.05)}
.toolbar{display:flex;gap:12px;margin:0 0 16px;flex-wrap:wrap;align-items:center}
.ns-search{padding:8px 14px;border:1px solid var(--border-default);border-radius:6px;font-size:14px;flex:1;min-width:200px;outline:none;transition:border-color .2s;background:var(--surface-0);color:var(--text-primary)}
.ns-search:focus{border-color:var(--color-accent)}
.filters{display:flex;gap:4px;flex-wrap:wrap}
.filter-btn{padding:6px 14px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-1);cursor:pointer;font-size:13px;font-weight:500;color:var(--text-muted);transition:all .2s}
.filter-btn:hover{background:var(--surface-2)}
.filter-btn.active{background:var(--color-accent);color:#fff;border-color:var(--color-accent)}
.toggle-btn{padding:6px 14px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-1);cursor:pointer;font-size:13px;font-weight:500;color:var(--text-muted);transition:all .2s;white-space:nowrap}
.toggle-btn:hover{background:var(--surface-2)}
.tier-heading{font-size:15px;font-weight:600;color:var(--text-secondary);margin:16px 0 8px;display:flex;align-items:center;gap:8px}
.tier-section{margin:16px 0;border:1px solid var(--border-default);border-radius:8px;overflow:hidden}
.tier-section>summary{padding:12px 16px;cursor:pointer;background:var(--surface-3)}
.ns-section{margin:12px 0;border:1px solid var(--border-default);border-radius:8px;overflow:hidden}
.ns-section summary{padding:12px 16px;cursor:pointer;font-weight:600;font-size:14px;background:var(--surface-2);display:flex;align-items:center;gap:12px}
.ns-section[open] summary{border-bottom:1px solid var(--border-default)}
.ns-label{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ns-count{font-size:12px;color:var(--text-muted);font-weight:400;white-space:nowrap}
.ns-bar{display:flex;width:120px;height:6px;border-radius:3px;overflow:hidden;background:var(--border-default);flex-shrink:0}
.bar-seg{height:100%}
.ns-badges{display:flex;gap:4px;flex-shrink:0}
.ns-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff}
.ns-badge.critical{background:var(--color-critical)}
.ns-badge.high{background:var(--color-high)}
.ns-badge.medium{background:var(--color-medium)}
.ns-badge.low{background:var(--color-low)}
.ns-badge.info{background:var(--color-info)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.no-findings{text-align:center;color:var(--text-muted);padding:32px;font-size:16px}
.passed-list{column-count:3;column-gap:24px;padding:0 0 0 20px;margin:12px 0;font-size:13px}
.passed-list li{padding:2px 0;color:var(--color-success)}
.res-drill{display:inline}
.res-drill summary{cursor:pointer;color:var(--color-accent);font-weight:500}
.res-list{margin:4px 0 0;padding-left:16px;font-size:12px;list-style:disc}
.res-more{list-style:none;color:var(--text-muted);font-style:italic;margin-top:4px}
.rem-trigger{cursor:pointer;display:inline-block;padding:6px 14px;border:none;border-radius:10px;background:color-mix(in srgb,#4f46e5 8%,transparent);color:#4f46e5;font-size:11px;font-weight:700;transition:all .2s}
.rem-trigger:hover{background:#4f46e5;color:#fff}
.fc-remediation{margin-top:10px;padding-top:10px;border-top:1px solid var(--border-subtle)}
.finding-cards{display:flex;flex-direction:column;gap:8px}
.finding-card{background:var(--surface-1);border:1px solid var(--border-default);border-radius:10px;padding:12px 16px;transition:box-shadow .2s}
.finding-card:hover{box-shadow:0 2px 8px rgba(0,0,0,.06)}
.fc-header{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.fc-check{font-size:13px;font-weight:600;color:var(--text-primary);white-space:nowrap}
.fc-res{font-size:12px;color:var(--text-secondary);flex:1;min-width:0;word-break:break-word}
.fc-fw{font-size:12px;color:var(--text-muted);display:flex;flex-wrap:wrap;gap:3px;flex-shrink:0}
.code-block{background:var(--code-bg);color:var(--code-color);padding:10px 14px;border-radius:6px;font-size:11px;line-height:1.5;overflow-x:auto;margin:6px 0;white-space:pre}
.code-block code{font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace}
.footer{text-align:center;padding:48px 24px;border-top:1px solid var(--border-subtle);background:var(--surface-1);color:var(--text-faint)}
.footer-frameworks{display:flex;justify-content:center;gap:32px;margin-bottom:16px}
.fw-icon{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.5px;opacity:.6}
.fw-icon svg{opacity:.6}
.footer-tagline{font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:3px;color:var(--text-faint)}
[id]{scroll-margin-top:44px}
.hidden{display:none}
.nav-spacer{flex:1}
.nav-btn{padding:4px 10px;border:1px solid var(--border-default);border-radius:4px;background:var(--surface-1);cursor:pointer;font-size:12px;font-weight:500;color:var(--text-muted);transition:all .2s}
.nav-btn:hover{background:var(--surface-3);color:var(--text-primary)}
.sort-group{display:flex;align-items:center;gap:4px}
.sort-label{font-size:12px;color:var(--text-muted);font-weight:500}
.sort-btn{padding:4px 10px;border:1px solid var(--border-default);border-radius:4px;background:var(--surface-1);cursor:pointer;font-size:12px;font-weight:500;color:var(--text-muted);transition:all .2s}
.sort-btn:hover{background:var(--surface-2)}
.sort-btn.active{background:var(--color-accent);color:#fff;border-color:var(--color-accent)}
.rem-drawer{position:fixed;inset:0;z-index:300;pointer-events:none;visibility:hidden}
.rem-drawer.open{pointer-events:auto;visibility:visible}
.rem-drawer-backdrop{position:absolute;inset:0;background:rgba(0,0,0,0);backdrop-filter:blur(0);transition:background .3s,backdrop-filter .3s}
.rem-drawer.open .rem-drawer-backdrop{background:rgba(0,0,0,.3);backdrop-filter:blur(2px)}
.rem-drawer-panel{position:absolute;top:0;right:0;bottom:0;width:min(560px,90vw);background:var(--surface-1);border-left:1px solid var(--border-default);box-shadow:-4px 0 24px rgba(0,0,0,.12);transform:translateX(100%);transition:transform .3s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column;overflow-y:auto}
.rem-drawer.open .rem-drawer-panel{transform:translateX(0)}
.rem-drawer-header{display:flex;align-items:center;gap:10px;padding:16px 20px;border-bottom:1px solid var(--border-default);flex-shrink:0}
.rem-drawer-title{font-size:14px;font-weight:700;color:var(--text-primary);font-family:'SF Mono',SFMono-Regular,Consolas,monospace;flex:1}
.rem-drawer-close{background:none;border:none;font-size:22px;cursor:pointer;color:var(--text-muted);padding:4px 8px;border-radius:4px;line-height:1}
.rem-drawer-close:hover{background:var(--surface-3);color:var(--text-primary)}
.rem-drawer-body{padding:20px;flex:1;overflow-y:auto}
.rem-drawer-body p{margin:6px 0;font-size:13px;color:var(--text-secondary);line-height:1.6}
.rem-h3{font-size:14px;font-weight:700;color:var(--text-primary);margin:18px 0 6px;padding-bottom:4px;border-bottom:1px solid var(--border-subtle)}
.rem-h4{font-size:12px;font-weight:600;color:var(--text-primary);margin:14px 0 4px}
.rem-drawer-body .code-block{font-size:12px;padding:12px 16px;margin:8px 0 12px;border:1px solid var(--border-subtle);border-radius:8px}
.header-brand{display:flex;align-items:center;gap:12px}
.brand-icon{display:flex;align-items:center;justify-content:center;width:36px;height:36px;background:#4f46e5;border-radius:10px;color:#fff;box-shadow:0 4px 12px rgba(79,70,229,.3)}
.brand-name{font-size:18px;font-weight:800;letter-spacing:-.3px;color:var(--text-primary)}
.brand-subtitle{display:block;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:2px;color:var(--text-faint)}
.header-cluster{font-size:12px;font-weight:600;color:var(--text-secondary);border-right:1px solid var(--border-default);padding-right:16px}
.header-cluster strong{color:#4f46e5}
.dark .header-cluster strong{color:#818cf8}
.theme-btn{display:flex;align-items:center;padding:8px;border:none;background:transparent;cursor:pointer;border-radius:50%;color:var(--text-muted);font-size:16px;transition:all .2s}
.theme-btn:hover{background:var(--surface-3);color:var(--text-primary)}
.theme-light{display:inline}.theme-dark{display:none}
.dark .theme-light{display:none}.dark .theme-dark{display:inline}
.hero-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:24px;margin-bottom:32px}
.hero-card{background:var(--surface-1);border-radius:24px;padding:24px;border:1px solid var(--border-subtle);box-shadow:0 1px 2px rgba(0,0,0,.05);position:relative;overflow:hidden;display:flex;flex-direction:column;justify-content:space-between;min-height:160px;border-top:3px solid transparent}
.hero-card-score{}
.hero-card-detail{justify-content:flex-start}
.hero-label{font-size:11px;font-weight:900;text-transform:uppercase;letter-spacing:2px;color:var(--text-faint);margin-bottom:4px}
.hero-number{font-size:48px;font-weight:900;line-height:1;letter-spacing:-1px;color:var(--text-primary)}
.hero-suffix{font-size:20px;font-weight:700;opacity:.6}
.hero-row{display:flex;align-items:baseline;gap:4px}
.hero-bottom{margin-top:16px;display:flex;align-items:center;gap:8px}
.grade-badge{padding:2px 10px;border-radius:6px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:-.3px;background:color-mix(in srgb,currentColor 12%,transparent)}
.hero-hint{font-size:10px;color:var(--text-faint)}
.hero-desc{font-size:10px;font-weight:600;color:var(--text-faint);line-height:1.6;margin-top:16px}
.hero-sev-labels{display:flex;gap:16px;margin-top:16px}
.sev-label-crit{font-size:10px;font-weight:900;color:var(--color-critical)}
.sev-label-high{font-size:10px;font-weight:900;color:var(--text-faint)}
.sev-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--surface-3);margin-top:8px}
.sev-bar-seg{height:100%}
.compliance-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;font-size:10px;text-transform:uppercase;font-weight:900}
.compliance-name{color:var(--text-muted);letter-spacing:.5px}
.compliance-pct{letter-spacing:-.3px}
.hero-scan-time{padding-top:12px;margin-top:auto;border-top:1px solid var(--border-subtle);display:flex;align-items:center;gap:6px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:2px;color:var(--text-faint)}
.scan-refresh{flex-shrink:0;opacity:.6}
.explorer{background:var(--surface-1);border-radius:24px;border:1px solid var(--border-subtle);box-shadow:0 25px 50px -12px rgba(0,0,0,.15);overflow:hidden;margin-bottom:32px}
.explorer-header{padding:32px 32px 24px;border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px}
.explorer-title{font-size:24px;font-weight:900;letter-spacing:-.5px;margin:0;color:var(--text-primary)}
.explorer-subtitle{font-size:14px;color:var(--text-faint);font-weight:500;margin:4px 0 0}
.pill-tabs{display:flex;align-items:center;gap:4px;background:var(--surface-3);border:1px solid var(--border-subtle);padding:6px;border-radius:16px}
.pill-tab{padding:8px 20px;border:none;border-radius:12px;background:transparent;cursor:pointer;font-size:12px;font-weight:700;color:var(--text-faint);transition:all .2s}
.pill-tab:hover{color:var(--text-primary)}
.pill-tab.active{background:var(--surface-1);color:var(--text-primary);box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid var(--border-subtle)}
.explorer-toolbar{padding:16px 32px;background:color-mix(in srgb,var(--surface-3) 50%,transparent);border-bottom:1px solid var(--border-subtle);display:flex;flex-wrap:wrap;gap:16px;align-items:center}
.search-wrap{flex:1;position:relative;min-width:280px;display:flex}
.search-icon{position:absolute;left:16px;top:0;bottom:0;margin:auto 0;width:16px;height:16px;color:var(--text-faint);pointer-events:none}
.search-wrap input{width:100%;padding:14px 16px 14px 44px;border:1px solid var(--border-default);border-radius:16px;font-size:14px;background:var(--surface-1);color:var(--text-primary);outline:none;box-shadow:0 1px 2px rgba(0,0,0,.05);transition:all .2s}
.search-wrap input:focus{border-color:#4f46e5;box-shadow:0 0 0 3px rgba(79,70,229,.15)}
.quick-filter{display:flex;align-items:center;gap:8px}
.qf-label{font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:2px;color:var(--text-faint);margin-right:4px}
.qf-btn{padding:6px 12px;border:none;border-radius:8px;background:var(--surface-0);cursor:pointer;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.5px;color:var(--text-faint);transition:all .2s}
.qf-btn:hover{color:var(--text-primary)}
.qf-btn.active{background:var(--text-primary);color:var(--surface-0)}
.qf-critical{background:var(--color-critical);color:#fff;opacity:.9}
.qf-critical:hover{opacity:1}
.qf-high{background:var(--color-high);color:#fff;opacity:.9}
.qf-high:hover{opacity:1}
.qf-others{background:var(--surface-3)}
.table-wrap{overflow-x:auto}
.findings-table{width:100%;border-collapse:collapse;text-align:left}
.ft-th{padding:20px 32px;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:2px;color:var(--text-faint);border-bottom:1px solid var(--border-subtle)}
.ft-th-right{text-align:right}
.findings-table td{padding:24px 32px;border-bottom:1px solid color-mix(in srgb,var(--border-subtle) 50%,transparent);vertical-align:middle}
.findings-table tbody tr{transition:background .15s}
.findings-table tbody tr:hover{background:color-mix(in srgb,var(--surface-3) 80%,transparent)}
.ft-check-name{font-size:14px;font-weight:700;letter-spacing:-.3px;color:var(--text-primary);transition:color .15s}
.findings-table tbody tr:hover .ft-check-name{color:#4f46e5}
.ft-check-desc{font-size:12px;color:var(--text-faint);margin-top:2px}
.ft-resource{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:var(--text-muted)}
.ft-resource-icon{display:flex;align-items:center;justify-content:center;width:28px;height:28px;background:var(--surface-3);border-radius:6px;font-size:10px;font-weight:700;color:var(--text-faint);flex-shrink:0}
.ft-view-fix{padding:8px 16px;background:color-mix(in srgb,#4f46e5 8%,transparent);color:#4f46e5;font-size:10px;font-weight:900;text-transform:uppercase;border:none;border-radius:12px;cursor:pointer;transition:all .2s;white-space:nowrap}
.ft-view-fix:hover{background:#4f46e5;color:#fff}
.pagination{padding:32px;background:var(--surface-3);border-top:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}
.page-info{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:var(--text-faint)}
.page-btns{display:flex;gap:8px}
.page-btn{padding:8px 16px;background:var(--surface-1);border:1px solid var(--border-default);border-radius:12px;font-size:10px;font-weight:900;text-transform:uppercase;cursor:pointer;color:var(--text-secondary);box-shadow:0 1px 2px rgba(0,0,0,.05);transition:all .2s}
.page-btn:hover:not(:disabled){border-color:#4f46e5;color:#4f46e5}
.page-btn:disabled{opacity:.5;cursor:not-allowed}
.print-meta,.print-exec,.print-triage,.print-cats,.print-ns,.print-compliance,.print-workloads,.print-rem{display:none}
@media print{
:root,.dark,html:not(.light){
--color-critical:#dc2626;--color-high:#ea580c;--color-medium:#d97706;--color-low:#0284c7;--color-info:#6b7280;
--color-accent:#4f46e5;--color-success:#10b981;
--surface-0:#f0f2f5;--surface-1:#ffffff;--surface-2:#f8fafc;--surface-3:#f1f5f9;
--text-primary:#0f172a;--text-secondary:#475569;--text-muted:#64748b;--text-faint:#94a3b8;
--border-default:#e2e8f0;--border-subtle:#f1f5f9;
--glass-bg:rgba(255,255,255,0.72);--glass-border:rgba(255,255,255,0.3);--glass-blur:12px;
--ambient-1:rgba(59,130,246,0.08);--ambient-2:rgba(124,58,237,0.06);
--fw-cis:#2563eb;--fw-mitre:#7c3aed;--fw-nsa:#059669;
--status-fail-bg:#fef2f2;--status-fail-color:#dc2626;--status-fail-border:#fecaca;
--status-pass-bg:#f0fdf4;--status-pass-color:#10b981;--status-pass-border:#bbf7d0;
--code-bg:#1e293b;--code-color:#e2e8f0
}
body{background:#fff!important}
body::before{display:none}
*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
.sticky-nav,.explorer-toolbar,.pagination,.quick-filter,.search-wrap,.rem-drawer,.rem-trigger,.ft-view-fix,.theme-btn,.pill-tabs,.help-overlay,.sort-group,.toggle-btn{display:none!important}
.container{padding:8px 0;max-width:100%}
.explorer{box-shadow:none;border:1px solid #ddd;border-radius:8px;overflow:visible}
.explorer-header{padding:16px 20px 12px;border-bottom:1px solid #ddd}
.explorer-title{font-size:18px}
.explorer-subtitle{font-size:11px}
.hero-grid{display:grid!important;grid-template-columns:repeat(2,1fr)!important;gap:12px!important;margin-bottom:16px}
.hero-card{min-height:auto!important;padding:12px 16px!important;box-shadow:none;border:1px solid #ddd;border-radius:8px;border-top-width:3px}
.hero-number{font-size:32px!important}
.hero-suffix{font-size:14px!important}
.hero-label{font-size:9px!important;margin-bottom:2px}
.hero-bottom{margin-top:8px}
.hero-desc{font-size:9px!important;margin-top:8px}
.hero-sev-labels{margin-top:8px}
.hero-scan-time{padding-top:6px;margin-top:8px;font-size:8px!important}
.grade-badge{font-size:8px!important}
.hero-hint{font-size:8px!important}
.compliance-row{padding:4px 0;font-size:9px!important}
#tab-all-findings{display:none!important}
#tab-by-namespace{display:none!important}
#tab-by-check,#tab-compliance{display:block!important;padding:12px 20px!important}
#tab-by-check::before{content:'By Check';display:block;font-size:14px;font-weight:800;margin-bottom:8px;padding-bottom:6px;border-bottom:2px solid #ddd}
#tab-compliance::before{content:'Compliance';display:block;font-size:14px;font-weight:800;margin-bottom:8px;padding-bottom:6px;border-bottom:2px solid #ddd;page-break-before:always}
.data-table{font-size:10px}
.data-table th{padding:6px 4px;font-size:9px;background:#f5f5f5!important}
.data-table td{padding:5px 4px}
.fw-section{padding:12px 0 0!important;margin-bottom:0!important}
.fw-section+.fw-section{border-top:1px solid #ddd}
.fw-section:last-child{padding-bottom:8px!important}
.fw-header{margin-bottom:8px;padding-left:8px}
.fw-header .tier-heading{font-size:13px!important}
.fw-score{font-size:11px}
.finding-row{break-inside:avoid;page-break-inside:avoid}
.fw-section{break-inside:avoid;page-break-inside:avoid}
.passed-list{column-count:4;font-size:10px}
.sev{font-size:8px!important;padding:3px 6px!important;min-width:auto!important}
.ns-badge{font-size:9px}
.status-fail,.status-pass{font-size:8px!important;padding:1px 6px!important}
.toolbar{margin-bottom:8px}
.ns-search,.filters{display:none!important}
.tier-section{margin:8px 0}
.tier-section>summary{padding:8px 12px;font-size:12px}
.ns-section{margin:6px 0}
.ns-section summary{padding:8px 12px;font-size:11px}
.footer{padding:16px;border-top:1px solid #ddd}
.footer-frameworks{gap:16px;margin-bottom:8px}
.fw-icon{font-size:8px;opacity:.8}
.footer-tagline{font-size:8px}
details[open]>summary~*{break-inside:avoid}
.mono{font-size:10px!important}
.print-meta,.print-exec,.print-triage,.print-cats,.print-ns,.print-compliance,.print-workloads,.print-rem{display:block!important}
.print-meta,.print-exec,.print-triage,.print-cats,.print-ns,.print-compliance{margin-top:24px}
.print-section-title{font-size:14px;font-weight:800;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid #ddd;page-break-after:avoid}
.print-table{width:100%;border-collapse:collapse;font-size:10px}
.print-table th{text-align:left;padding:4px 6px;background:#f5f5f5!important;border-bottom:1px solid #ddd;font-size:9px;font-weight:600}
.print-table td{padding:4px 6px;border-bottom:1px solid #eee;vertical-align:top}
.print-exec-text{border-left:3px solid #4f46e5;background:#f8fafc;padding:8px 12px;font-size:11px;line-height:1.6;margin:0 0 8px}
.print-workloads,.print-rem{page-break-before:always}
.print-ns-group{break-inside:avoid;page-break-inside:avoid;margin-bottom:16px}
.print-ns-heading{font-size:12px;font-weight:700;margin:16px 0 8px;color:#333;border-bottom:1px solid #ddd;padding-bottom:4px}
.print-ns-tier{font-weight:400;color:#666;font-size:10px}
.print-ns-stats{float:right;font-size:10px;font-weight:400}
.print-workload{margin:8px 0 12px 12px;break-inside:avoid}
.print-wl-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;padding:4px 6px;background:#f5f5f5;border-radius:4px}
.print-wl-name{font-size:11px;font-weight:700}
.print-wl-counts{font-size:9px;color:#666}
.print-wl-table{margin-top:2px}
.print-wl-table th{font-size:8px}
.print-wl-table td{font-size:9px;padding:2px 4px}
.print-exec-actions{margin:8px 0 0 16px;font-size:10px;line-height:1.6}
.print-exec-actions li{margin-bottom:4px}
.print-rem-entry{break-inside:avoid;page-break-inside:avoid;margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid #ddd}
.print-rem-entry h4{font-size:12px;margin:16px 0 8px;color:#333}
.print-rem-entry .code-block{background:#f5f5f5!important;color:#333!important;font-size:9px;border:1px solid #ddd}
.print-rem-entry .rem-h3{font-size:12px;font-weight:700;margin:10px 0 4px;border-bottom:1px solid #ddd}
.print-rem-entry .rem-h4{font-size:11px;font-weight:600;margin:8px 0 2px}
.print-truncation{font-size:10px;color:#666;font-style:italic;margin-top:4px}
.print-ns h4{font-size:12px;font-weight:700;margin:20px 0 8px;color:#333}
}
@media(prefers-reduced-transparency:reduce){.sticky-nav{backdrop-filter:none;-webkit-backdrop-filter:none;background:var(--surface-1)}body::before{display:none}}
@media(max-width:1100px){.hero-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:768px){.hero-grid{grid-template-columns:1fr}.explorer-header{flex-direction:column}.pill-tabs{width:100%;overflow-x:auto}.explorer-toolbar{padding:16px}.findings-table td,.ft-th{padding:12px 16px}.pagination{padding:16px}.hide-mobile{display:none}}`

const htmlJS = `function switchTab(btn){document.querySelectorAll('.pill-tab').forEach(function(b){b.classList.remove('active')});document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active')});btn.classList.add('active');var panel=document.getElementById('tab-'+btn.dataset.tab);if(panel)panel.classList.add('active');history.replaceState(null,null,'#'+btn.dataset.tab)}(function(){var hash=location.hash.replace('#','');if(hash){var btn=document.querySelector('.pill-tab[data-tab="'+hash+'"]');if(btn)switchTab(btn)}window.addEventListener('hashchange',function(){var h=location.hash.replace('#','');var b=document.querySelector('.pill-tab[data-tab="'+h+'"]');if(b)switchTab(b)})})();var PAGE_SIZE=25,currentPage=0,filteredFindings=[],allFindings=[],findingsByNs={},CHECKER_META=null;function getCheckerMeta(){if(!CHECKER_META){var el=document.getElementById('checker-meta');CHECKER_META=el?JSON.parse(el.textContent):{}}return CHECKER_META}function getFindings(){var el=document.getElementById('findings-json');if(!el)return[];try{var d=JSON.parse(el.textContent);if(!d.c)return[];var a=[];for(var i=0;i<d.c.length;i++){a.push({checker:d.c[i],severity:d.s[i],resource:d.r[i],namespace:d.n[i]||'',kind:d.k[i],container:d.t[i]||'',message:d.m[i],field_path:d.f[i]||''})}return a}catch(e){return[]}}function initFindings(){allFindings=getFindings();filteredFindings=allFindings.slice();currentPage=0;findingsByNs={};allFindings.forEach(function(f){var ns=f.namespace||'';if(!findingsByNs[ns])findingsByNs[ns]=[];findingsByNs[ns].push(f)});renderPage()}function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}function kindIcon(kind){var m={Deployment:'D',StatefulSet:'SS',DaemonSet:'DS',Job:'J',CronJob:'CJ',Pod:'P',ClusterRole:'CR',ClusterRoleBinding:'CB',Role:'R',RoleBinding:'RB',Service:'Sv',Ingress:'I',ConfigMap:'CM',Secret:'Sc',Namespace:'N',NetworkPolicy:'NP',ServiceAccount:'SA',PersistentVolumeClaim:'PV',Node:'No'};return m[kind]||kind.charAt(0).toUpperCase()||'?'}function fwBadges(m){if(!m||!m.fw)return'';var h='<span class="fc-fw">',fp=m.fw.split(' | '),cp=(m.ci||'').split(' | ');for(var i=0;i<fp.length;i++){var fw=fp[i],ci=cp[i]||'',cls='fw-badge';if(fw==='CIS')cls+=' fw-cis';else if(fw==='MITRE')cls+=' fw-mitre';else if(fw==='NSA')cls+=' fw-nsa';ci.split(', ').forEach(function(id){if(id)h+='<span class="'+cls+'">'+fw+' '+esc(id)+'</span> '})}return h+'</span>'}function renderPage(){var start=currentPage*PAGE_SIZE;var end=Math.min(start+PAGE_SIZE,filteredFindings.length);var tbody=document.getElementById('findings-tbody');if(!tbody)return;var cm=getCheckerMeta();var html='';for(var i=start;i<end;i++){var f=filteredFindings[i];var res=f.kind?(f.kind+' / '+(f.resource||'')):(f.resource||'');var ki=kindIcon(f.kind||'');var m=cm[f.checker]||{};html+='<tr><td><span class="sev '+f.severity+'">'+f.severity+'</span></td>';html+='<td><div class="ft-check-name">'+esc(f.checker)+'</div><div class="ft-check-desc">'+esc(f.message||'')+'</div></td>';html+='<td><div class="ft-resource"><span class="ft-resource-icon">'+ki+'</span>'+esc(res)+'</div></td>';html+='<td style="text-align:right">'+(m.r?'<button class="ft-view-fix rem-trigger" data-checker="'+esc(f.checker)+'" onclick="openDrawer(this)">View Fix</button>':'')+'</td></tr>'}tbody.innerHTML=html;var pr=document.getElementById('page-range');if(pr)pr.textContent=filteredFindings.length?(start+1)+'\u2013'+end:'0\u20130';var pb=document.getElementById('prev-page');var nb=document.getElementById('next-page');if(pb)pb.disabled=currentPage===0;if(nb)nb.disabled=end>=filteredFindings.length}function nextPage(){if((currentPage+1)*PAGE_SIZE<filteredFindings.length){currentPage++;renderPage();var el=document.getElementById('findings');if(el)el.scrollIntoView({behavior:'smooth',block:'start'})}}function prevPage(){if(currentPage>0){currentPage--;renderPage();var el=document.getElementById('findings');if(el)el.scrollIntoView({behavior:'smooth',block:'start'})}}function filterAllFindings(){var q=document.getElementById('search').value.toLowerCase();var sevBtn=document.querySelector('.qf-btn.active');var sev=sevBtn?sevBtn.dataset.severity:'all';filteredFindings=allFindings.filter(function(f){var matchSearch=!q||(f.checker+' '+f.resource+' '+f.message+' '+f.severity+' '+f.kind+' '+f.namespace).toLowerCase().indexOf(q)>=0;var matchSev=sev==='all'||f.severity===sev||(sev==='others'&&f.severity!=='Critical'&&f.severity!=='High');return matchSearch&&matchSev});currentPage=0;renderPage()}function setQuickFilter(btn){document.querySelectorAll('.qf-btn').forEach(function(b){b.classList.remove('active')});btn.classList.add('active');filterAllFindings()}function loadNsFindings(s){var ns=s.dataset.ns,nsf=findingsByNs[ns]||[],cm=getCheckerMeta(),el=document.querySelector('.ns-search'),q=el?el.value.toLowerCase():'',sb=document.querySelector('.filter-btn.active'),sv=sb?sb.dataset.severity:'all',ff=nsf.filter(function(f){var ms=!q||(f.checker+' '+f.resource+' '+f.message+' '+f.severity+' '+f.kind).toLowerCase().indexOf(q)>=0;return ms&&(sv==='all'||f.severity===sv)}),c=s.querySelector('.finding-cards');if(!c)return;if(!ff.length){c.innerHTML='';return}var h='';if(typeof AGGREGATE!=='undefined'&&AGGREGATE){var g={},o=[];ff.forEach(function(f){var k=f.checker+'|'+f.severity+'|'+f.message;if(!g[k]){g[k]={ch:f.checker,sv:f.severity,msg:f.message,rs:[]};o.push(k)}var r=f.kind?f.kind+'/'+f.resource:f.resource;g[k].rs.push({n:r,c:f.container})});o.forEach(function(k){var a=g[k],m=cm[a.ch]||{},fw=fwBadges(m);h+='<div class="finding-card finding-row" data-severity="'+a.sv+'"><div class="fc-header"><span class="sev '+a.sv+'">'+a.sv+'</span><span class="fc-check mono">'+esc(a.ch)+'</span><span class="fc-res mono">';if(a.rs.length===1){h+=esc(a.rs[0].n);if(a.rs[0].c)h+=' ('+esc(a.rs[0].c)+')'}else{h+='<details class="res-drill"><summary>'+a.rs.length+' resources</summary><ul class="res-list">';a.rs.forEach(function(r){h+='<li>'+esc(r.n);if(r.c)h+=' ('+esc(r.c)+')';h+='</li>'});h+='</ul></details>'}h+='</span>'+fw+'</div>';if(m.r)h+='<button class="fc-remediation rem-trigger" data-checker="'+esc(a.ch)+'" onclick="openDrawer(this)">View Fix</button>';h+='</div>'})}else{ff.forEach(function(f){var m=cm[f.checker]||{},fw=fwBadges(m),r=f.kind?f.kind+'/'+f.resource:f.resource;h+='<div class="finding-card finding-row" data-severity="'+f.severity+'"><div class="fc-header"><span class="sev '+f.severity+'">'+f.severity+'</span><span class="fc-check mono">'+esc(f.checker)+'</span><span class="fc-res mono">'+esc(r);if(f.container)h+=' ('+esc(f.container)+')';h+='</span>'+fw+'</div>';if(m.r)h+='<button class="fc-remediation rem-trigger" data-checker="'+esc(f.checker)+'" onclick="openDrawer(this)">View Fix</button>';h+='</div>'})}c.innerHTML=h}function filterFindings(){var el=document.querySelector('.ns-search');var q=el?el.value.toLowerCase():'';var sev=document.querySelector('.filter-btn.active').dataset.severity;document.querySelectorAll('.ns-section').forEach(function(s){var ns=s.dataset.ns;var nsf=findingsByNs[ns]||[];var visible=nsf.filter(function(f){var matchSearch=!q||(f.checker+' '+f.resource+' '+f.message+' '+f.severity+' '+f.kind).toLowerCase().indexOf(q)>=0;var matchSev=sev==='all'||f.severity===sev;return matchSearch&&matchSev}).length;s.classList.toggle('hidden',visible===0);if(s.open&&visible>0)loadNsFindings(s);if(q&&visible>0)s.open=true});document.querySelectorAll('.fw-section').forEach(function(s){s.querySelectorAll('.finding-row').forEach(function(r){var text=r.textContent.toLowerCase();var matchSearch=!q||text.indexOf(q)>=0;var matchSev=sev==='all'||r.dataset.severity===sev;r.classList.toggle('hidden',!(matchSearch&&matchSev))});var vis=s.querySelectorAll('.finding-row:not(.hidden)').length;s.classList.toggle('hidden',vis===0)})}function toggleSeverity(btn){document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active')});btn.classList.add('active');filterFindings()}function toggleAll(){var sections=document.querySelectorAll('.ns-section:not(.hidden)');var btn=document.getElementById('toggle-all');var anyOpen=false;sections.forEach(function(s){if(s.open)anyOpen=true});sections.forEach(function(s){s.open=!anyOpen;if(s.open)loadNsFindings(s)});btn.textContent=anyOpen?'Expand All':'Collapse All'}function openDrawer(btn){var drawer=document.getElementById('rem-drawer');var title=drawer.querySelector('.rem-drawer-title');var sevBadge=drawer.querySelector('.rem-drawer-sev');var body=drawer.querySelector('.rem-drawer-body');var checker=btn.dataset.checker;title.textContent=checker;var card=btn.closest('.finding-card');if(card){var s=card.querySelector('.sev');if(s){sevBadge.textContent=s.textContent;sevBadge.className='rem-drawer-sev sev '+s.textContent}}else{var tr=btn.closest('tr');if(tr){var s=tr.querySelector('.sev');if(s){sevBadge.textContent=s.textContent;sevBadge.className='rem-drawer-sev sev '+s.textContent}}}var store=document.getElementById('rem-'+checker);body.innerHTML=store?store.innerHTML:'';drawer.classList.add('open');drawer.setAttribute('aria-hidden','false');document.body.style.overflow='hidden'}function closeDrawer(){var drawer=document.getElementById('rem-drawer');drawer.classList.remove('open');drawer.setAttribute('aria-hidden','true');document.body.style.overflow=''}function sortNamespaces(btn){document.querySelectorAll('.sort-btn').forEach(function(b){b.classList.remove('active')});btn.classList.add('active');var mode=btn.dataset.sort;document.querySelectorAll('.tier-section').forEach(function(tier){var parent=tier.querySelector('.ns-section')?.parentElement;if(!parent)return;var sections=Array.from(parent.querySelectorAll('.ns-section'));sections.sort(function(a,b){if(mode==='alpha')return a.dataset.label.localeCompare(b.dataset.label);if(mode==='count')return parseInt(b.dataset.count)-parseInt(a.dataset.count);var sa=a.dataset.sev.split(',').map(Number),sb=b.dataset.sev.split(',').map(Number);for(var i=0;i<5;i++){if(sa[i]!==sb[i])return sb[i]-sa[i]}return 0});sections.forEach(function(s){parent.appendChild(s)})})}function toggleDarkMode(){var html=document.documentElement;if(html.classList.contains('dark')){html.classList.remove('dark');html.classList.add('light')}else{html.classList.remove('light');html.classList.add('dark')}}var sevWeight={Critical:5,High:4,Medium:3,Low:2,Info:1};document.querySelectorAll('.sortable-th').forEach(function(th){th.addEventListener('click',function(){var table=th.closest('table');var tbody=table.querySelector('tbody');var idx=Array.from(th.parentElement.children).indexOf(th);var sortType=th.dataset.sort;var dir='asc';if(th.classList.contains('sort-asc'))dir='desc';else if(th.classList.contains('sort-desc'))dir='none';table.querySelectorAll('.sortable-th').forEach(function(h){h.classList.remove('sort-asc','sort-desc')});if(dir==='none'){return}th.classList.add('sort-'+dir);var rows=Array.from(tbody.querySelectorAll('tr'));rows.sort(function(a,b){var av,bv;if(sortType==='severity'){av=sevWeight[a.dataset.sevWeight]||0;bv=sevWeight[b.dataset.sevWeight]||0}else if(sortType==='num'){av=parseInt(a.children[idx].textContent)||0;bv=parseInt(b.children[idx].textContent)||0}else{av=a.children[idx].textContent.trim().toLowerCase();bv=b.children[idx].textContent.trim().toLowerCase();return dir==='asc'?av.localeCompare(bv):bv.localeCompare(av)}return dir==='asc'?av-bv:bv-av});rows.forEach(function(r){tbody.appendChild(r)})})});function toggleHelp(){document.getElementById('help-overlay').classList.toggle('hidden')}document.addEventListener('keydown',function(e){if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;var tabs=['all-findings','by-namespace','by-check','compliance'];if(e.key==='Escape'){var drawer=document.getElementById('rem-drawer');if(drawer&&drawer.classList.contains('open')){closeDrawer();e.preventDefault();return}var overlay=document.getElementById('help-overlay');if(!overlay.classList.contains('hidden')){overlay.classList.add('hidden');e.preventDefault();return}}if(e.key>='1'&&e.key<='4'){var idx=parseInt(e.key)-1;var btn=document.querySelector('.pill-tab[data-tab="'+tabs[idx]+'"]');if(btn){switchTab(btn);e.preventDefault()}}else if(e.key==='f'){var s=document.getElementById('search');if(s){s.focus();e.preventDefault()}}else if(e.key==='e'){toggleAll();e.preventDefault()}else if(e.key==='d'){toggleDarkMode();e.preventDefault()}else if(e.key==='?'){toggleHelp();e.preventDefault()}});function downloadBlob(data,filename,mime){var blob=new Blob([data],{type:mime});var url=URL.createObjectURL(blob);var a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url)}function exportJSON(){var findings=getFindings();var cm=getCheckerMeta();var qf=document.querySelector('.qf-btn.active');var filter=qf?qf.dataset.severity:'all';if(filter!=='all'){findings=filter==='others'?findings.filter(function(f){return f.severity!=='Critical'&&f.severity!=='High'}):findings.filter(function(f){return f.severity===filter})}var enriched=findings.map(function(f){var m=cm[f.checker]||{};return{checker:f.checker,severity:f.severity,resource:f.resource,namespace:f.namespace,kind:f.kind,container:f.container,message:f.message,remediation:m.r||'',field_path:f.field_path,frameworks:m.fw||'',control_ids:m.ci||'',category:m.ca||''}});downloadBlob(JSON.stringify(enriched,null,2),'kubevigil-findings.json','application/json')}function exportCSV(){var findings=getFindings();var cm=getCheckerMeta();var qf=document.querySelector('.qf-btn.active');var filter=qf?qf.dataset.severity:'all';if(filter!=='all'){findings=filter==='others'?findings.filter(function(f){return f.severity!=='Critical'&&f.severity!=='High'}):findings.filter(function(f){return f.severity===filter})}var cols=['checker','severity','category','resource','namespace','kind','container','message','remediation','field_path','frameworks','control_ids'];var rows=[cols.join(',')];findings.forEach(function(f){var m=cm[f.checker]||{};var row={checker:f.checker,severity:f.severity,resource:f.resource,namespace:f.namespace||'',kind:f.kind,container:f.container||'',message:f.message,field_path:f.field_path||'',remediation:m.r||'',frameworks:m.fw||'',control_ids:m.ci||'',category:m.ca||''};rows.push(cols.map(function(c){var v=(row[c]||'').toString().replace(/"/g,'""');return '"'+v+'"'}).join(','))});downloadBlob(rows.join('\n'),'kubevigil-findings.csv','text/csv')}initFindings();`

// formatFrameworksHTML returns framework references as colored pill badges.
func formatFrameworksHTML(refs []checker.FrameworkRef) template.HTML {
	if len(refs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, ref := range refs {
		if i > 0 {
			b.WriteString(" ")
		}
		cls := "fw-badge"
		switch strings.ToLower(ref.Framework) {
		case "cis":
			cls += " fw-cis"
		case "mitre":
			cls += " fw-mitre"
		case "nsa":
			cls += " fw-nsa"
		}
		b.WriteString(`<span class="`)
		b.WriteString(cls)
		b.WriteString(`">`)
		b.WriteString(template.HTMLEscapeString(strings.ToUpper(ref.Framework)))
		b.WriteString(" ")
		b.WriteString(template.HTMLEscapeString(ref.ControlID))
		b.WriteString("</span>")
	}
	return template.HTML(b.String())
}

// computeDonutSegments builds SVG circle segments for a severity donut chart.
// Each segment is a circle with stroke-dasharray and stroke-dashoffset.
// Uses r=40 with circumference ~251.33.
func computeDonutSegments(counts map[checker.Severity]int) []htmlDonutSegment {
	total := 0
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return nil
	}

	const circumference = 251.33 // 2*pi*40
	type sevColor struct {
		sev   checker.Severity
		color string
	}
	order := []sevColor{
		{checker.SeverityCritical, "var(--color-critical)"},
		{checker.SeverityHigh, "var(--color-high)"},
		{checker.SeverityMedium, "var(--color-medium)"},
		{checker.SeverityLow, "var(--color-low)"},
		{checker.SeverityInfo, "var(--color-info)"},
	}

	var segments []htmlDonutSegment
	offset := 0.0
	for _, sc := range order {
		count := counts[sc.sev]
		if count == 0 {
			continue
		}
		arcLen := circumference * float64(count) / float64(total)
		segments = append(segments, htmlDonutSegment{
			Color:      template.CSS(sc.color), //nolint:gosec // trusted severity color
			DashArray:  fmt.Sprintf("%.1f %.1f", arcLen, circumference-arcLen),
			DashOffset: fmt.Sprintf("%.1f", -offset),
		})
		offset += arcLen
	}
	return segments
}

// sortSectionsBySeverity sorts namespace sections by severity weight,
// putting namespaces with more critical findings first.
func sortSectionsBySeverity(sections []htmlSection) {
	sort.SliceStable(sections, func(i, j int) bool {
		wi := sections[i].Critical*10000 + sections[i].High*1000 + sections[i].Medium*100 + sections[i].Low*10 + sections[i].Info
		wj := sections[j].Critical*10000 + sections[j].High*1000 + sections[j].Medium*100 + sections[j].Low*10 + sections[j].Info
		return wi > wj
	})
}

// sumCounts totals all severity counts.
func sumCounts(counts map[checker.Severity]int) int {
	total := 0
	for _, c := range counts {
		total += c
	}
	return total
}

// passRate computes the percentage of checks that passed.
func passRate(cc CheckCoverage) int {
	if cc.TotalRun == 0 {
		return 0
	}
	return 100 * cc.Clean / cc.TotalRun
}

// buildNamespaceBars builds a sorted list of namespace bar chart data.
// Returns at most maxN entries sorted by severity weight.
func buildNamespaceBars(sections []htmlSection, maxN int) []htmlNamespaceBar {
	if len(sections) == 0 {
		return nil
	}

	// Sort by severity weight descending.
	sorted := make([]htmlSection, len(sections))
	copy(sorted, sections)
	sortSectionsBySeverity(sorted)

	if maxN > 0 && len(sorted) > maxN {
		sorted = sorted[:maxN]
	}

	// Find max total for normalization.
	maxTotal := 0
	for i := range sorted {
		if sorted[i].Count > maxTotal {
			maxTotal = sorted[i].Count
		}
	}
	if maxTotal == 0 {
		return nil
	}

	bars := make([]htmlNamespaceBar, len(sorted))
	for i := range sorted {
		bars[i] = htmlNamespaceBar{
			Label:    sorted[i].Label,
			Total:    sorted[i].Count,
			Critical: sorted[i].Critical,
			High:     sorted[i].High,
			Medium:   sorted[i].Medium,
			Low:      sorted[i].Low,
			Info:     sorted[i].Info,
			CritW:    barPct(sorted[i].Critical, maxTotal),
			HighW:    barPct(sorted[i].High, maxTotal),
			MedW:     barPct(sorted[i].Medium, maxTotal),
			LowW:     barPct(sorted[i].Low, maxTotal),
			InfoW:    barPct(sorted[i].Info, maxTotal),
		}
	}
	return bars
}

// barPct returns a percentage width (0-100) with a minimum of 1 when part > 0,
// preventing small severity segments from vanishing in bar charts.
func barPct(part, total int) int {
	if total == 0 || part == 0 {
		return 0
	}
	w := 100 * part / total
	if w == 0 {
		w = 1
	}
	return w
}

// buildFrameworkGroups groups findings by compliance framework and control.
func buildFrameworkGroups(findings []checker.Finding) []htmlFrameworkGroup {
	type controlKey struct {
		framework string
		controlID string
	}
	type controlData struct {
		title     string
		severity  checker.Severity
		resources map[string]struct{}
	}

	fwOrder := []string{}
	fwControls := make(map[string][]string) // framework -> ordered control IDs
	controlMap := make(map[controlKey]*controlData)
	seenControls := make(map[controlKey]bool)

	for i := range findings {
		for _, ref := range findings[i].Frameworks {
			fw := strings.ToUpper(ref.Framework)
			ck := controlKey{fw, ref.ControlID}

			cd, ok := controlMap[ck]
			if !ok {
				cd = &controlData{
					title:     ref.Title,
					severity:  findings[i].Severity,
					resources: make(map[string]struct{}),
				}
				controlMap[ck] = cd
				if !seenControls[ck] {
					seenControls[ck] = true
					if _, hasFW := fwControls[fw]; !hasFW {
						fwOrder = append(fwOrder, fw)
					}
					fwControls[fw] = append(fwControls[fw], ref.ControlID)
				}
			}
			if findings[i].Severity > cd.severity {
				cd.severity = findings[i].Severity
			}
			res := formatResource(&findings[i])
			cd.resources[res] = struct{}{}
		}
	}

	sort.Strings(fwOrder)
	totals := frameworks.ControlCounts()
	allIDs := frameworks.AllControlIDs()

	var groups []htmlFrameworkGroup
	for _, fw := range fwOrder {
		controlIDs := fwControls[fw]
		failedSet := make(map[string]bool, len(controlIDs))
		var controls []htmlControlGroup
		for _, cid := range controlIDs {
			failedSet[cid] = true
			cd := controlMap[controlKey{fw, cid}]
			resources := make([]string, 0, len(cd.resources))
			for r := range cd.resources {
				resources = append(resources, r)
			}
			sort.Strings(resources)
			totalCount := len(resources)
			truncated := 0
			if len(resources) > maxComplianceResources {
				truncated = len(resources) - maxComplianceResources
				resources = resources[:maxComplianceResources]
			}
			controls = append(controls, htmlControlGroup{
				ControlID: cid,
				Title:     cd.title,
				Severity:  cd.severity.String(),
				Count:     totalCount,
				Resources: resources,
				Truncated: truncated,
			})
		}
		total := max(totals[strings.ToLower(fw)], len(controls))
		passed := total - len(controls)
		passRate := 0
		if total > 0 {
			passRate = 100 * passed / total
		}
		// Compute passed control IDs: all controls minus failing ones.
		var passedIDs []string
		for _, id := range allIDs[strings.ToLower(fw)] {
			if !failedSet[id] {
				passedIDs = append(passedIDs, id)
			}
		}
		groups = append(groups, htmlFrameworkGroup{
			Framework:        fw,
			Controls:         controls,
			TotalCtrl:        total,
			PassedCtrl:       passed,
			PassRate:         passRate,
			PassRateColor:    scoreToColor(passRate),
			PassedControlIDs: passedIDs,
		})
	}
	return groups
}

// buildComplianceSummary derives a compact compliance overview from framework groups.
func buildComplianceSummary(groups []htmlFrameworkGroup) []htmlComplianceSummary {
	if len(groups) == 0 {
		return nil
	}
	out := make([]htmlComplianceSummary, len(groups))
	for i, g := range groups {
		out[i] = htmlComplianceSummary{
			Framework:      g.Framework,
			ControlsFailed: len(g.Controls),
			ControlsTotal:  g.TotalCtrl,
			Pct:            g.PassRate,
			PctColor:       pctColor(g.PassRate),
			PassedCount:    g.PassedCtrl,
		}
	}
	return out
}

// buildCategoryStats groups findings by checker category and computes per-category stats.
func buildCategoryStats(findings []checker.Finding, catMap map[string]string) []htmlCategoryStat {
	if len(catMap) == 0 {
		return nil
	}

	type catData struct {
		counts    map[checker.Severity]int
		resources map[string]struct{}
	}

	cats := make(map[string]*catData)
	catOrder := make([]string, 0)

	for i := range findings {
		cat := catMap[findings[i].Checker]
		if cat == "" {
			cat = "Other"
		}
		cd, ok := cats[cat]
		if !ok {
			cd = &catData{
				counts:    make(map[checker.Severity]int),
				resources: make(map[string]struct{}),
			}
			cats[cat] = cd
			catOrder = append(catOrder, cat)
		}
		cd.counts[findings[i].Severity]++
		res := formatResource(&findings[i])
		cd.resources[res] = struct{}{}
	}

	sort.Strings(catOrder)

	stats := make([]htmlCategoryStat, 0, len(catOrder))
	for _, cat := range catOrder {
		cd := cats[cat]
		total := 0
		for _, c := range cd.counts {
			total += c
		}
		stats = append(stats, htmlCategoryStat{
			Category:  checker.CategoryDisplayName(cat),
			Count:     total,
			Resources: len(cd.resources),
			Critical:  cd.counts[checker.SeverityCritical],
			High:      cd.counts[checker.SeverityHigh],
			Medium:    cd.counts[checker.SeverityMedium],
			Low:       cd.counts[checker.SeverityLow],
			Info:      cd.counts[checker.SeverityInfo],
		})
	}
	return stats
}

// maxPrintFindingRows caps the total finding rows in the workload drilldown
// to avoid excessively long PDF output.
const maxPrintFindingRows = 500

// sectionSevWeight computes a sort weight for a namespace section.
func sectionSevWeight(crit, high, med, low, info int) int {
	return crit*10000 + high*1000 + med*100 + low*10 + info
}

// parseSev converts a severity string to Severity, defaulting to Info.
func parseSev(s string) checker.Severity {
	sev, err := checker.ParseSeverity(s)
	if err != nil {
		return checker.SeverityInfo
	}
	return sev
}

// buildPrintTriage builds the Namespace Triage table from all three tiers.
func buildPrintTriage(app, infra, cluster []htmlSection) []htmlPrintNamespaceTriage {
	type entry struct {
		ns   string
		tier string
		htmlSection
		workloads int
		topIssue  string
	}

	var entries []entry
	addSections := func(sections []htmlSection, tier string) {
		for i := range sections {
			sec := &sections[i]
			resources := make(map[string]struct{})
			var worstSev checker.Severity
			var worstChecker string
			for j := range sec.Findings {
				f := &sec.Findings[j]
				res := f.Resource
				if res != "" {
					resources[res] = struct{}{}
				}
				sev := parseSev(f.Severity)
				if sev > worstSev || (sev == worstSev && worstChecker == "") {
					worstSev = sev
					worstChecker = f.Checker
				}
			}
			entries = append(entries, entry{
				ns:          sec.Label,
				tier:        tier,
				htmlSection: *sec,
				workloads:   len(resources),
				topIssue:    worstChecker,
			})
		}
	}
	addSections(app, "App")
	addSections(infra, "Infra")
	addSections(cluster, "Cluster")

	// Sort by severity weight descending.
	sort.SliceStable(entries, func(i, j int) bool {
		wi := sectionSevWeight(entries[i].Critical, entries[i].High, entries[i].Medium, entries[i].Low, entries[i].Info)
		wj := sectionSevWeight(entries[j].Critical, entries[j].High, entries[j].Medium, entries[j].Low, entries[j].Info)
		return wi > wj
	})

	out := make([]htmlPrintNamespaceTriage, len(entries))
	for i := range entries {
		e := &entries[i]
		out[i] = htmlPrintNamespaceTriage{
			Rank:      i + 1,
			Namespace: e.ns,
			Tier:      e.tier,
			Total:     e.Count,
			Critical:  e.Critical,
			High:      e.High,
			Medium:    e.Medium,
			Low:       e.Low,
			Info:      e.Info,
			Workloads: e.workloads,
			TopIssue:  e.topIssue,
		}
	}
	return out
}

// buildPrintNamespaceDetails builds the workload drilldown for Critical & High findings.
func buildPrintNamespaceDetails(app, infra, cluster []htmlSection) (details []htmlPrintNamespaceDetail, totalFindings int) {
	type nsKey struct {
		label string
		tier  string
	}
	nsMap := make(map[nsKey]*htmlPrintNamespaceDetail)
	var nsOrder []nsKey

	processSections := func(sections []htmlSection, tier string) {
		for i := range sections {
			sec := &sections[i]
			key := nsKey{label: sec.Label, tier: tier}
			for j := range sec.Findings {
				f := &sec.Findings[j]
				sev := parseSev(f.Severity)
				if sev != checker.SeverityCritical && sev != checker.SeverityHigh {
					continue
				}
				nd, ok := nsMap[key]
				if !ok {
					nd = &htmlPrintNamespaceDetail{
						Namespace: sec.Label,
						Tier:      tier,
					}
					nsMap[key] = nd
					nsOrder = append(nsOrder, key)
				}
				nd.Total++
				if sev == checker.SeverityCritical {
					nd.Critical++
				} else {
					nd.High++
				}

				// Find or create workload.
				res := f.Resource
				if res == "" {
					res = "(cluster)"
				}
				var wl *htmlPrintWorkload
				for wi := range nd.Workloads {
					if nd.Workloads[wi].Resource == res {
						wl = &nd.Workloads[wi]
						break
					}
				}
				if wl == nil {
					nd.Workloads = append(nd.Workloads, htmlPrintWorkload{Resource: res})
					wl = &nd.Workloads[len(nd.Workloads)-1]
				}
				wl.Total++
				if sev == checker.SeverityCritical {
					wl.Critical++
				} else {
					wl.High++
				}
				wl.Findings = append(wl.Findings, htmlPrintWorkloadFinding{
					Severity:  f.Severity,
					Checker:   f.Checker,
					Container: f.Container,
					FieldPath: f.FieldPath,
					Message:   f.Message,
				})
			}
		}
	}

	processSections(app, "App")
	processSections(infra, "Infra")
	processSections(cluster, "Cluster")

	// Sort namespaces by severity weight.
	sort.SliceStable(nsOrder, func(i, j int) bool {
		a, b := nsMap[nsOrder[i]], nsMap[nsOrder[j]]
		wa := sectionSevWeight(a.Critical, a.High, 0, 0, 0)
		wb := sectionSevWeight(b.Critical, b.High, 0, 0, 0)
		return wa > wb
	})

	// Sort workloads within each namespace by severity weight.
	for _, key := range nsOrder {
		nd := nsMap[key]
		sort.SliceStable(nd.Workloads, func(i, j int) bool {
			wi := nd.Workloads[i].Critical*10000 + nd.Workloads[i].High*1000
			wj := nd.Workloads[j].Critical*10000 + nd.Workloads[j].High*1000
			return wi > wj
		})
	}

	// Build result and apply cap.
	var result []htmlPrintNamespaceDetail
	totalRows := 0
	truncated := 0
	for _, key := range nsOrder {
		nd := nsMap[key]
		for _, wl := range nd.Workloads {
			totalRows += len(wl.Findings)
		}
		result = append(result, *nd)
	}
	if totalRows > maxPrintFindingRows {
		truncated = totalRows - maxPrintFindingRows
	}
	return result, truncated
}

// buildPrintNamespaceRows builds enhanced namespace rows with top workloads column.
func buildPrintNamespaceRows(sections []htmlSection, maxWorkloads int) []htmlPrintNamespaceRow {
	rows := make([]htmlPrintNamespaceRow, len(sections))
	for i := range sections {
		sec := &sections[i]
		// Count findings per resource and find top workloads by severity weight.
		type resStat struct {
			name string
			crit int
			high int
		}
		resMap := make(map[string]*resStat)
		for j := range sec.Findings {
			f := &sec.Findings[j]
			res := f.Resource
			if res == "" {
				continue
			}
			rs, ok := resMap[res]
			if !ok {
				rs = &resStat{name: res}
				resMap[res] = rs
			}
			switch f.Severity {
			case "Critical":
				rs.crit++
			case "High":
				rs.high++
			}
		}
		// Sort resources by severity weight.
		resList := make([]*resStat, 0, len(resMap))
		for _, rs := range resMap {
			resList = append(resList, rs)
		}
		sort.SliceStable(resList, func(a, b int) bool {
			wa := resList[a].crit*10000 + resList[a].high*1000
			wb := resList[b].crit*10000 + resList[b].high*1000
			if wa != wb {
				return wa > wb
			}
			return resList[a].name < resList[b].name
		})
		n := min(maxWorkloads, len(resList))
		names := make([]string, n)
		for j := range n {
			names[j] = resList[j].name
		}
		rows[i] = htmlPrintNamespaceRow{
			Label:        sec.Label,
			Total:        sec.Count,
			Critical:     sec.Critical,
			High:         sec.High,
			Medium:       sec.Medium,
			Low:          sec.Low,
			Info:         sec.Info,
			TopWorkloads: strings.Join(names, ", "),
		}
	}
	return rows
}

// buildExecActions generates 3-5 actionable bullet points from the top aggregates.
func buildExecActions(topAggs []htmlAggregate, app, infra, cluster []htmlSection) []string {
	var actions []string
	for _, agg := range topAggs {
		if len(actions) >= 5 {
			break
		}
		if agg.Severity != "Critical" && agg.Severity != "High" {
			continue
		}
		// Collect affected namespaces.
		var nsNames []string
		for _, sections := range [][]htmlSection{app, infra, cluster} {
			for si := range sections {
				for fi := range sections[si].Findings {
					if sections[si].Findings[fi].Checker == agg.Checker {
						if !slices.Contains(nsNames, sections[si].Label) {
							nsNames = append(nsNames, sections[si].Label)
						}
					}
				}
			}
		}
		var nsPart string
		if len(nsNames) > 3 {
			nsPart = fmt.Sprintf("%s, %s, and %d more", nsNames[0], nsNames[1], len(nsNames)-2)
		} else if len(nsNames) > 0 {
			nsPart = strings.Join(nsNames, ", ")
		}
		action := fmt.Sprintf("Fix %s across %d workloads", agg.Checker, agg.Resources)
		if nsPart != "" {
			action += " in " + nsPart
		}
		actions = append(actions, action)
	}
	return actions
}

// gradeHint returns a human-readable hint for a posture score grade.
func gradeHint(score int) string {
	switch {
	case score >= 80:
		return "Excellent"
	case score >= 60:
		return "Good"
	case score >= 40:
		return "Needs Attention"
	case score >= 20:
		return "At Risk"
	default:
		return "Critical"
	}
}

func makeHTMLAggregates(aggs []CheckAggregate, fwMap map[string]template.HTML, descMap map[string]string) []htmlAggregate {
	out := make([]htmlAggregate, len(aggs))
	for i := range aggs {
		out[i] = htmlAggregate{
			Severity:     aggs[i].Severity.String(),
			Checker:      aggs[i].Checker,
			Description:  descMap[aggs[i].Checker],
			Count:        aggs[i].Count,
			Resources:    aggs[i].Resources,
			AppCount:     aggs[i].AppCount,
			InfraCount:   aggs[i].InfraCount,
			ClusterCount: aggs[i].ClusterCount,
			Frameworks:   fwMap[aggs[i].Checker],
		}
	}
	return out
}

// stripNamespacePrefix removes the namespace prefix from a resource path.
// For example, "default/Deployment/nginx" → "Deployment/nginx" when ns is "default".
// Cluster-scoped resources (empty ns) are returned unchanged.
func stripNamespacePrefix(path, ns string) string {
	if ns == "" {
		return path
	}
	prefix := ns + "/"
	if strings.HasPrefix(path, prefix) {
		return path[len(prefix):]
	}
	return path
}

// formatWithCommas adds thousands separators to an integer.
// Example: 6965 → "6,965", 1318 → "1,318".
func formatWithCommas(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	offset := len(s) % 3
	if offset > 0 {
		b.WriteString(s[:offset])
	}
	for i := offset; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// formatTimestamp formats a time for display in the report footer.
// Zero times return "unknown". Non-zero times use "2 Jan 2006, 15:04 MST".
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2 Jan 2006, 15:04 MST")
}

// formatFrameworkColumns groups framework references into pipe-delimited strings.
// Returns two strings: "CIS | MITRE | NSA" and "5.2.1 | T1611 | 3.1".
func formatFrameworkColumns(refs []checker.FrameworkRef) (fwNames, controlIDs string) {
	type fwGroup struct {
		name string
		cids []string
	}
	var groups []fwGroup
	seen := map[string]int{} // framework name → index in groups
	for _, ref := range refs {
		name := strings.ToUpper(ref.Framework)
		if idx, ok := seen[name]; ok {
			groups[idx].cids = append(groups[idx].cids, ref.ControlID)
		} else {
			seen[name] = len(groups)
			groups = append(groups, fwGroup{name: name, cids: []string{ref.ControlID}})
		}
	}
	fws := make([]string, len(groups))
	cids := make([]string, len(groups))
	for j, g := range groups {
		fws[j] = g.name
		cids[j] = strings.Join(g.cids, ", ")
	}
	return strings.Join(fws, " | "), strings.Join(cids, " | ")
}

// buildCheckerMetaJSON builds a per-checker metadata blob for deduplication.
// Each checker name maps to its remediation text, frameworks, control IDs, and category.
// This avoids repeating per-checker data in every finding row.
func buildCheckerMetaJSON(findings []checker.Finding, categories map[string]string) template.JS {
	type checkerMeta struct {
		Remediation string `json:"r,omitempty"`
		Frameworks  string `json:"fw,omitempty"`
		ControlIDs  string `json:"ci,omitempty"`
		Category    string `json:"ca,omitempty"`
	}
	meta := make(map[string]*checkerMeta, len(findings))
	for i := range findings {
		name := findings[i].Checker
		if _, exists := meta[name]; exists {
			continue
		}
		m := &checkerMeta{}
		if findings[i].Remediation != "" {
			m.Remediation = findings[i].Remediation
		}
		if len(findings[i].Frameworks) > 0 {
			m.Frameworks, m.ControlIDs = formatFrameworkColumns(findings[i].Frameworks)
		}
		if categories != nil {
			m.Category = categories[name]
		}
		meta[name] = m
	}
	b, _ := json.Marshal(meta)
	return template.JS(b) //nolint:gosec // trusted data
}

// buildFindingsJSON serializes findings into a columnar JSON format for client-side use.
// Column-oriented format reduces key name overhead: {c:[...],s:[...],r:[...],...}
// Per-checker fields (remediation, frameworks, category) are in checker-meta instead.
func buildFindingsJSON(findings []checker.Finding, _ map[string]string) template.JS {
	type columnarFindings struct {
		Checker   []string `json:"c"`
		Severity  []string `json:"s"`
		Resource  []string `json:"r"`
		Namespace []string `json:"n"`
		Kind      []string `json:"k"`
		Container []string `json:"t"`
		Message   []string `json:"m"`
		FieldPath []string `json:"f"`
	}
	n := len(findings)
	cf := columnarFindings{
		Checker:   make([]string, n),
		Severity:  make([]string, n),
		Resource:  make([]string, n),
		Namespace: make([]string, n),
		Kind:      make([]string, n),
		Container: make([]string, n),
		Message:   make([]string, n),
		FieldPath: make([]string, n),
	}
	for i := range findings {
		cf.Checker[i] = findings[i].Checker
		cf.Severity[i] = findings[i].Severity.String()
		cf.Resource[i] = findings[i].Resource
		cf.Namespace[i] = findings[i].Namespace
		cf.Kind[i] = findings[i].Kind
		cf.Container[i] = findings[i].Container
		cf.Message[i] = findings[i].Message
		cf.FieldPath[i] = findings[i].FieldPath
	}
	b, _ := json.Marshal(cf)
	return template.JS(b) //nolint:gosec // trusted data
}

func buildExecSummary(summary *ExecutiveSummary, topAggs []htmlAggregate) string {
	grade := scoreToGrade(summary.PostureScore)
	var b strings.Builder

	fmt.Fprintf(&b, "Your cluster scores %s (%d/100).", grade, summary.PostureScore)

	// Identify top risk areas from critical/high checks.
	var riskParts []string
	for _, agg := range topAggs {
		if len(riskParts) >= 3 {
			break
		}
		if agg.Severity == "Critical" || agg.Severity == "High" {
			riskParts = append(riskParts, fmt.Sprintf("%s (%d findings)", agg.Checker, agg.Count))
		}
	}
	if len(riskParts) > 0 {
		b.WriteString(" Key risk areas include ")
		for i, part := range riskParts {
			if i > 0 && i == len(riskParts)-1 {
				b.WriteString(", and ")
			} else if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(part)
		}
		b.WriteString(".")
	}

	crit := summary.SeverityCounts[checker.SeverityCritical]
	if crit > 0 {
		fmt.Fprintf(&b, " Immediate attention is recommended for the %d Critical findings.", crit)
	} else if summary.PostureScore >= 80 {
		b.WriteString(" The cluster demonstrates a strong security posture.")
	}

	return b.String()
}

// scoreToColor returns a contextual color based on score value.
// pctColor returns a hex color for a compliance pass-rate percentage.
// Red <30%, amber 30-60%, green >60%.
func pctColor(pct int) string {
	switch {
	case pct > 60:
		return "#10b981"
	case pct >= 30:
		return "#f9a825"
	default:
		return "#dc2626"
	}
}

// findingsColor returns a color reflecting the worst severity present.
func findingsColor(crit, high, med, low, info int) string {
	switch {
	case crit > 0:
		return "#dc2626" // critical red
	case high > 0:
		return "#ea580c" // high orange
	case med > 0:
		return "#d97706" // medium amber
	case low > 0:
		return "#0284c7" // low blue
	case info > 0:
		return "#6b7280" // info gray
	default:
		return "#10b981" // clean green
	}
}

func scoreToColor(score int) string {
	switch {
	case score >= 80:
		return "#10b981" // green
	case score >= 60:
		return "#65a30d" // lime
	case score >= 40:
		return "#f9a825" // amber
	case score >= 20:
		return "#ea580c" // orange
	default:
		return "#dc2626" // red
	}
}

// scoreToGrade returns a letter grade based on posture score.
func scoreToGrade(score int) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 60:
		return "B"
	case score >= 40:
		return "C"
	case score >= 20:
		return "D"
	default:
		return "F"
	}
}

func init() {
	register(&HTMLReporter{})
}
