package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/stribog-cloud/kubevigil/internal/baseline"
	"github.com/stribog-cloud/kubevigil/internal/checker"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cloud"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cluster"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/crd"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/image"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/network"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/psa"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/rbac"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/scheduling"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/secrets"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/storage"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/supply_chain"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
	"github.com/stribog-cloud/kubevigil/internal/k8s"
	"github.com/stribog-cloud/kubevigil/internal/policy"
	"github.com/stribog-cloud/kubevigil/internal/report"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

var (
	flagFile                    string
	flagKubeconfig              string
	flagContext                 string
	flagNamespace               string
	flagExcludeNamespace        string
	flagSeverity                string
	flagFailOn                  string
	flagFramework               string
	flagConcurrency             int
	flagIncludeManaged          bool
	flagIncludeSystemNamespaces bool
	flagExcludeInfra            bool
	flagNoAggregate             bool
	flagSummaryOnly             bool
	flagPolicyFile              string
	flagBaseline                string
	flagSaveBaseline            string
	flagFailOnNew               bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Kubernetes resources for security issues",
	Long:  "Scan a live cluster or YAML manifests for security misconfigurations.",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&flagFile, "file", "f", "", "path to YAML file or directory (manifest mode)")
	scanCmd.Flags().StringVar(&flagKubeconfig, "kubeconfig", "", "path to kubeconfig file")
	scanCmd.Flags().StringVar(&flagContext, "context", "", "kubeconfig context to use")
	scanCmd.Flags().StringVarP(&flagNamespace, "namespace", "n", "", "scan only this namespace")
	scanCmd.Flags().StringVar(&flagExcludeNamespace, "exclude-namespace", "", "exclude this namespace")
	scanCmd.Flags().StringVar(&flagSeverity, "severity", "", "minimum severity to report (info, low, medium, high, critical)")
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "", "minimum severity for exit code 1 (overrides config)")
	scanCmd.Flags().StringVar(&flagFramework, "framework", "", "filter findings by compliance framework (cis, mitre, nsa)")
	scanCmd.Flags().IntVar(&flagConcurrency, "concurrency", 0, "max concurrent checks (overrides config)")
	scanCmd.Flags().BoolVar(&flagIncludeManaged, "include-managed", false, "include managed Pods and ReplicaSets (normally filtered to avoid duplicates)")
	scanCmd.Flags().BoolVar(&flagIncludeSystemNamespaces, "include-system-namespaces", false, "include system namespaces (kube-system, kube-public, kube-node-lease)")
	scanCmd.Flags().BoolVar(&flagExcludeInfra, "exclude-infra", false, "exclude infrastructure namespaces (monitoring, rook-ceph, calico, etc.)")
	scanCmd.Flags().BoolVar(&flagNoAggregate, "no-aggregate", false, "show every finding individually instead of grouping by check")
	scanCmd.Flags().BoolVar(&flagSummaryOnly, "summary-only", false, "show only the summary table (text output only)")
	scanCmd.Flags().StringVar(&flagPolicyFile, "policy-file", "", "path to a custom CEL policy file or directory (evaluated alongside built-in checks)")
	scanCmd.Flags().StringVar(&flagBaseline, "baseline", "", "path to a baseline file; findings are annotated new/existing against it")
	scanCmd.Flags().StringVar(&flagSaveBaseline, "save-baseline", "", "write a baseline file from this scan's findings and exit 0")
	scanCmd.Flags().BoolVar(&flagFailOnNew, "fail-on-new", false, "exit 1 only when findings are NEW relative to --baseline (ignores severity threshold)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
	setupLogging()
	if flagNoColor {
		color.NoColor = true
	}

	// Load config.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		return &exitError{code: 3, err: err}
	}

	// Apply CLI overrides.
	if flagFailOn != "" {
		cfg.Settings.FailOn = flagFailOn
	}
	if flagSeverity != "" {
		cfg.Settings.SeverityThreshold = flagSeverity
	}
	if flagConcurrency > 0 {
		cfg.Settings.Concurrency = flagConcurrency
	}
	if flagIncludeManaged {
		cfg.Settings.IncludeManaged = true
	}
	if flagIncludeSystemNamespaces {
		cfg.Settings.IncludeSystemNamespaces = true
	}
	if flagExcludeInfra {
		cfg.Settings.ExcludeInfra = true
	}
	if flagNoAggregate {
		cfg.Settings.NoAggregate = true
	}

	// Build the checker registry for THIS scan: a fresh registry seeded from the
	// built-in checks, plus any user-defined CEL policies from the config's
	// customPolicies block and/or --policy-file. Customs are never registered
	// into the shared DefaultRegistry singleton — that would leak state across
	// in-process scans and into `list checks`.
	registry := checker.NewRegistry()
	for _, c := range checker.DefaultRegistry().All() {
		registry.MustRegister(c)
	}
	if regErr := registerCustomPolicies(registry, cfg); regErr != nil {
		fmt.Fprintf(os.Stderr, "Policy error: %v\n", regErr)
		return &exitError{code: 3, err: regErr}
	}

	// Create scanner.
	scanner := engine.NewScanner(registry, cfg)

	// Create context with timeout.
	timeout := config.GetTimeout(cfg)
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	// Run scan.
	var result *checker.ScanResult
	if flagFile != "" {
		result, err = scanner.ScanManifest(ctx, flagFile)
	} else {
		dynClient, discClient, clientErr := k8s.NewClient(flagKubeconfig, flagContext)
		if clientErr != nil {
			return fmt.Errorf("connecting to cluster: %w", clientErr)
		}
		result, err = scanner.ScanLive(ctx, dynClient, discClient)
		if err == nil {
			result.ClusterInfo.ContextName = resolveContextName(flagKubeconfig, flagContext)
		}
	}
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	// Filter by severity threshold.
	if cfg.Settings.SeverityThreshold != "" && cfg.Settings.SeverityThreshold != "info" {
		threshold, threshErr := checker.ParseSeverity(cfg.Settings.SeverityThreshold)
		if threshErr != nil {
			return fmt.Errorf("invalid severity threshold %q: %w (valid: info, low, medium, high, critical)", cfg.Settings.SeverityThreshold, threshErr)
		}
		filtered := make([]checker.Finding, 0, len(result.Findings))
		for i := range result.Findings {
			if result.Findings[i].Severity >= threshold {
				filtered = append(filtered, result.Findings[i])
			}
		}
		result.Findings = filtered
	}

	// Filter by namespace.
	if flagNamespace != "" {
		result.Findings = filterByNamespace(result.Findings, flagNamespace)
	}
	if flagExcludeNamespace != "" {
		filtered := make([]checker.Finding, 0, len(result.Findings))
		for i := range result.Findings {
			if result.Findings[i].Namespace != flagExcludeNamespace {
				filtered = append(filtered, result.Findings[i])
			}
		}
		result.Findings = filtered
	}

	// Filter out system namespaces by default.
	if !cfg.Settings.IncludeSystemNamespaces {
		filtered := make([]checker.Finding, 0, len(result.Findings))
		for i := range result.Findings {
			if !config.IsSystemNamespace(result.Findings[i].Namespace) {
				filtered = append(filtered, result.Findings[i])
			}
		}
		result.Findings = filtered
	}

	// Filter out infrastructure namespaces if requested.
	if cfg.Settings.ExcludeInfra {
		filtered := make([]checker.Finding, 0, len(result.Findings))
		for i := range result.Findings {
			if !config.IsInfraNamespace(cfg, result.Findings[i].Namespace) {
				filtered = append(filtered, result.Findings[i])
			}
		}
		result.Findings = filtered
	}

	// Filter by compliance framework.
	if flagFramework != "" {
		result.Findings = frameworks.FilterByFramework(result.Findings, flagFramework)
	}

	// Save a baseline from this scan's (filtered) findings and exit, if asked.
	if flagSaveBaseline != "" {
		// --save-baseline is a terminal action: it records the current findings
		// and exits, so combining it with --baseline / --fail-on-new (which
		// compare against a baseline) is contradictory. Reject it rather than
		// silently ignoring the comparison flags.
		if flagBaseline != "" || flagFailOnNew {
			err := fmt.Errorf("--save-baseline cannot be combined with --baseline or --fail-on-new")
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
			return &exitError{code: 3, err: err}
		}
		base := baseline.FromFindings(result.Findings)
		base.ToolVersion = version.Version
		if saveErr := base.Save(flagSaveBaseline); saveErr != nil {
			return &exitError{code: 3, err: saveErr}
		}
		fmt.Fprintf(os.Stderr, "Baseline written to %s (%d findings)\n", flagSaveBaseline, len(base.Fingerprints))
		return nil
	}

	// Annotate findings against a baseline (new/existing) if provided.
	var drift baseline.DiffResult
	baselineApplied := false
	if flagBaseline != "" {
		base, loadErr := baseline.Load(flagBaseline)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Baseline error: %v\n", loadErr)
			return &exitError{code: 3, err: loadErr}
		}
		drift = baseline.Annotate(base, result.Findings)
		baselineApplied = true
	}

	// Resolve output target: file path (by extension) or format name to stdout.
	out, outErr := resolveOutput(flagOutput)
	if outErr != nil {
		return fmt.Errorf("output: %w", outErr)
	}
	defer out.Close()

	// Generate report.
	var reporter report.Reporter
	if flagSummaryOnly && out.Format == "text" {
		reporter = &report.TextReporter{SummaryOnly: true}
	} else {
		var reporterErr error
		reporter, reporterErr = report.Get(out.Format)
		if reporterErr != nil {
			return fmt.Errorf("invalid output format: %w", reporterErr)
		}
	}
	// Inject config for namespace classification if the reporter supports it.
	if configurable, ok := reporter.(report.Configurable); ok {
		configurable.SetConfig(cfg)
	}
	if genErr := reporter.Generate(ctx, result, out.Writer); genErr != nil {
		return fmt.Errorf("generating report: %w", genErr)
	}

	// Report drift when a baseline was applied.
	if baselineApplied {
		fmt.Fprintf(os.Stderr, "Baseline drift: %d new, %d existing, %d resolved\n",
			drift.New, drift.Existing, drift.Resolved)
	}

	// --fail-on-new gates strictly on NEW findings relative to the baseline,
	// independent of the severity threshold. It requires --baseline.
	if flagFailOnNew {
		if !baselineApplied {
			err := fmt.Errorf("--fail-on-new requires --baseline")
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
			return &exitError{code: 3, err: err}
		}
		if drift.New > 0 {
			return &exitError{code: 1, err: fmt.Errorf("%d new findings relative to baseline", drift.New)}
		}
		return nil
	}

	// Check exit code based on fail-on severity.
	if hasFailures(result.Findings, config.FailOnSeverity(cfg)) {
		return &exitError{code: 1, err: fmt.Errorf("findings above threshold")}
	}
	return nil
}

// registerCustomPolicies compiles user-defined CEL policies from the config and
// the --policy-file (file or directory) and registers them into the registry.
// A duplicate ID (colliding with a built-in check or another policy) or a CEL
// compile error is returned so the caller can exit with a config error.
func registerCustomPolicies(registry *checker.Registry, cfg *config.Config) error {
	specs := append([]policy.Spec(nil), cfg.CustomPolicies...)
	if flagPolicyFile != "" {
		info, statErr := os.Stat(flagPolicyFile)
		if statErr != nil {
			return fmt.Errorf("reading policy path: %w", statErr)
		}
		var ps *policy.Set
		var loadErr error
		if info.IsDir() {
			ps, loadErr = policy.LoadDir(flagPolicyFile)
		} else {
			ps, loadErr = policy.LoadFile(flagPolicyFile)
		}
		if loadErr != nil {
			return loadErr
		}
		specs = append(specs, ps.Policies...)
	}
	if len(specs) == 0 {
		return nil
	}
	set := &policy.Set{Version: policy.SpecVersion, Policies: specs}
	if valErr := set.Validate(); valErr != nil {
		return valErr
	}
	celCheckers, err := policy.Checkers(set)
	if err != nil {
		return err
	}
	for _, c := range celCheckers {
		if regErr := registry.Register(c); regErr != nil {
			return fmt.Errorf("registering custom policy %q: %w", c.Name(), regErr)
		}
	}
	return nil
}

// filterByNamespace returns only findings whose Namespace matches the given namespace.
// Cluster-scoped findings (Namespace == "") are excluded — they do not belong to any namespace.
func filterByNamespace(findings []checker.Finding, ns string) []checker.Finding {
	filtered := make([]checker.Finding, 0, len(findings))
	for i := range findings {
		if findings[i].Namespace == ns {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}

// hasFailures returns true if any finding meets or exceeds the fail-on severity.
func hasFailures(findings []checker.Finding, failOn string) bool {
	threshold, err := checker.ParseSeverity(failOn)
	if err != nil {
		return false
	}
	for i := range findings {
		if findings[i].Severity >= threshold {
			return true
		}
	}
	return false
}

// loadConfig loads configuration from the --config flag, auto-discovery, or defaults.
func loadConfig() (*config.Config, error) {
	if flagConfig != "" {
		return config.Load(flagConfig)
	}
	path, err := config.Discover()
	if err != nil {
		return nil, err
	}
	if path != "" {
		return config.Load(path)
	}
	return config.Default(), nil
}

// resolveContextName returns the effective kubeconfig context name.
// If an explicit context was provided, it is returned as-is.
// Otherwise, the current-context from the kubeconfig is resolved.
func resolveContextName(kubeconfig, explicitContext string) string {
	if explicitContext != "" {
		return explicitContext
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	rawConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).RawConfig()
	if err != nil {
		return ""
	}
	return rawConfig.CurrentContext
}
