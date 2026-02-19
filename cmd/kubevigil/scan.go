package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/k8s"
	"github.com/stribog-cloud/kubevigil/internal/report"
)

var (
	flagFile             string
	flagKubeconfig       string
	flagContext          string
	flagNamespace        string
	flagExcludeNamespace string
	flagSeverity         string
	flagFailOn           string
	flagConcurrency      int
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
	scanCmd.Flags().IntVar(&flagConcurrency, "concurrency", 0, "max concurrent checks (overrides config)")
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

	// Create scanner.
	scanner := engine.NewScanner(checker.DefaultRegistry(), cfg)

	// Create context with timeout.
	timeout := config.GetTimeout(cfg)
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	// Run scan.
	var result *checker.ScanResult
	if flagFile != "" {
		result, err = scanner.ScanManifest(ctx, flagFile)
	} else {
		kubeconfig := flagKubeconfig
		if kubeconfig == "" {
			kubeconfig = os.Getenv("KUBECONFIG")
		}
		dynClient, discClient, clientErr := k8s.NewClient(kubeconfig, flagContext)
		if clientErr != nil {
			return fmt.Errorf("connecting to cluster: %w", clientErr)
		}
		result, err = scanner.ScanLive(ctx, dynClient, discClient)
	}
	if err != nil {
		return err
	}

	// Filter by severity threshold.
	if cfg.Settings.SeverityThreshold != "" && cfg.Settings.SeverityThreshold != "info" {
		threshold, threshErr := checker.ParseSeverity(cfg.Settings.SeverityThreshold)
		if threshErr == nil {
			filtered := make([]checker.Finding, 0, len(result.Findings))
			for i := range result.Findings {
				if result.Findings[i].Severity >= threshold {
					filtered = append(filtered, result.Findings[i])
				}
			}
			result.Findings = filtered
		}
	}

	// Generate report.
	reporter, reporterErr := report.Get(flagOutput)
	if reporterErr != nil {
		return fmt.Errorf("invalid output format: %w", reporterErr)
	}
	if genErr := reporter.Generate(ctx, result, os.Stdout); genErr != nil {
		return fmt.Errorf("generating report: %w", genErr)
	}

	// Check exit code based on fail-on severity.
	if hasFailures(result.Findings, config.FailOnSeverity(cfg)) {
		return &exitError{code: 1, err: fmt.Errorf("findings above threshold")}
	}
	return nil
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
