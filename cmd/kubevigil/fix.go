package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

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
	"github.com/stribog-cloud/kubevigil/internal/fix"
)

var (
	flagFixApply            bool
	flagFixYes              bool
	flagFixVerify           bool
	flagFixRiskLevel        string
	flagFixSystemNS         bool
	flagFixChecks           string
	flagFixSeverity         string
	flagFixNamespace        string
	flagFixExcludeNamespace string
	flagFixExcludeInfra     bool
	flagFixFingerprint      string
	flagFixOutput           string
	flagFixKustomize        string
	flagFixReport           string
	flagFixBackupDir        string
	flagFixGitPR            bool
)

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Auto-remediate security findings in Kubernetes manifests",
	Long: `Scans manifests, identifies fixable security issues, and patches them.
By default, shows what would change (dry-run). Use --apply to modify files.`,
	Args: cobra.ExactArgs(1),
	RunE: runFix,
}

func init() {
	// Execution control.
	fixCmd.Flags().BoolVar(&flagFixApply, "apply", false, "actually modify files (default: dry-run)")
	fixCmd.Flags().BoolVar(&flagFixYes, "yes", false, "skip interactive confirmation")
	fixCmd.Flags().BoolVar(&flagFixVerify, "verify", false, "re-scan after applying fixes")

	// Risk control.
	fixCmd.Flags().StringVar(&flagFixRiskLevel, "risk-level", "safe", "risk level for fixes (safe, moderate, aggressive)")
	fixCmd.Flags().BoolVar(&flagFixSystemNS, "i-understand-system-namespaces", false, "allow fixing resources in system namespaces")

	// Filtering.
	fixCmd.Flags().StringVar(&flagFixChecks, "checks", "", "comma-separated check IDs to fix")
	fixCmd.Flags().StringVar(&flagFixSeverity, "severity", "", "comma-separated severity levels to fix")
	fixCmd.Flags().StringVarP(&flagFixNamespace, "namespace", "n", "", "comma-separated namespaces to include")
	fixCmd.Flags().StringVar(&flagFixExcludeNamespace, "exclude-namespace", "", "comma-separated namespaces to exclude")
	fixCmd.Flags().BoolVar(&flagFixExcludeInfra, "exclude-infra", false, "exclude infrastructure namespaces")
	fixCmd.Flags().StringVar(&flagFixFingerprint, "fingerprint", "", "comma-separated finding fingerprints to fix")

	// Output control.
	fixCmd.Flags().StringVarP(&flagFixOutput, "output", "o", "diff", "output mode (diff, kubectl, helm-values)")
	fixCmd.Flags().StringVar(&flagFixKustomize, "kustomize", "", "path for Kustomize overlay output")
	fixCmd.Flags().StringVar(&flagFixReport, "report", "", "custom path for fix report")
	fixCmd.Flags().StringVar(&flagFixBackupDir, "backup-dir", "", "custom backup directory")

	// Git integration.
	fixCmd.Flags().BoolVar(&flagFixGitPR, "git-pr", false, "create branch and PR (requires gh/glab)")

	rootCmd.AddCommand(fixCmd)
}

func runFix(cmd *cobra.Command, args []string) error {
	setupLogging()
	if flagNoColor {
		color.NoColor = true
	}

	// Load config.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		return &exitError{code: fix.ExitFixConfigError, err: err}
	}

	// Parse risk level.
	riskLevel, err := fix.ParseRiskLevel(flagFixRiskLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return &exitError{code: fix.ExitFixConfigError, err: err}
	}

	// Validate output mode.
	validOutputModes := map[string]bool{"diff": true, "kubectl": true, "helm-values": true}
	if !validOutputModes[flagFixOutput] {
		err := fmt.Errorf("invalid output mode %q (valid: diff, kubectl, helm-values)", flagFixOutput)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return &exitError{code: fix.ExitFixConfigError, err: err}
	}

	// Build fix config from flags and config file.
	fixCfg := buildFixConfig(cfg, riskLevel)

	// CI mode / non-interactive detection.
	if fixCfg.Apply && !fixCfg.Yes && !isInteractive() {
		err := fmt.Errorf("--apply in non-interactive mode requires --yes flag")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Hint: Run 'kubevigil fix %s' first to review changes, then add --yes for CI.\n", args[0])
		return &exitError{code: fix.ExitFixConfigError, err: err}
	}

	// Create fix engine.
	fixReg := fix.DefaultRegistry()
	checkerReg := checker.DefaultRegistry()
	fixer := fix.NewFixer(fixReg, checkerReg, cfg, &fixCfg)

	// Create context.
	timeout := config.GetTimeout(cfg)
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	// Plan fixes.
	plan, err := fixer.Plan(ctx, []string{args[0]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return &exitError{code: fix.ExitFixError, err: err}
	}

	// Check if there's anything to do.
	if plan.Summary.Applied == 0 && plan.Summary.Skipped == 0 {
		fmt.Fprintln(os.Stdout, "No fixable findings found.")
		return &exitError{code: fix.ExitFixNothingToDo, err: fmt.Errorf("no fixable findings")}
	}
	if plan.Summary.Applied == 0 {
		printFixSummary(os.Stdout, &plan.Summary, false, fixCfg.RiskLevel)
		fmt.Fprintln(os.Stdout, "\nNo fixes to apply at the current risk level.")
		return &exitError{code: fix.ExitFixNothingToDo, err: fmt.Errorf("no fixable findings at current risk level")}
	}

	// Detection warnings for Helm/Kustomize-managed resources.
	if helmFiles := fix.DetectHelmManaged(plan); len(helmFiles) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d file(s) contain Helm-managed resources.\n", len(helmFiles))
		fmt.Fprintln(os.Stderr, "Consider using --output helm-values instead of patching manifests directly.")
		for _, f := range helmFiles {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
		fmt.Fprintln(os.Stderr)
	}
	if kustDirs := fix.DetectKustomize([]string{args[0]}); len(kustDirs) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: Kustomize configuration detected.\n")
		fmt.Fprintln(os.Stderr, "Consider using --kustomize <dir> to generate a Kustomize overlay instead.")
		for _, d := range kustDirs {
			fmt.Fprintf(os.Stderr, "  %s\n", d)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Handle output modes that don't require --apply.
	switch flagFixOutput {
	case "kubectl":
		printKubectlPatches(os.Stdout, plan, riskLevel)
		return nil
	case "helm-values":
		opts := fix.DefaultHelmValuesOptions()
		opts.RiskLevel = riskLevel
		output, genErr := fix.GenerateHelmValues(plan, opts)
		if genErr != nil {
			fmt.Fprintf(os.Stderr, "Error generating Helm values: %v\n", genErr)
			return &exitError{code: fix.ExitFixError, err: genErr}
		}
		fmt.Fprint(os.Stdout, string(output))
		return nil
	case "diff":
		printDiffs(os.Stdout, plan)
	}

	// Kustomize overlay output.
	if flagFixKustomize != "" {
		if err := fix.GenerateKustomizeOverlay(plan, flagFixKustomize); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating Kustomize overlay: %v\n", err)
			return &exitError{code: fix.ExitFixError, err: err}
		}
		fmt.Fprintf(os.Stdout, "Kustomize overlay written to: %s\n", flagFixKustomize)
		fmt.Fprintf(os.Stdout, "Apply with: kubectl apply -k %s\n", flagFixKustomize)
		return nil
	}

	// Dry-run mode: show summary and exit.
	if !fixCfg.Apply {
		printFixSummary(os.Stdout, &plan.Summary, false, fixCfg.RiskLevel)
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "This was a dry-run. No files were modified.")
		fmt.Fprintf(os.Stdout, "To apply these fixes: kubevigil fix %s --apply\n", args[0])
		return nil
	}

	// Interactive confirmation for bulk operations.
	if !fixCfg.Yes && plan.Summary.FilesModified > fixCfg.BulkThreshold {
		proceed, promptErr := confirmBulkApply(os.Stdin, os.Stdout, plan)
		if promptErr != nil {
			return &exitError{code: fix.ExitFixError, err: promptErr}
		}
		if !proceed {
			fmt.Fprintln(os.Stdout, "Fix operation cancelled.")
			return nil
		}
	}

	// Apply fixes.
	summary, err := fixer.Apply(ctx, plan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return &exitError{code: fix.ExitFixError, err: err}
	}

	printFixSummary(os.Stdout, summary, true, fixCfg.RiskLevel)

	// Generate fix report.
	var reportContent []byte
	reportOpts := fix.ReportOptions{
		RiskLevel:  fixCfg.RiskLevel,
		Applied:    true,
		BackupDir:  summary.BackupDir,
		SourcePath: args[0],
	}
	reportContent, reportErr := fix.GenerateFixReport(plan, &reportOpts)
	if reportErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not generate fix report: %v\n", reportErr)
	} else {
		reportPath := flagFixReport
		if reportPath == "" && summary.BackupDir != "" {
			reportPath = filepath.Join(summary.BackupDir, "FIX-REPORT.md")
		}
		if reportPath != "" {
			if writeErr := fix.WriteFixReport(plan, &reportOpts, reportPath); writeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not write fix report: %v\n", writeErr)
			} else {
				fmt.Fprintf(os.Stdout, "Fix report: %s\n", reportPath)
			}
		}
	}

	// Check for partial failure.
	if summary.FilesFailed > 0 && summary.FilesModified > 0 {
		return &exitError{code: fix.ExitFixPartialSuccess, err: fmt.Errorf("%d files failed", summary.FilesFailed)}
	}

	// GitOps PR creation.
	if flagFixGitPR {
		prCfg := fix.DefaultGitPRConfig(plan, reportContent)
		prCfg.WorkDir = filepath.Dir(args[0])
		prURL, prErr := fix.CreateGitOpsPR(&prCfg)
		if prErr != nil {
			fmt.Fprintf(os.Stderr, "Error creating PR: %v\n", prErr)
		} else {
			fmt.Fprintf(os.Stdout, "Pull request created: %s\n", prURL)
		}
	}

	// Verify if requested.
	if fixCfg.Verify {
		verifyResult, verifyErr := fixer.Verify(ctx, plan)
		if verifyErr != nil {
			fmt.Fprintf(os.Stderr, "Verify error: %v\n", verifyErr)
		} else {
			printVerifyResult(os.Stdout, verifyResult)
			if !verifyResult.Clean {
				return &exitError{code: fix.ExitFixVerifyFailed, err: fmt.Errorf("findings remain after fix")}
			}
		}
	}

	return nil
}

// buildFixConfig constructs a fix.Config from CLI flags and the config file.
// CLI flags override config file values.
func buildFixConfig(cfg *config.Config, riskLevel fix.RiskLevel) fix.Config {
	fixCfg := fix.DefaultConfig()
	fixCfg.RiskLevel = riskLevel
	fixCfg.Apply = flagFixApply
	fixCfg.Yes = flagFixYes
	fixCfg.Verify = flagFixVerify
	fixCfg.AllowSystemNamespaces = flagFixSystemNS

	// Config file values (only apply if CLI flag was not explicitly set).
	if cfg.Fix.BulkThreshold > 0 {
		fixCfg.BulkThreshold = cfg.Fix.BulkThreshold
	}
	if cfg.Fix.BackupDir != "" && flagFixBackupDir == "" {
		fixCfg.BackupDir = cfg.Fix.BackupDir
	}
	fixCfg.AdditionalSystemNamespaces = cfg.Fix.AdditionalSystemNamespaces

	// CLI flag overrides.
	if flagFixBackupDir != "" {
		fixCfg.BackupDir = flagFixBackupDir
	}

	// Filtering.
	if flagFixChecks != "" {
		fixCfg.Checks = splitComma(flagFixChecks)
	}
	if flagFixSeverity != "" {
		fixCfg.Severities = splitComma(flagFixSeverity)
	}
	if flagFixNamespace != "" {
		fixCfg.Namespaces = splitComma(flagFixNamespace)
	}
	if flagFixExcludeNamespace != "" {
		fixCfg.ExcludeNamespaces = splitComma(flagFixExcludeNamespace)
	}
	if flagFixFingerprint != "" {
		fixCfg.Fingerprints = splitComma(flagFixFingerprint)
	}

	return fixCfg
}

// splitComma splits a comma-separated string into trimmed non-empty parts.
func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// isInteractive returns true if stdin is a terminal (not piped/CI).
func isInteractive() bool {
	// Check CI environment variables.
	ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"}
	for _, v := range ciVars {
		if val := os.Getenv(v); val == "true" || val == "1" {
			return false
		}
	}
	if os.Getenv("JENKINS_URL") != "" {
		return false
	}

	// Check if stdin is a terminal.
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// confirmBulkApply prompts the user for confirmation before applying bulk fixes.
// Returns true if the user confirms, false if they cancel.
func confirmBulkApply(in io.Reader, out io.Writer, plan *fix.Plan) (bool, error) {
	fmt.Fprintf(out, "\nThis will modify %d files.\n\n", plan.Summary.FilesModified)

	nsMap := make(map[string]int)
	for i := range plan.Summary.Results {
		if plan.Summary.Results[i].Applied {
			nsMap[plan.Summary.Results[i].Namespace]++
		}
	}
	namespaces := make([]string, 0, len(nsMap))
	for ns := range nsMap {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	fmt.Fprintf(out, "  Fixes to apply: %d\n", plan.Summary.Applied)
	fmt.Fprintf(out, "  Namespaces affected: %s\n", strings.Join(namespaces, ", "))
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Apply %d fixes? [y/N] ", plan.Summary.Applied)

	var response string
	if _, err := fmt.Fscan(in, &response); err != nil {
		return false, nil
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes", nil
}

// printDiffs writes all file diffs to the writer with optional color.
func printDiffs(w io.Writer, plan *fix.Plan) {
	paths := sortedKeys(plan.Diffs)
	isTTY := !color.NoColor && isTerminalWriter(w)

	for _, path := range paths {
		diff := plan.Diffs[path]
		if isTTY {
			diff = fix.ColorDiff(diff)
		}
		fmt.Fprintln(w, diff)

		// Print inline impact warnings for non-safe fixes.
		if fp, ok := plan.Files[path]; ok {
			for i := range fp.Fixes {
				pf := &fp.Fixes[i]
				if pf.Applied && pf.Strategy.Impact != "" &&
					(pf.Strategy.Safety == checker.FixLikelySafe || pf.Strategy.Safety == checker.FixPotentiallyBreaking) {
					safetyLabel := "likely_safe"
					if pf.Strategy.Safety == checker.FixPotentiallyBreaking {
						safetyLabel = "potentially_breaking"
					}
					fmt.Fprintf(w, "# IMPACT (%s): %s\n", safetyLabel, pf.Strategy.Impact)
				}
			}
		}
	}
}

// printKubectlPatches generates kubectl patch commands organized by namespace.
func printKubectlPatches(w io.Writer, plan *fix.Plan, riskLevel fix.RiskLevel) {
	fmt.Fprintln(w, "# KubeVigil kubectl patch commands")
	fmt.Fprintf(w, "# Risk level: %s\n", riskLevel)
	fmt.Fprintln(w)

	// Group applied results by namespace.
	type patchInfo struct {
		kind      string
		resource  string
		namespace string
		checkID   string
		safety    checker.FixSafety
		desc      string
	}

	nsPatchMap := make(map[string][]patchInfo)
	for i := range plan.Summary.Results {
		r := &plan.Summary.Results[i]
		if !r.Applied {
			continue
		}
		ns := r.Namespace
		if ns == "" {
			ns = "default"
		}
		nsPatchMap[ns] = append(nsPatchMap[ns], patchInfo{
			kind:      r.Kind,
			resource:  r.Resource,
			namespace: ns,
			checkID:   r.CheckID,
			safety:    r.Safety,
			desc:      r.Description,
		})
	}

	namespaces := make([]string, 0, len(nsPatchMap))
	for ns := range nsPatchMap {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for _, ns := range namespaces {
		patches := nsPatchMap[ns]
		fmt.Fprintf(w, "# --- Namespace: %s (%d patches) ---\n\n", ns, len(patches))
		for _, p := range patches {
			fmt.Fprintf(w, "# Fix: %s (check: %s, risk: %s)\n", p.desc, p.checkID, p.safety)
			// Generate a strategic merge patch for the finding.
			fmt.Fprintf(w, "kubectl patch %s %s -n %s --type=strategic -p '{\"spec\":{\"template\":{\"spec\":{}}}}'\n\n",
				strings.ToLower(p.kind), p.resource, p.namespace)
		}
	}
}

// printFixSummary writes the fix summary to the writer.
func printFixSummary(w io.Writer, summary *fix.Summary, applied bool, riskLevel fix.RiskLevel) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "KubeVigil Fix Summary")
	fmt.Fprintln(w, strings.Repeat("\u2500", 21))

	fmt.Fprintf(w, "Files scanned:    %4d\n", summary.FilesScanned)
	fmt.Fprintf(w, "Files to modify:  %4d\n", summary.FilesModified)
	fmt.Fprintf(w, "Findings total:   %4d\n", summary.TotalFindings)
	fmt.Fprintln(w)

	// By risk classification.
	fmt.Fprintln(w, "By risk classification:")
	safeCt := summary.ByRisk[checker.FixSafe]
	likelyCt := summary.ByRisk[checker.FixLikelySafe]
	breakCt := summary.ByRisk[checker.FixPotentiallyBreaking]

	action := "will be applied"
	if applied {
		action = "applied"
	}
	fmt.Fprintf(w, "  Safe:                %3d  [%s]\n", safeCt, action)

	if riskLevel.AllowsSafety(checker.FixLikelySafe) {
		fmt.Fprintf(w, "  Likely safe:         %3d  [%s]\n", likelyCt, action)
	} else {
		fmt.Fprintf(w, "  Likely safe:         %3d  [skipped — use --risk-level moderate]\n", likelyCt)
	}

	if riskLevel.AllowsSafety(checker.FixPotentiallyBreaking) {
		fmt.Fprintf(w, "  Potentially breaking:%3d  [%s]\n", breakCt, action)
	} else {
		fmt.Fprintf(w, "  Potentially breaking:%3d  [skipped — use --risk-level aggressive]\n", breakCt)
	}
	fmt.Fprintln(w)

	// Skipped reasons.
	if len(summary.SkipReasons) > 0 {
		fmt.Fprintln(w, "Skipped:")
		reasons := sortedKeys(summary.SkipReasons)
		for _, reason := range reasons {
			ct := summary.SkipReasons[reason]
			label := skipReasonLabel(reason)
			fmt.Fprintf(w, "  %-22s %3d\n", label+":", ct)
		}
		fmt.Fprintln(w)
	}

	// Backup and report paths.
	if summary.BackupDir != "" {
		fmt.Fprintf(w, "Backup: %s\n", summary.BackupDir)
		fmt.Fprintf(w, "\nTo restore: cp -r %s/* <original-path>/\n", summary.BackupDir)
	}

	// Errors.
	if len(summary.Errors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Errors:")
		for _, e := range summary.Errors {
			fmt.Fprintf(w, "  %s — %s\n", e.FilePath, e.Err)
		}
	}
}

// skipReasonLabel maps internal skip reason keys to human-readable labels.
func skipReasonLabel(reason string) string {
	switch reason {
	case "system_namespace":
		return "System namespaces"
	case "risk_level":
		return "Risk > allowed"
	case "check_not_selected":
		return "Check filtered"
	case "severity_not_selected":
		return "Severity filtered"
	case "namespace_not_selected":
		return "NS filtered"
	case "namespace_excluded":
		return "NS excluded"
	default:
		return reason
	}
}

// printVerifyResult writes a structured verification summary.
func printVerifyResult(w io.Writer, result *fix.VerifyResult) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Verification Results")
	fmt.Fprintln(w, strings.Repeat("\u2500", 20))
	fmt.Fprintf(w, "Fixable before:  %4d\n", result.TotalBefore)
	fmt.Fprintf(w, "Fixable after:   %4d\n", result.TotalAfter)
	fmt.Fprintf(w, "Resolved:        %4d\n", result.Resolved)
	if result.New > 0 {
		fmt.Fprintf(w, "New:             %4d\n", result.New)
	}
	fmt.Fprintln(w)

	if result.Clean {
		fmt.Fprintln(w, "All fixable findings resolved.")
	} else {
		fmt.Fprintf(w, "%d fixable findings remain:\n", result.Remaining)
		paths := sortedKeys(result.RemainingFindings)
		for _, path := range paths {
			checks := result.RemainingFindings[path]
			fmt.Fprintf(w, "  %s: %s\n", path, strings.Join(checks, ", "))
		}
	}
}

// isTerminalWriter returns true if the writer is os.Stdout or os.Stderr connected to a terminal.
func isTerminalWriter(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		info, err := f.Stat()
		if err != nil {
			return false
		}
		return info.Mode()&os.ModeCharDevice != 0
	}
	return false
}

// sortedKeys returns sorted keys from a map[string]T.
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
