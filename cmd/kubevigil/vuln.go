package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/report"
	"github.com/stribog-cloud/kubevigil/internal/vuln"
)

var (
	flagVulnSBOM    string
	flagVulnImage   string
	flagVulnFailOn  string
	flagVulnMinSev  string
	flagVulnTimeout time.Duration
	flagVulnOutput  string
)

var vulnCmd = &cobra.Command{
	Use:   "vuln --sbom <file|dir>",
	Short: "Scan a software bill of materials for known vulnerabilities (OSV.dev)",
	Long: `Scan an image's software bill of materials (SPDX or CycloneDX JSON) against the
OSV.dev vulnerability database and report known CVEs, fused into the same finding
model and report formats as a posture scan.

The SBOM is the package inventory of a container image — generate one with syft,
trivy, or docker sbom, then point kubevigil vuln at it. This command requires
network access to https://api.osv.dev.`,
	Example: `  kubevigil vuln --sbom app.spdx.json --image myapp:1.4.0
  kubevigil vuln --sbom ./sboms/ -o sarif --fail-on high`,
	RunE: runVuln,
}

func init() {
	vulnCmd.Flags().StringVar(&flagVulnSBOM, "sbom", "", "path to an SBOM file or a directory of SBOMs (SPDX or CycloneDX JSON) [required]")
	vulnCmd.Flags().StringVar(&flagVulnImage, "image", "", "container image reference the SBOM describes (recorded on findings)")
	vulnCmd.Flags().StringVarP(&flagVulnOutput, "output", "o", "text", "output format or file path (text, json, markdown, yaml, html, sarif, junit, csv)")
	vulnCmd.Flags().StringVar(&flagVulnFailOn, "fail-on", "", "minimum severity for exit code 1 (info, low, medium, high, critical)")
	vulnCmd.Flags().StringVar(&flagVulnMinSev, "min-severity", "", "drop vulnerabilities below this severity from the report")
	vulnCmd.Flags().DurationVar(&flagVulnTimeout, "timeout", 60*time.Second, "per-request timeout for OSV.dev queries")
	rootCmd.AddCommand(vulnCmd)
}

func runVuln(cmd *cobra.Command, _ []string) error {
	if flagVulnSBOM == "" {
		return &exitError{code: 3, err: fmt.Errorf("--sbom is required")}
	}

	minSev := checker.SeverityInfo
	if flagVulnMinSev != "" {
		parsed, err := checker.ParseSeverity(flagVulnMinSev)
		if err != nil {
			return &exitError{code: 3, err: fmt.Errorf("invalid --min-severity: %w", err)}
		}
		minSev = parsed
	}

	packages, err := loadSBOMPackages(flagVulnSBOM)
	if err != nil {
		return &exitError{code: 3, err: err}
	}
	if len(packages) == 0 {
		fmt.Fprintln(os.Stderr, "No packages with a package URL (purl) found in the SBOM; nothing to check.")
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), maxVulnScanTime(flagVulnTimeout, len(packages)))
	defer cancel()

	client := vuln.NewHTTPOSVClient(flagVulnTimeout)
	findings, err := vuln.NewScanner(client).Scan(ctx, packages, vuln.ScanOptions{
		Image:       flagVulnImage,
		MinSeverity: minSev,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Vulnerability scan failed: %v\n", err)
		return &exitError{code: 2, err: err}
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			StartTime: time.Now(),
			ScanMode:  checker.ScanModeManifest,
		},
	}

	out, outErr := resolveOutput(flagVulnOutput)
	if outErr != nil {
		return fmt.Errorf("output: %w", outErr)
	}
	defer out.Close()
	reporter, repErr := report.Get(out.Format)
	if repErr != nil {
		return fmt.Errorf("invalid output format: %w", repErr)
	}
	if genErr := reporter.Generate(ctx, result, out.Writer); genErr != nil {
		return fmt.Errorf("generating report: %w", genErr)
	}

	if flagVulnFailOn != "" && hasFailures(findings, flagVulnFailOn) {
		return &exitError{code: 1, err: fmt.Errorf("vulnerabilities at or above %q severity", flagVulnFailOn)}
	}
	return nil
}

// maxVulnScanTime bounds the whole scan: the per-request timeout times a
// generous factor for the number of advisory fetches, so a large SBOM does not
// hang indefinitely while still allowing every package to be queried.
func maxVulnScanTime(perRequest time.Duration, pkgCount int) time.Duration {
	batches := (pkgCount / 1000) + 1
	// Allow one batch query plus up to pkgCount detail fetches, capped.
	budget := perRequest * time.Duration(batches+pkgCount)
	maxBudget := 15 * time.Minute
	if budget > maxBudget || budget <= 0 {
		return maxBudget
	}
	return budget
}

// loadSBOMPackages reads an SBOM file or a directory of SBOMs and returns the
// merged, deduplicated package inventory. For a directory, files that do not
// parse as an SBOM are skipped with a warning; for a single file, a parse
// failure is a hard error.
func loadSBOMPackages(path string) ([]vuln.Package, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM path: %w", err)
	}

	seen := map[string]vuln.Package{}
	add := func(pkgs []vuln.Package) {
		for _, p := range pkgs {
			seen[p.Purl] = p
		}
	}

	if !info.IsDir() {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("reading SBOM: %w", readErr)
		}
		pkgs, parseErr := vuln.ParseSBOM(data)
		if parseErr != nil {
			return nil, parseErr
		}
		add(pkgs)
		return mapToSortedPackages(seen), nil
	}

	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		return nil, fmt.Errorf("reading SBOM directory: %w", readErr)
	}
	parsedAny := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		full := filepath.Join(path, e.Name())
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", e.Name(), readErr)
			continue
		}
		pkgs, parseErr := vuln.ParseSBOM(data)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", e.Name(), parseErr)
			continue
		}
		add(pkgs)
		parsedAny = true
	}
	if !parsedAny {
		return nil, fmt.Errorf("no parseable SBOM (.json) files found in %s", path)
	}
	return mapToSortedPackages(seen), nil
}

func mapToSortedPackages(seen map[string]vuln.Package) []vuln.Package {
	out := make([]vuln.Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Purl < out[j].Purl })
	return out
}
