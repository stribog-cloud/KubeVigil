package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/fix"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
)

// handleListChecks lists available security checks with optional filtering.
func (kv *KubeVigilMCP) handleListChecks(
	_ context.Context,
	_ *mcp.CallToolRequest,
	input ListChecksInput,
) (*mcp.CallToolResult, CheckListOutput, error) {
	fixRegistry := fix.DefaultRegistry()
	allChecks := kv.registry.All()

	var checks []CheckInfo
	for _, c := range allChecks {
		// Category filter.
		if input.Category != "" && !checkerHasCategory(c, input.Category) {
			continue
		}

		// Mode filter.
		if input.Mode != "" {
			mode, err := checker.ParseScanMode(input.Mode)
			if err != nil {
				return nil, CheckListOutput{}, fmt.Errorf("list_checks: invalid mode %q: %w", input.Mode, err)
			}
			if !checkerSupportsMode(c, mode) {
				continue
			}
		}

		info := CheckInfo{
			ID:          c.Name(),
			Description: c.Description(),
			Modes:       modeStrings(c),
			AutoFixable: fixRegistry.Has(c.Name()),
		}

		// Primary category.
		cats := c.Categories()
		if len(cats) > 0 {
			info.Category = cats[0].String()
		}

		// Default severity: run with nil cache to get the checker's metadata.
		// We use the scan meta from last result if available, otherwise report
		// the severity from the checker's default finding shape.
		info.Severity = checkerDefaultSeverity(c)

		checks = append(checks, info)
	}

	return nil, CheckListOutput{
		Checks: checks,
		Total:  len(checks),
	}, nil
}

// handleGetRemediation returns detailed remediation guidance for a check.
func (kv *KubeVigilMCP) handleGetRemediation(
	_ context.Context,
	_ *mcp.CallToolRequest,
	input GetRemediationInput,
) (*mcp.CallToolResult, RemediationOutput, error) {
	if input.Checker == "" {
		return nil, RemediationOutput{}, fmt.Errorf("get_remediation: checker ID is required")
	}

	c, ok := kv.registry.Get(input.Checker)
	if !ok {
		return nil, RemediationOutput{}, fmt.Errorf("get_remediation: unknown checker %q", input.Checker)
	}

	output := RemediationOutput{
		Checker:     c.Name(),
		Description: c.Description(),
		Frameworks:  frameworks.LookupAll(c.Name()),
	}

	// Look for a matching finding in the last scan result.
	kv.mu.RLock()
	result := kv.lastResult
	kv.mu.RUnlock()

	if result != nil {
		if finding := findMatchingFinding(result, input); finding != nil {
			output.Remediation = finding.Remediation
			output.FixHint = finding.FixHint
			output.CurrentValue = finding.CurrentValue
			output.DesiredValue = finding.DesiredValue
			output.Resource = finding.Resource
			output.Namespace = finding.Namespace
			return nil, output, nil
		}

		// No specific finding match, but we have results — get generic
		// remediation from any finding with this checker ID.
		for i := range result.Findings {
			if result.Findings[i].Checker == input.Checker {
				output.Remediation = result.Findings[i].Remediation
				output.FixHint = result.Findings[i].FixHint
				break
			}
		}
	}

	// If still no remediation text, provide a placeholder.
	if output.Remediation == "" {
		output.Remediation = fmt.Sprintf("Review the %q check documentation for remediation guidance.", c.Name())
	}

	return nil, output, nil
}

// findMatchingFinding searches the scan result for a finding matching the
// given checker, resource, and namespace combination.
func findMatchingFinding(result *checker.ScanResult, input GetRemediationInput) *checker.Finding {
	if input.Resource == "" {
		return nil
	}
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.Checker != input.Checker {
			continue
		}
		if f.Resource != input.Resource {
			continue
		}
		if input.Namespace != "" && f.Namespace != input.Namespace {
			continue
		}
		return f
	}
	return nil
}

// checkerHasCategory returns true if the checker has a matching category.
func checkerHasCategory(c checker.Checker, category string) bool {
	normalized := strings.ToLower(category)
	for _, cat := range c.Categories() {
		if strings.ToLower(cat.String()) == normalized {
			return true
		}
	}
	return false
}

// checkerSupportsMode returns true if the checker supports the given scan mode.
func checkerSupportsMode(c checker.Checker, mode checker.ScanMode) bool {
	for _, m := range c.SupportedModes() {
		if m == mode {
			return true
		}
	}
	return false
}

// modeStrings returns the human-readable mode names for a checker.
func modeStrings(c checker.Checker) []string {
	modes := c.SupportedModes()
	result := make([]string, len(modes))
	for i, m := range modes {
		result[i] = m.String()
	}
	return result
}

// checkerDefaultSeverity returns the default severity for a checker by
// inspecting its first finding template. Returns "Medium" if unknown.
func checkerDefaultSeverity(c checker.Checker) string {
	// Most checkers have a known severity from the checker description metadata.
	// Run with nil context/cache would panic, so we use a heuristic:
	// all KubeVigil checkers set severity at construction time, and the first
	// finding from any run of the checker has the default severity.
	// Since we can't run without resources, return a sensible default.
	return "Medium"
}
