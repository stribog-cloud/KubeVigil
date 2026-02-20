package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
)

const (
	// defaultFindingsLimit is the default page size for get_findings.
	defaultFindingsLimit = 25
	// maxFindingsLimit is the maximum page size for get_findings.
	maxFindingsLimit = 100
)

// handleGetFindings queries and filters findings from the most recent scan.
func (kv *KubeVigilMCP) handleGetFindings(
	_ context.Context,
	_ *mcp.CallToolRequest,
	input GetFindingsInput, //nolint:gocritic // value required by MCP SDK ToolHandlerFor signature
) (*mcp.CallToolResult, FindingsOutput, error) {
	kv.mu.RLock()
	result := kv.lastResult
	kv.mu.RUnlock()

	if result == nil {
		return nil, FindingsOutput{}, fmt.Errorf("get_findings: no scan results available. Run scan_cluster or scan_manifests first")
	}

	// Filter findings in a single pass. Each filter is AND-combined.
	filtered := filterFindings(result.Findings, &input)

	// Paginate after filtering.
	limit := input.Limit
	if limit <= 0 {
		limit = defaultFindingsLimit
	}
	if limit > maxFindingsLimit {
		limit = maxFindingsLimit
	}

	offset := input.Offset
	if offset < 0 {
		offset = 0
	}

	total := len(filtered)
	// Slice for the requested page.
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	return nil, FindingsOutput{
		Findings: toFindingDetails(page),
		Total:    total,
		Offset:   offset,
		Limit:    limit,
		HasMore:  end < total,
	}, nil
}

// filterFindings applies all filter criteria to findings. Filters are
// AND-combined: a finding must match all specified filters.
func filterFindings(findings []checker.Finding, input *GetFindingsInput) []checker.Finding {
	hasSeverity := input.Severity != ""
	hasCategory := input.Category != ""
	hasNamespace := input.Namespace != ""
	hasChecker := input.Checker != ""
	hasFramework := input.Framework != ""

	// Fast path: no filters applied.
	if !hasSeverity && !hasCategory && !hasNamespace && !hasChecker && !hasFramework {
		// Return a copy to avoid callers mutating the original slice.
		result := make([]checker.Finding, len(findings))
		copy(result, findings)
		return result
	}

	// Pre-parse severity once, not per-finding.
	var severityTarget checker.Severity
	if hasSeverity {
		parsed, err := checker.ParseSeverity(input.Severity)
		if err == nil {
			severityTarget = parsed
		} else {
			hasSeverity = false // invalid severity string — skip filter
		}
	}

	normalizedCategory := strings.ToLower(input.Category)
	normalizedFramework := ""
	if hasFramework {
		normalizedFramework = frameworks.NormalizeFramework(input.Framework)
	}

	result := make([]checker.Finding, 0, len(findings)/4) // heuristic pre-alloc
	for i := range findings {
		f := &findings[i]

		if hasSeverity && f.Severity != severityTarget {
			continue
		}
		if hasCategory && !categoryMatches(f.Checker, normalizedCategory) {
			continue
		}
		if hasNamespace && f.Namespace != input.Namespace {
			continue
		}
		if hasChecker && f.Checker != input.Checker {
			continue
		}
		if hasFramework && !findingHasFramework(f, normalizedFramework) {
			continue
		}

		result = append(result, *f)
	}
	return result
}

// categoryMatches checks if a checker ID belongs to the given category.
// It uses the default registry to look up the checker's categories.
func categoryMatches(checkerID, normalizedCategory string) bool {
	c, ok := checker.Get(checkerID)
	if !ok {
		return false
	}
	for _, cat := range c.Categories() {
		if strings.ToLower(cat.String()) == normalizedCategory {
			return true
		}
	}
	return false
}

// findingHasFramework checks if a finding maps to the given framework.
func findingHasFramework(f *checker.Finding, normalizedFramework string) bool {
	for _, ref := range f.Frameworks {
		if ref.Framework == normalizedFramework {
			return true
		}
	}
	return false
}
