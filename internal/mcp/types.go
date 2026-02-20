// Package mcp provides a Model Context Protocol (MCP) server for KubeVigil,
// allowing AI assistants to scan Kubernetes clusters, query findings, and
// get remediation guidance through a conversational interface.
//
// The MCP server is a thin transport layer over the existing scan engine.
// It reuses [engine.Scanner], [checker.Registry], [config.Config], and all
// existing checker packages. Zero duplication of scan logic.
package mcp

import "github.com/stribog-cloud/kubevigil/internal/checker"

// ScanClusterInput holds the parameters for the scan_cluster tool.
type ScanClusterInput struct {
	// Kubeconfig is the path to the kubeconfig file.
	Kubeconfig string `json:"kubeconfig,omitempty" jsonschema:"path to kubeconfig file"`
	// Context is the kubeconfig context to use.
	Context string `json:"context,omitempty" jsonschema:"kubeconfig context to use"`
	// Namespace restricts the scan to a single namespace.
	Namespace string `json:"namespace,omitempty" jsonschema:"scan only this namespace"`
	// Severity sets the minimum severity to report (info, low, medium, high, critical).
	Severity string `json:"severity,omitempty" jsonschema:"minimum severity to report: info, low, medium, high, critical"`
	// Framework filters findings by compliance framework (cis, mitre, nsa).
	Framework string `json:"framework,omitempty" jsonschema:"filter by compliance framework: cis, mitre, nsa"`
	// ExcludeInfra excludes infrastructure namespaces from results.
	ExcludeInfra bool `json:"exclude_infra,omitempty" jsonschema:"exclude infrastructure namespaces"`
}

// ScanManifestsInput holds the parameters for the scan_manifests tool.
type ScanManifestsInput struct {
	// Path is the file or directory path to scan.
	Path string `json:"path" jsonschema:"path to YAML file or directory"`
	// Severity sets the minimum severity to report.
	Severity string `json:"severity,omitempty" jsonschema:"minimum severity to report: info, low, medium, high, critical"`
	// Framework filters findings by compliance framework.
	Framework string `json:"framework,omitempty" jsonschema:"filter by compliance framework: cis, mitre, nsa"`
}

// GetFindingsInput holds the parameters for the get_findings tool.
type GetFindingsInput struct {
	// Severity filters by exact severity level (case-insensitive).
	Severity string `json:"severity,omitempty" jsonschema:"filter by severity: info, low, medium, high, critical"`
	// Category filters by check category (case-insensitive).
	Category string `json:"category,omitempty" jsonschema:"filter by category: Workload, RBAC, Network, Image, Secrets, Storage, etc."`
	// Namespace filters by Kubernetes namespace.
	Namespace string `json:"namespace,omitempty" jsonschema:"filter by namespace"`
	// Checker filters by check ID (e.g., privileged, run-as-root).
	Checker string `json:"checker,omitempty" jsonschema:"filter by check ID such as privileged or run-as-root"`
	// Framework filters by compliance framework (cis, mitre, nsa).
	Framework string `json:"framework,omitempty" jsonschema:"filter by compliance framework: cis, mitre, nsa"`
	// Limit is the maximum number of findings to return (default 25, max 100).
	Limit int `json:"limit,omitempty" jsonschema:"max findings to return, default 25, max 100"`
	// Offset is the number of findings to skip for pagination.
	Offset int `json:"offset,omitempty" jsonschema:"offset for pagination"`
}

// GetSummaryInput holds the parameters for the get_summary tool.
// No input is needed — it summarizes the most recent scan.
type GetSummaryInput struct{}

// ListChecksInput holds the parameters for the list_checks tool.
type ListChecksInput struct {
	// Category filters checks by category.
	Category string `json:"category,omitempty" jsonschema:"filter by category"`
	// Mode filters checks by supported scan mode (live, manifest).
	Mode string `json:"mode,omitempty" jsonschema:"filter by scan mode: live or manifest"`
}

// GetRemediationInput holds the parameters for the get_remediation tool.
type GetRemediationInput struct {
	// Checker is the check ID to get remediation for (required).
	Checker string `json:"checker" jsonschema:"check ID such as privileged or run-as-root"`
	// Resource is the specific resource name for targeted remediation.
	Resource string `json:"resource,omitempty" jsonschema:"specific resource name to get targeted remediation"`
	// Namespace is the namespace of the resource.
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace of the resource"`
}

// ScanSummaryOutput is the summary returned by scan tools and get_summary.
type ScanSummaryOutput struct {
	// Cluster is the cluster name or scan target identifier.
	Cluster string `json:"cluster,omitempty"`
	// ServerVersion is the Kubernetes server version.
	ServerVersion string `json:"server_version,omitempty"`
	// NodeCount is the number of nodes in the cluster.
	NodeCount int `json:"node_count,omitempty"`
	// ChecksRun is the number of checks executed.
	ChecksRun int `json:"checks_run"`
	// ChecksErrored is the number of checks that encountered errors.
	ChecksErrored int `json:"checks_errored"`
	// TotalFindings is the total number of findings.
	TotalFindings int `json:"total_findings"`
	// SeverityCounts maps severity names to finding counts.
	SeverityCounts map[string]int `json:"severity_counts"`
	// CategoryCounts maps category names to finding counts.
	CategoryCounts map[string]int `json:"category_counts"`
	// TopIssues lists the most common checks by finding count.
	TopIssues []TopIssue `json:"top_issues"`
	// ComplianceStats maps framework names to mapped control counts.
	ComplianceStats map[string]int `json:"compliance_stats,omitempty"`
}

// TopIssue represents a frequently occurring check in the summary.
type TopIssue struct {
	// Checker is the check ID.
	Checker string `json:"checker"`
	// Severity is the severity level of the check.
	Severity string `json:"severity"`
	// Count is the number of findings for this check.
	Count int `json:"count"`
}

// FindingDetail is an MCP-compatible representation of a security finding.
// It mirrors [checker.Finding] but uses string for Severity so the
// auto-generated JSON schema matches the serialized output.
type FindingDetail struct {
	// Checker is the kebab-case ID of the check that produced this finding.
	Checker string `json:"checker"`
	// Severity is the impact level (Info, Low, Medium, High, Critical).
	Severity string `json:"severity"`
	// Resource is the name of the Kubernetes resource.
	Resource string `json:"resource"`
	// Namespace is the namespace of the resource.
	Namespace string `json:"namespace,omitempty"`
	// Kind is the Kubernetes resource kind.
	Kind string `json:"kind"`
	// Container is the container name, if applicable.
	Container string `json:"container,omitempty"`
	// Message describes the issue.
	Message string `json:"message"`
	// Remediation describes how to fix the issue.
	Remediation string `json:"remediation"`
	// FieldPath is the JSON path to the problematic field.
	FieldPath string `json:"field_path,omitempty"`
	// Frameworks lists compliance framework references.
	Frameworks []checker.FrameworkRef `json:"frameworks,omitempty"`
	// CurrentValue is the current insecure value.
	CurrentValue any `json:"current_value,omitempty"`
	// DesiredValue is the recommended secure value.
	DesiredValue any `json:"desired_value,omitempty"`
}

// toFindingDetail converts a checker.Finding to an FindingDetail.
func toFindingDetail(f *checker.Finding) FindingDetail {
	return FindingDetail{
		Checker:      f.Checker,
		Severity:     f.Severity.String(),
		Resource:     f.Resource,
		Namespace:    f.Namespace,
		Kind:         f.Kind,
		Container:    f.Container,
		Message:      f.Message,
		Remediation:  f.Remediation,
		FieldPath:    f.FieldPath,
		Frameworks:   f.Frameworks,
		CurrentValue: f.CurrentValue,
		DesiredValue: f.DesiredValue,
	}
}

// toFindingDetails converts a slice of checker.Finding to FindingDetail.
func toFindingDetails(findings []checker.Finding) []FindingDetail {
	result := make([]FindingDetail, len(findings))
	for i := range findings {
		result[i] = toFindingDetail(&findings[i])
	}
	return result
}

// FindingsOutput is the paginated result from get_findings.
type FindingsOutput struct {
	// Findings is the list of matching findings for the current page.
	Findings []FindingDetail `json:"findings"`
	// Total is the total number of matching findings across all pages.
	Total int `json:"total"`
	// Offset is the offset used for this page.
	Offset int `json:"offset"`
	// Limit is the limit used for this page.
	Limit int `json:"limit"`
	// HasMore is true if there are more findings beyond this page.
	HasMore bool `json:"has_more"`
}

// CheckInfo describes a single security check for list_checks output.
type CheckInfo struct {
	// ID is the kebab-case check identifier.
	ID string `json:"id"`
	// Description is a human-readable description.
	Description string `json:"description"`
	// Category is the primary category.
	Category string `json:"category"`
	// Modes lists the supported scan modes.
	Modes []string `json:"modes"`
	// Severity is the default severity level.
	Severity string `json:"severity"`
	// AutoFixable indicates whether the check has an auto-fix strategy.
	AutoFixable bool `json:"auto_fixable"`
}

// CheckListOutput is the result from list_checks.
type CheckListOutput struct {
	// Checks is the list of matching checks.
	Checks []CheckInfo `json:"checks"`
	// Total is the total number of matching checks.
	Total int `json:"total"`
}

// RemediationOutput is the result from get_remediation.
type RemediationOutput struct {
	// Checker is the check ID.
	Checker string `json:"checker"`
	// Description is the check description.
	Description string `json:"description"`
	// Remediation is the remediation guidance text.
	Remediation string `json:"remediation"`
	// FixHint provides structured auto-fix metadata, if available.
	FixHint *checker.FixHint `json:"fix_hint,omitempty"`
	// Frameworks lists the compliance framework references for this check.
	Frameworks []checker.FrameworkRef `json:"frameworks,omitempty"`
	// CurrentValue is the current insecure value, if a specific finding was matched.
	CurrentValue any `json:"current_value,omitempty"`
	// DesiredValue is the recommended secure value, if a specific finding was matched.
	DesiredValue any `json:"desired_value,omitempty"`
	// Resource is the resource name, if a specific finding was matched.
	Resource string `json:"resource,omitempty"`
	// Namespace is the resource namespace, if a specific finding was matched.
	Namespace string `json:"namespace,omitempty"`
}
