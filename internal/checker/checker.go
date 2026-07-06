// Package checker defines the security check framework used by all KubeVigil checkers.
//
// It declares the [Checker] interface, the [Finding] result type, [Severity] levels,
// [ScanMode] constants, and the [ResourceCache] that supplies Kubernetes objects to checks.
// Individual checker implementations live in category sub-packages (e.g., workload, rbac, network).
package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Severity classifies the impact level of a security finding.
type Severity int

const (
	// SeverityInfo indicates an informational observation with no direct security impact.
	SeverityInfo Severity = iota
	// SeverityLow indicates a best practice deviation with minimal direct risk.
	SeverityLow
	// SeverityMedium indicates a defense-in-depth gap.
	SeverityMedium
	// SeverityHigh indicates a significant security weakness.
	SeverityHigh
	// SeverityCritical indicates a direct path to cluster compromise.
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "Info",
	SeverityLow:      "Low",
	SeverityMedium:   "Medium",
	SeverityHigh:     "High",
	SeverityCritical: "Critical",
}

var severityFromName = map[string]Severity{
	"info":     SeverityInfo,
	"low":      SeverityLow,
	"medium":   SeverityMedium,
	"high":     SeverityHigh,
	"critical": SeverityCritical,
}

// String returns the human-readable name of the severity.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// ParseSeverity converts a string to a Severity value.
// Returns an error if the string is not a valid severity name.
func ParseSeverity(s string) (Severity, error) {
	if sev, ok := severityFromName[strings.ToLower(s)]; ok {
		return sev, nil
	}
	return SeverityInfo, fmt.Errorf("unknown severity: %q", s)
}

// MarshalJSON serializes Severity as a JSON string (e.g., "Critical").
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// MarshalYAML serializes Severity as a YAML string (e.g., "Critical").
func (s Severity) MarshalYAML() (any, error) {
	return s.String(), nil
}

// UnmarshalYAML deserializes Severity from a YAML string.
func (s *Severity) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// UnmarshalJSON deserializes Severity from a JSON string.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ScanMode indicates how the scan is being performed.
type ScanMode int

const (
	// ScanModeLive scans a running Kubernetes cluster via the API.
	ScanModeLive ScanMode = iota
	// ScanModeManifest scans YAML/JSON manifests from disk.
	ScanModeManifest
)

// String returns the human-readable name of the scan mode.
func (m ScanMode) String() string {
	switch m {
	case ScanModeLive:
		return "Live"
	case ScanModeManifest:
		return "Manifest"
	default:
		return fmt.Sprintf("ScanMode(%d)", int(m))
	}
}

// ParseScanMode converts a string to a ScanMode value.
func ParseScanMode(s string) (ScanMode, error) {
	switch strings.ToLower(s) {
	case "live":
		return ScanModeLive, nil
	case "manifest":
		return ScanModeManifest, nil
	default:
		return ScanModeLive, fmt.Errorf("unknown scan mode: %q", s)
	}
}

// MarshalJSON serializes ScanMode as a JSON string (e.g., "Live").
func (m ScanMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

// UnmarshalJSON deserializes ScanMode from a JSON string.
func (m *ScanMode) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseScanMode(str)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

// FixSafety classifies the risk level of a fix operation.
type FixSafety string

const (
	// FixSafe indicates a fix with zero risk of breaking functionality.
	FixSafe FixSafety = "safe"
	// FixLikelySafe indicates a fix with very low risk that could theoretically break edge cases.
	FixLikelySafe FixSafety = "likely_safe"
	// FixPotentiallyBreaking indicates a fix that could impact functionality.
	FixPotentiallyBreaking FixSafety = "potentially_breaking"
	// FixManualOnly indicates a fix that cannot be automated and requires manual intervention.
	FixManualOnly FixSafety = "manual_only"
)

// FixOp describes the type of YAML modification a fix performs.
type FixOp string

const (
	// FixOpSet sets a field to a specific value.
	FixOpSet FixOp = "set"
	// FixOpAdd adds a new field that doesn't exist yet.
	FixOpAdd FixOp = "add"
	// FixOpRemove removes a field entirely.
	FixOpRemove FixOp = "remove"
	// FixOpMerge merges into an existing map or list.
	FixOpMerge FixOp = "merge"
)

// FixHint provides structured metadata for auto-remediation.
type FixHint struct {
	// Safety classifies the risk level of applying this fix.
	Safety FixSafety `json:"safety" yaml:"safety"`
	// Description explains what the fix does.
	Description string `json:"description" yaml:"description"`
	// Impact explains what could break if this fix is applied.
	Impact string `json:"impact,omitempty" yaml:"impact"`
	// Operation describes the type of YAML modification.
	Operation FixOp `json:"operation" yaml:"operation"`
}

// FrameworkRef links a finding to a specific compliance framework control.
type FrameworkRef struct {
	// Framework is the identifier (e.g., "cis", "mitre", "nsa").
	Framework string `json:"framework" yaml:"framework"`
	// Version is the framework version (e.g., "1.8", "v14", "1.2").
	Version string `json:"version" yaml:"version"`
	// ControlID is the control identifier (e.g., "5.2.1", "T1611").
	ControlID string `json:"control_id" yaml:"control_id"`
	// Title is the human-readable control title.
	Title string `json:"title" yaml:"title"`
}

// Finding represents a single security issue detected by a checker.
type Finding struct {
	// Checker is the kebab-case ID of the check that produced this finding.
	Checker string `json:"checker" yaml:"checker"`
	// Severity is the impact level of this finding.
	Severity Severity `json:"severity" yaml:"severity"`
	// Resource is the name of the Kubernetes resource.
	Resource string `json:"resource" yaml:"resource"`
	// Namespace is the namespace of the resource (empty for cluster-scoped).
	Namespace string `json:"namespace,omitempty" yaml:"namespace"`
	// Kind is the Kubernetes resource kind (Deployment, Pod, etc.).
	Kind string `json:"kind" yaml:"kind"`
	// Container is the container name, if applicable.
	Container string `json:"container,omitempty" yaml:"container"`
	// Message is a human-readable description of the issue.
	Message string `json:"message" yaml:"message"`
	// Remediation describes how to fix the issue.
	Remediation string `json:"remediation" yaml:"remediation"`
	// FieldPath is the JSON path to the problematic field.
	FieldPath string `json:"field_path,omitempty" yaml:"field_path"`
	// Frameworks lists compliance framework references for this finding.
	Frameworks []FrameworkRef `json:"frameworks,omitempty" yaml:"frameworks"`
	// CurrentValue is the current insecure value of the field (e.g., true for privileged).
	CurrentValue any `json:"current_value,omitempty" yaml:"current_value,omitempty"`
	// DesiredValue is the recommended secure value (e.g., false for privileged).
	DesiredValue any `json:"desired_value,omitempty" yaml:"desired_value,omitempty"`
	// FixHint provides structured metadata for auto-remediation.
	FixHint *FixHint `json:"fix_hint,omitempty" yaml:"fix_hint,omitempty"`
	// Status is the baseline-comparison result for this finding: "new" (not in
	// the baseline), "existing" (present in the baseline), or "" when no
	// baseline was applied. Set by the baseline package during a scan; omitted
	// from output when empty so the field is backward-compatible.
	Status string `json:"status,omitempty" yaml:"status,omitempty"`
	// CVE carries vulnerability metadata when this finding represents a known
	// CVE in a container image's software inventory (checker
	// "image-vulnerability"). Nil for ordinary posture findings, so the field is
	// backward-compatible and omitted from output for non-vulnerability findings.
	CVE *CVEInfo `json:"cve,omitempty" yaml:"cve,omitempty"`
}

// CVEInfo holds structured metadata for a vulnerability finding sourced from a
// vulnerability database (OSV.dev). It is attached to a Finding via the CVE
// field when the finding represents a known vulnerability in an image's
// software bill of materials rather than a Kubernetes misconfiguration.
type CVEInfo struct {
	// ID is the primary advisory identifier (e.g. "GHSA-c3h9-896r-86jm" or a
	// "CVE-…" id when that is the canonical record).
	ID string `json:"id" yaml:"id"`
	// Aliases lists equivalent identifiers for the same vulnerability, including
	// the CVE id when the primary ID is a non-CVE advisory.
	Aliases []string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	// Package is the affected package name from the SBOM.
	Package string `json:"package" yaml:"package"`
	// Version is the installed (vulnerable) package version.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// FixedVersion is the earliest version that resolves the vulnerability, or
	// empty when no fixed version is published.
	FixedVersion string `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"`
	// CVSS is the CVSS base score (0.0–10.0), or 0 when no vector was available.
	CVSS float64 `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	// Vector is the raw CVSS vector string the score was derived from.
	Vector string `json:"vector,omitempty" yaml:"vector,omitempty"`
	// Purl is the package URL the vulnerability was matched on.
	Purl string `json:"purl,omitempty" yaml:"purl,omitempty"`
	// Image is the container image reference the affected package belongs to.
	Image string `json:"image,omitempty" yaml:"image,omitempty"`
}

// ClusterInfo holds metadata about the scanned cluster.
type ClusterInfo struct {
	// ServerVersion is the Kubernetes server version string.
	ServerVersion string `json:"server_version,omitempty" yaml:"server_version"`
	// NodeCount is the number of nodes in the cluster.
	NodeCount int `json:"node_count" yaml:"node_count"`
	// NamespaceCount is the number of namespaces in the cluster.
	NamespaceCount int `json:"namespace_count" yaml:"namespace_count"`
	// ContextName is the kubeconfig context used for the scan.
	ContextName string `json:"context_name,omitempty" yaml:"context_name"`
}

// ScanMeta holds metadata about the scan execution.
type ScanMeta struct {
	// StartTime is when the scan began.
	StartTime time.Time `json:"start_time"`
	// Duration is how long the scan took.
	Duration time.Duration `json:"duration"`
	// ChecksRun is the number of checks that executed.
	ChecksRun int `json:"checks_run"`
	// ChecksSkipped is the number of checks that were skipped.
	ChecksSkipped int `json:"checks_skipped"`
	// ChecksErrored is the number of checks that encountered errors.
	ChecksErrored int `json:"checks_errored"`
	// CheckNames lists the names of all checks that were executed.
	CheckNames []string `json:"check_names,omitempty"`
	// CheckDescriptions maps check names to their human-readable descriptions.
	CheckDescriptions map[string]string `json:"check_descriptions,omitempty"`
	// CheckCategories maps check names to their primary category name.
	CheckCategories map[string]string `json:"check_categories,omitempty"`
	// ScanMode is how the scan was performed.
	ScanMode ScanMode `json:"scan_mode"`
}

// ScanResult holds the complete results of a scan.
type ScanResult struct {
	// Findings is the list of security issues detected.
	Findings []Finding `json:"findings"`
	// ClusterInfo holds metadata about the scanned cluster.
	ClusterInfo ClusterInfo `json:"cluster_info"`
	// ScanMeta holds metadata about the scan execution.
	ScanMeta ScanMeta `json:"scan_meta"`
}

// Checker is the interface that all security checks must implement.
type Checker interface {
	// Name returns the kebab-case identifier for this check (e.g., "privileged").
	Name() string
	// Description returns a human-readable description of what this check detects.
	Description() string
	// Categories returns the categories this check belongs to.
	Categories() []Category
	// SupportedModes returns which scan modes this check supports.
	SupportedModes() []ScanMode
	// RequiredResources returns the Kubernetes resource types this check needs.
	RequiredResources() []schema.GroupVersionResource
	// Run executes the check against the provided resources and returns findings.
	Run(ctx context.Context, resources *ResourceCache) ([]Finding, error)
}
