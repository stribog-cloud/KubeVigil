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

// Finding represents a single security issue detected by a checker.
type Finding struct {
	// Checker is the kebab-case ID of the check that produced this finding.
	Checker string `json:"checker"`
	// Severity is the impact level of this finding.
	Severity Severity `json:"severity"`
	// Resource is the name of the Kubernetes resource.
	Resource string `json:"resource"`
	// Namespace is the namespace of the resource (empty for cluster-scoped).
	Namespace string `json:"namespace,omitempty"`
	// Kind is the Kubernetes resource kind (Deployment, Pod, etc.).
	Kind string `json:"kind"`
	// Container is the container name, if applicable.
	Container string `json:"container,omitempty"`
	// Message is a human-readable description of the issue.
	Message string `json:"message"`
	// Remediation describes how to fix the issue.
	Remediation string `json:"remediation"`
	// FieldPath is the JSON path to the problematic field.
	FieldPath string `json:"field_path,omitempty"`
}

// ClusterInfo holds metadata about the scanned cluster.
type ClusterInfo struct {
	// ServerVersion is the Kubernetes server version string.
	ServerVersion string `json:"server_version,omitempty"`
	// NodeCount is the number of nodes in the cluster.
	NodeCount int `json:"node_count"`
	// ContextName is the kubeconfig context used for the scan.
	ContextName string `json:"context_name,omitempty"`
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
