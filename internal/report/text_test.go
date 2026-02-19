package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func init() {
	// Disable colors in tests for deterministic output.
	color.NoColor = true
}

func TestTextReporter_EmptyFindings(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Findings (0 total)")
	assert.Contains(t, out, "Total Findings:  0")
}

func TestTextReporter_SingleFinding(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Container:   "nginx",
				Message:     "Container runs in privileged mode",
				Remediation: "Set securityContext.privileged to false",
				FieldPath:   ".spec.containers[0].securityContext.privileged",
			},
		},
		ScanMeta: checker.ScanMeta{
			Duration: 42 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "[Critical] privileged")
	assert.Contains(t, out, "Resource:    default/Deployment/nginx")
	assert.Contains(t, out, "Container:   nginx")
	assert.Contains(t, out, "Message:     Container runs in privileged mode")
	assert.Contains(t, out, "Remediation: Set securityContext.privileged to false")
	assert.Contains(t, out, "Field:       .spec.containers[0].securityContext.privileged")
	assert.Contains(t, out, "Findings (1 total)")
	assert.Contains(t, out, "Total Findings:  1")
	assert.Contains(t, out, "Critical: 1")
}

func TestTextReporter_MultipleSeverities(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:  "resource-limits-ratio",
				Severity: checker.SeverityLow,
				Resource: "web",
				Kind:     "Deployment",
				Message:  "Limits-to-requests ratio too high",
			},
			{
				Checker:  "privileged",
				Severity: checker.SeverityCritical,
				Resource: "nginx",
				Kind:     "Deployment",
				Message:  "Container runs in privileged mode",
			},
			{
				Checker:  "read-only-rootfs",
				Severity: checker.SeverityMedium,
				Resource: "api",
				Kind:     "Pod",
				Message:  "Root filesystem is not read-only",
			},
		},
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	// Critical should appear before Medium, which should appear before Low.
	critIdx := strings.Index(out, "[Critical]")
	medIdx := strings.Index(out, "[Medium]")
	lowIdx := strings.Index(out, "[Low]")
	assert.Greater(t, medIdx, critIdx, "Medium should appear after Critical")
	assert.Greater(t, lowIdx, medIdx, "Low should appear after Medium")
}

func TestTextReporter_ContainerShown(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:   "privileged",
				Severity:  checker.SeverityCritical,
				Resource:  "nginx",
				Kind:      "Deployment",
				Container: "sidecar",
				Message:   "test",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Container:   sidecar")
}

func TestTextReporter_NoContainerOmitted(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:  "host-pid",
				Severity: checker.SeverityCritical,
				Resource: "nginx",
				Kind:     "Pod",
				Message:  "hostPID enabled",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "Container:")
}

func TestTextReporter_LiveModeClusterInfo(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeLive,
			Duration: 100 * time.Millisecond,
		},
		ClusterInfo: checker.ClusterInfo{
			ServerVersion: "v1.28.0",
			ContextName:   "prod-cluster",
			NodeCount:     5,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Server Version:  v1.28.0")
	assert.Contains(t, out, "Context:         prod-cluster")
	assert.Contains(t, out, "Node Count:      5")
	assert.Contains(t, out, "Scan Mode:       Live")
}

func TestTextReporter_ManifestModeNoClusterInfo(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeManifest,
			Duration: 10 * time.Millisecond,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.NotContains(t, out, "Server Version:")
	assert.NotContains(t, out, "Context:")
	assert.NotContains(t, out, "Node Count:")
}

func TestTextReporter_SummaryOnly(t *testing.T) {
	r := &TextReporter{SummaryOnly: true}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "worker", Namespace: "default", Kind: "StatefulSet", Message: "not read-only"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	out := buf.String()

	// Executive Summary should contain the severity breakdown.
	assert.Contains(t, out, "Executive Summary")
	assert.Contains(t, out, "Total Findings:  4")
	assert.Contains(t, out, "Critical: 2")

	// Should have per-namespace breakdown (moved up after Findings header).
	assert.Contains(t, out, "By Namespace:")
	assert.Contains(t, out, "backend")
	assert.Contains(t, out, "default")

	// Should NOT have the old redundant Summary section.
	assert.NotContains(t, out, "\nSummary\n")

	// Should NOT have individual finding details.
	assert.NotContains(t, out, "privileged mode")
	assert.NotContains(t, out, "runs as root")
	assert.NotContains(t, out, "Remediation:")
}

func TestTextReporter_TopRisks(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:   "privileged",
				Severity:  checker.SeverityCritical,
				Resource:  "nginx",
				Namespace: "default",
				Kind:      "Deployment",
				Container: "nginx",
				Message:   "Container runs in privileged mode",
			},
			{
				Checker:   "run-as-root",
				Severity:  checker.SeverityHigh,
				Resource:  "api",
				Namespace: "backend",
				Kind:      "Deployment",
				Container: "api",
				Message:   "Container runs as root",
			},
			{
				Checker:   "read-only-rootfs",
				Severity:  checker.SeverityMedium,
				Resource:  "worker",
				Namespace: "default",
				Kind:      "StatefulSet",
				Container: "worker",
				Message:   "Root filesystem is not read-only",
			},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()

	// Should have "Top Risks" section header.
	assert.Contains(t, out, "Top Risks")

	// Should contain the top risk details.
	assert.Contains(t, out, "[Critical]")
	assert.Contains(t, out, "privileged")
	assert.Contains(t, out, "default/Deployment/nginx")
	assert.Contains(t, out, "Container runs in privileged mode")

	assert.Contains(t, out, "[High]")
	assert.Contains(t, out, "run-as-root")
	assert.Contains(t, out, "backend/Deployment/api")
	assert.Contains(t, out, "Container runs as root")

	// Top Risks should appear after Executive Summary and before Findings.
	topRisksIdx := strings.Index(out, "Top Risks\n")
	execSummaryIdx := strings.Index(out, "Executive Summary")
	findingsIdx := strings.Index(out, "Findings (3 total)")
	assert.Greater(t, topRisksIdx, execSummaryIdx, "Top Risks should appear after Executive Summary")
	assert.Less(t, topRisksIdx, findingsIdx, "Top Risks should appear before Findings")
}

func TestTextReporter_ComplianceSummary(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:   "privileged",
				Severity:  checker.SeverityCritical,
				Resource:  "nginx",
				Namespace: "default",
				Kind:      "Deployment",
				Message:   "Container runs in privileged mode",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.1", Title: "Minimize privileged containers"},
					{Framework: "mitre", Version: "v14", ControlID: "T1611", Title: "Escape to Host"},
					{Framework: "nsa", Version: "1.2", ControlID: "3.1", Title: "Pod Security"},
				},
			},
			{
				Checker:   "run-as-root",
				Severity:  checker.SeverityHigh,
				Resource:  "api",
				Namespace: "backend",
				Kind:      "Deployment",
				Message:   "Container runs as root",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.6", Title: "Minimize root containers"},
				},
			},
			{
				Checker:   "read-only-rootfs",
				Severity:  checker.SeverityMedium,
				Resource:  "worker",
				Namespace: "default",
				Kind:      "StatefulSet",
				Message:   "Root filesystem is not read-only",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.4", Title: "Read-only rootfs"},
					{Framework: "nsa", Version: "1.2", ControlID: "3.1", Title: "Pod Security"},
				},
			},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()

	// Should have "Compliance" section header.
	assert.Contains(t, out, "Compliance\n")

	// CIS has 3 unique controls: 5.2.1, 5.2.6, 5.2.4.
	assert.Contains(t, out, "CIS v1.8")
	assert.Contains(t, out, "3 controls violated")

	// MITRE has 1 unique technique: T1611.
	assert.Contains(t, out, "MITRE ATT&CK v14")
	assert.Contains(t, out, "1 technique")

	// NSA has 1 unique control: 3.1.
	assert.Contains(t, out, "NSA/CISA v1.2")
	assert.Contains(t, out, "1 control violated")

	// Compliance should appear after findings section.
	complianceIdx := strings.Index(out, "Compliance\n")
	findingsIdx := strings.Index(out, "Findings (3 total)")
	assert.Greater(t, complianceIdx, findingsIdx, "Compliance should appear after Findings")
}

func TestTextReporter_PassedChecks(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer

	checkNames := []string{
		"automount-token", "capabilities-drop-all", "host-network", "host-pid",
		"host-port", "image-latest-tag", "liveness-probe", "memory-limits",
		"privileged", "read-only-rootfs", "readiness-probe", "resource-limits",
		"resource-requests", "run-as-non-root", "run-as-root", "seccomp-profile",
		"service-account", "sysctls", "host-ipc", "apparmor-profile",
		"cpu-limits", "ephemeral-storage", "host-aliases", "privilege-escalation",
		"startup-probe",
	}

	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "worker", Namespace: "default", Kind: "StatefulSet", Message: "not read-only"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:   checker.ScanModeManifest,
			ChecksRun:  25,
			CheckNames: checkNames,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()

	// Should contain "Checks Passed (22):" header with the count.
	assert.Contains(t, out, "Checks Passed (22):")

	// With 22 passed, should show first 10 and "... and 12 more".
	assert.Contains(t, out, "... and 12 more")

	// Should contain some of the first passed check names (sorted alphabetically).
	assert.Contains(t, out, "apparmor-profile")
	assert.Contains(t, out, "automount-token")
}

func TestTextReporter_PassedChecks_FewPassed(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer

	checkNames := []string{
		"privileged", "run-as-root", "read-only-rootfs",
		"host-network", "host-pid",
	}

	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "worker", Namespace: "default", Kind: "StatefulSet", Message: "not read-only"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:   checker.ScanModeManifest,
			ChecksRun:  5,
			CheckNames: checkNames,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()

	assert.Contains(t, out, "Checks Passed (2):")
	assert.Contains(t, out, "host-network")
	assert.Contains(t, out, "host-pid")
	assert.NotContains(t, out, "... and")
}

func TestTextReporter_NoRedundantSummary(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()

	// The old redundant Summary section should be gone.
	assert.NotContains(t, out, "\nSummary\n")
	assert.NotContains(t, out, "Total: 2 findings")

	// Executive summary should still exist.
	assert.Contains(t, out, "Executive Summary")
}

func TestTextReporter_NamespaceTierGrouping(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Container:   "nginx",
				Message:     "Container runs in privileged mode",
				Remediation: "Set privileged: false",
			},
			{
				Checker:     "run-as-root",
				Severity:    checker.SeverityHigh,
				Resource:    "coredns",
				Namespace:   "monitoring",
				Kind:        "Deployment",
				Container:   "coredns",
				Message:     "Container runs as root",
				Remediation: "Set runAsNonRoot: true",
			},
			{
				Checker:     "rbac-wildcard",
				Severity:    checker.SeverityCritical,
				Resource:    "admin",
				Namespace:   "",
				Kind:        "ClusterRole",
				Message:     "Wildcard resource access",
				Remediation: "Restrict RBAC resources",
			},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()

	// Should have tier section headers.
	assert.Contains(t, out, "Application Namespaces")
	assert.Contains(t, out, "Infrastructure Namespaces")
	assert.Contains(t, out, "Cluster-Scoped")

	// Find the tier header positions using the unique tier header format.
	appIdx := strings.Index(out, "── Application Namespaces")
	infraIdx := strings.Index(out, "── Infrastructure Namespaces")
	clusterIdx := strings.Index(out, "── Cluster-Scoped")

	// Tiers should appear in order.
	assert.Greater(t, infraIdx, appIdx, "Infrastructure should appear after Application")
	assert.Greater(t, clusterIdx, infraIdx, "Cluster-Scoped should appear after Infrastructure")

	// Findings should appear under correct tiers.
	defaultFindingIdx := strings.Index(out[appIdx:], "default/Deployment/nginx") + appIdx
	assert.Greater(t, defaultFindingIdx, appIdx, "default NS finding should be after Application header")
	assert.Less(t, defaultFindingIdx, infraIdx, "default NS finding should be before Infrastructure header")

	monitorFindingIdx := strings.Index(out[infraIdx:], "monitoring/Deployment/coredns") + infraIdx
	assert.Greater(t, monitorFindingIdx, infraIdx, "monitoring NS finding should be after Infrastructure header")
	assert.Less(t, monitorFindingIdx, clusterIdx, "monitoring NS finding should be before Cluster-Scoped header")

	clusterRoleFindingIdx := strings.Index(out[clusterIdx:], "ClusterRole/admin") + clusterIdx
	assert.Greater(t, clusterRoleFindingIdx, clusterIdx, "ClusterRole finding should be after Cluster-Scoped header")
}

func TestTextReporter_SummaryOnlyNamespaceBreakdown(t *testing.T) {
	r := &TextReporter{SummaryOnly: true}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "By Namespace:")
	assert.Contains(t, out, "backend")
	assert.Contains(t, out, "default")
	assert.NotContains(t, out, "\nSummary\n")
}

func TestTextReporter_CancelledContext(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}
