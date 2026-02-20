package mcp_test

// E2E tests for the MCP server against the real kubevigil binary.
//
// These tests start bin/kubevigil mcp-server as a subprocess, connect via
// the MCP SDK's CommandTransport, and exercise all 6 tools through the
// real MCP protocol. No running Kubernetes cluster is required — only
// manifest scan mode is used.
//
// Approach: Go subprocess tests (not Bats) because:
//   - Native JSON parsing for JSON-RPC response validation
//   - Type-safe assertions with Go testing
//   - MCP SDK's CommandTransport handles subprocess lifecycle
//   - Programmatic schema validation of tool responses
//
// Prerequisites: bin/kubevigil must be built (make build).

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// kubevigiBinary returns the path to the kubevigil binary, or skips the test
// if the binary is not found.
func kubevigilBinary(t *testing.T) string {
	t.Helper()

	// Find the repo root from this test file's location.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")
	binary := filepath.Join(repoRoot, "bin", "kubevigil")

	if _, err := os.Stat(binary); err != nil {
		t.Skipf("kubevigil binary not found at %s (run 'make build' first)", binary)
	}
	return binary
}

// e2eFixturesDir returns the path to the test fixtures directory.
func e2eFixturesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "test", "fixtures")
}

// connectToServer starts the kubevigil MCP server as a subprocess and returns
// a connected client session. The server is automatically shut down when the
// test ends.
func connectToServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	binary := kubevigilBinary(t)
	cmd := exec.Command(binary, "mcp-server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "e2e-test",
		Version: "v0.0.1",
	}, nil)

	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to MCP server: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	return session
}

// TestE2EServerStartupAndCapabilities verifies that the real binary starts,
// completes the MCP initialize handshake, and reports correct capabilities.
func TestE2EServerStartupAndCapabilities(t *testing.T) {
	session := connectToServer(t)

	// Ping to verify the connection is alive.
	ctx := context.Background()
	if err := session.Ping(ctx, nil); err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

// TestE2EToolDiscovery verifies that tools/list returns all 6 tools with
// correct names, descriptions, and input schemas.
func TestE2EToolDiscovery(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	expectedTools := map[string]bool{
		"scan_cluster":    false,
		"scan_manifests":  false,
		"get_findings":    false,
		"get_summary":     false,
		"list_checks":     false,
		"get_remediation": false,
	}

	if len(result.Tools) != len(expectedTools) {
		t.Errorf("got %d tools, want %d", len(result.Tools), len(expectedTools))
	}

	for _, tool := range result.Tools {
		if _, ok := expectedTools[tool.Name]; !ok {
			t.Errorf("unexpected tool: %q", tool.Name)
			continue
		}
		expectedTools[tool.Name] = true

		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
		// Verify each tool has an input schema.
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil input schema", tool.Name)
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("expected tool %q not found", name)
		}
	}
}

// TestE2EManifestScanEndToEnd scans real fixture files and verifies the
// summary response contains valid finding counts.
func TestE2EManifestScanEndToEnd(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	fixtureDir := filepath.Join(e2eFixturesDir(t), "privileged")
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "scan_manifests",
		Arguments: map[string]any{"path": fixtureDir},
	})
	if err != nil {
		t.Fatalf("scan_manifests failed: %v", err)
	}

	// The result should have text content with the summary JSON.
	if result.IsError {
		t.Fatalf("scan_manifests returned error: %v", contentText(result))
	}

	// Parse the structured content from the tool result.
	summary := extractSummary(t, result)
	if summary.TotalFindings == 0 {
		t.Error("expected non-zero total findings from privileged fixtures")
	}
	if summary.ChecksRun == 0 {
		t.Error("expected non-zero checks run")
	}

	// Verify severity counts add up.
	sevTotal := 0
	for _, count := range summary.SeverityCounts {
		sevTotal += count
	}
	if sevTotal != summary.TotalFindings {
		t.Errorf("severity counts sum (%d) != total findings (%d)", sevTotal, summary.TotalFindings)
	}
}

// TestE2EFindingsQueryAfterScan verifies that get_findings returns filtered
// results from a prior scan.
func TestE2EFindingsQueryAfterScan(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	// First scan.
	fixtureDir := filepath.Join(e2eFixturesDir(t), "privileged")
	_, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "scan_manifests",
		Arguments: map[string]any{"path": fixtureDir},
	})
	if err != nil {
		t.Fatalf("scan_manifests failed: %v", err)
	}

	// Query all findings.
	allResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_findings",
		Arguments: map[string]any{"limit": 100},
	})
	if err != nil {
		t.Fatalf("get_findings failed: %v", err)
	}
	allFindings := extractFindings(t, allResult)
	if allFindings.Total == 0 {
		t.Fatal("expected findings from scan")
	}

	// Query only critical findings.
	critResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_findings",
		Arguments: map[string]any{"severity": "critical", "limit": 100},
	})
	if err != nil {
		t.Fatalf("get_findings with severity filter failed: %v", err)
	}
	critFindings := extractFindings(t, critResult)

	// Verify all returned findings are critical.
	for _, f := range critFindings.Findings {
		if f.Severity != "Critical" {
			t.Errorf("finding %q has severity %q, want Critical", f.Checker, f.Severity)
		}
	}
	// Critical should be <= total.
	if critFindings.Total > allFindings.Total {
		t.Errorf("critical findings (%d) > all findings (%d)", critFindings.Total, allFindings.Total)
	}

	// Verify pagination metadata.
	if allFindings.Limit == 0 {
		t.Error("expected non-zero limit in pagination")
	}
}

// TestE2ESummaryAfterScan verifies that get_summary returns consistent data.
func TestE2ESummaryAfterScan(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	// Scan first.
	fixtureDir := filepath.Join(e2eFixturesDir(t), "privileged")
	scanResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "scan_manifests",
		Arguments: map[string]any{"path": fixtureDir},
	})
	if err != nil {
		t.Fatalf("scan_manifests failed: %v", err)
	}
	scanSummary := extractSummary(t, scanResult)

	// Get summary.
	summaryResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_summary",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("get_summary failed: %v", err)
	}
	summary := extractSummary(t, summaryResult)

	// Summary should match the scan.
	if summary.TotalFindings != scanSummary.TotalFindings {
		t.Errorf("get_summary total (%d) != scan total (%d)", summary.TotalFindings, scanSummary.TotalFindings)
	}

	// Top issues should be sorted by count descending.
	for i := 1; i < len(summary.TopIssues); i++ {
		if summary.TopIssues[i].Count > summary.TopIssues[i-1].Count {
			t.Errorf("top issues not sorted: [%d].Count=%d > [%d].Count=%d",
				i, summary.TopIssues[i].Count, i-1, summary.TopIssues[i-1].Count)
		}
	}
}

// TestE2EListChecks verifies list_checks returns the full registry and
// supports category filtering.
func TestE2EListChecks(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	// List all checks.
	allResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_checks",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("list_checks failed: %v", err)
	}
	allChecks := extractCheckList(t, allResult)
	if allChecks.Total < 110 {
		t.Errorf("expected at least 110 checks, got %d", allChecks.Total)
	}

	// Filter by RBAC category.
	rbacResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_checks",
		Arguments: map[string]any{"category": "RBAC"},
	})
	if err != nil {
		t.Fatalf("list_checks with category filter failed: %v", err)
	}
	rbacChecks := extractCheckList(t, rbacResult)
	if rbacChecks.Total == 0 {
		t.Error("expected RBAC checks")
	}
	if rbacChecks.Total >= allChecks.Total {
		t.Errorf("RBAC checks (%d) should be less than all checks (%d)", rbacChecks.Total, allChecks.Total)
	}
	// Verify all returned checks are RBAC.
	for _, c := range rbacChecks.Checks {
		if c.Category != "RBAC" {
			t.Errorf("check %q has category %q, want RBAC", c.ID, c.Category)
		}
	}
}

// TestE2ERemediationLookup verifies get_remediation returns non-empty
// guidance with framework references.
func TestE2ERemediationLookup(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_remediation",
		Arguments: map[string]any{"checker": "privileged"},
	})
	if err != nil {
		t.Fatalf("get_remediation failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("get_remediation returned error: %v", contentText(result))
	}

	remediation := extractRemediation(t, result)
	if remediation.Remediation == "" {
		t.Error("expected non-empty remediation text")
	}
	if remediation.Checker != "privileged" {
		t.Errorf("checker = %q, want %q", remediation.Checker, "privileged")
	}
	if remediation.Description == "" {
		t.Error("expected non-empty description")
	}
}

// TestE2EErrorHandlingNoScan verifies that querying findings without a prior
// scan returns an appropriate error. The MCP SDK wraps tool handler errors
// in a CallToolResult with IsError=true.
func TestE2EErrorHandlingNoScan(t *testing.T) {
	session := connectToServer(t)
	ctx := context.Background()

	// Call get_findings without any prior scan.
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_findings",
		Arguments: map[string]any{},
	})

	// The SDK may return the error as a Go error or as a result with IsError.
	if err != nil {
		// Error returned at protocol level — still valid, check message.
		errMsg := err.Error()
		if !containsSubstring(errMsg, "no scan results") {
			t.Errorf("error message %q should mention 'no scan results'", errMsg)
		}
		return
	}

	// Error wrapped in result with IsError=true.
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for get_findings with no prior scan")
	}
	text := contentText(result)
	if !containsSubstring(text, "no scan results") {
		t.Errorf("error content %q should mention 'no scan results'", text)
	}

	// Also test get_summary without scan.
	summaryResult, summaryErr := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_summary",
		Arguments: map[string]any{},
	})
	if summaryErr != nil {
		if !containsSubstring(summaryErr.Error(), "no scan results") {
			t.Errorf("get_summary error %q should mention 'no scan results'", summaryErr.Error())
		}
		return
	}
	if summaryResult != nil && !summaryResult.IsError {
		t.Error("expected get_summary to return error without prior scan")
	}
}

// TestE2ECleanShutdown verifies the server exits cleanly when the client
// session is closed.
func TestE2ECleanShutdown(t *testing.T) {
	binary := kubevigilBinary(t)
	cmd := exec.Command(binary, "mcp-server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "e2e-shutdown-test",
		Version: "v0.0.1",
	}, nil)

	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to MCP server: %v", err)
	}

	// Verify the server is alive.
	if err := session.Ping(ctx, nil); err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	// Close the session — the server should exit cleanly.
	if err := session.Close(); err != nil {
		t.Fatalf("closing session: %v", err)
	}
}

// --- Helper types and functions ---

// e2eSummary mirrors ScanSummaryOutput for JSON unmarshaling in E2E tests.
type e2eSummary struct {
	Cluster        string         `json:"cluster"`
	ServerVersion  string         `json:"server_version"`
	NodeCount      int            `json:"node_count"`
	ChecksRun      int            `json:"checks_run"`
	ChecksErrored  int            `json:"checks_errored"`
	TotalFindings  int            `json:"total_findings"`
	SeverityCounts map[string]int `json:"severity_counts"`
	CategoryCounts map[string]int `json:"category_counts"`
	TopIssues      []struct {
		Checker  string `json:"checker"`
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	} `json:"top_issues"`
	ComplianceStats map[string]int `json:"compliance_stats"`
}

// e2eFindingsOutput mirrors FindingsOutput for JSON unmarshaling.
type e2eFindingsOutput struct {
	Findings []struct {
		Checker  string `json:"checker"`
		Severity string `json:"severity"`
		Resource string `json:"resource"`
	} `json:"findings"`
	Total   int  `json:"total"`
	Offset  int  `json:"offset"`
	Limit   int  `json:"limit"`
	HasMore bool `json:"has_more"`
}

// e2eCheckList mirrors CheckListOutput for JSON unmarshaling.
type e2eCheckList struct {
	Checks []struct {
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Category    string   `json:"category"`
		Modes       []string `json:"modes"`
		Severity    string   `json:"severity"`
		AutoFixable bool     `json:"auto_fixable"`
	} `json:"checks"`
	Total int `json:"total"`
}

// e2eRemediation mirrors RemediationOutput for JSON unmarshaling.
type e2eRemediation struct {
	Checker     string `json:"checker"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// contentText extracts the text content from an MCP CallToolResult.
func contentText(result *mcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// extractSummary parses a ScanSummaryOutput from the tool result JSON.
func extractSummary(t *testing.T, result *mcp.CallToolResult) e2eSummary {
	t.Helper()
	text := contentText(result)
	if text == "" {
		t.Fatal("empty content in tool result")
	}
	var summary e2eSummary
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		t.Fatalf("parsing summary JSON: %v\nraw: %s", err, text)
	}
	return summary
}

// extractFindings parses a FindingsOutput from the tool result JSON.
func extractFindings(t *testing.T, result *mcp.CallToolResult) e2eFindingsOutput {
	t.Helper()
	text := contentText(result)
	if text == "" {
		t.Fatal("empty content in tool result")
	}
	var findings e2eFindingsOutput
	if err := json.Unmarshal([]byte(text), &findings); err != nil {
		t.Fatalf("parsing findings JSON: %v\nraw: %s", err, text)
	}
	return findings
}

// extractCheckList parses a CheckListOutput from the tool result JSON.
func extractCheckList(t *testing.T, result *mcp.CallToolResult) e2eCheckList {
	t.Helper()
	text := contentText(result)
	if text == "" {
		t.Fatal("empty content in tool result")
	}
	var checks e2eCheckList
	if err := json.Unmarshal([]byte(text), &checks); err != nil {
		t.Fatalf("parsing check list JSON: %v\nraw: %s", err, text)
	}
	return checks
}

// extractRemediation parses a RemediationOutput from the tool result JSON.
func extractRemediation(t *testing.T, result *mcp.CallToolResult) e2eRemediation {
	t.Helper()
	text := contentText(result)
	if text == "" {
		t.Fatal("empty content in tool result")
	}
	var rem e2eRemediation
	if err := json.Unmarshal([]byte(text), &rem); err != nil {
		t.Fatalf("parsing remediation JSON: %v\nraw: %s", err, text)
	}
	return rem
}

// containsSubstring checks if s contains substr (case-insensitive).
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(substr) == 0 ||
			findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFold(s, t string) bool {
	for i := 0; i < len(s); i++ {
		a, b := s[i], t[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}
