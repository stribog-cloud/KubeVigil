package mcp

import (
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// ToolNames enumerates the MCP tool identifiers registered by the server.
var ToolNames = []string{
	"scan_cluster",
	"scan_manifests",
	"get_findings",
	"get_summary",
	"list_checks",
	"get_remediation",
}

// KubeVigilMCP is the MCP server state. It holds the checker registry,
// configuration, and the most recent scan result.
type KubeVigilMCP struct {
	config     *config.Config
	registry   *checker.Registry
	lastResult *checker.ScanResult
	mu         sync.RWMutex
}

// NewKubeVigilMCP creates a new MCP server instance with the given
// configuration and checker registry.
func NewKubeVigilMCP(cfg *config.Config, registry *checker.Registry) *KubeVigilMCP {
	return &KubeVigilMCP{
		config:   cfg,
		registry: registry,
	}
}

// LastResult returns the most recent scan result, or nil if no scan has run.
// It is safe for concurrent use.
func (kv *KubeVigilMCP) LastResult() *checker.ScanResult {
	kv.mu.RLock()
	defer kv.mu.RUnlock()
	return kv.lastResult
}

// NewServer creates an MCP server with all KubeVigil tools registered.
// The caller is responsible for running the server with an appropriate
// transport (e.g., [mcp.StdioTransport] for CLI use).
func NewServer(cfg *config.Config, registry *checker.Registry) *mcp.Server {
	kv := NewKubeVigilMCP(cfg, registry)
	return newMCPServer(kv)
}

// newMCPServer creates and configures the MCP server with all tools registered.
func newMCPServer(kv *KubeVigilMCP) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "kubevigil",
			Version: version.Version,
		},
		nil,
	)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_cluster",
		Description: "Scan a live Kubernetes cluster for security misconfigurations. Returns a summary with finding counts by severity and category, top issues, and compliance stats. Use get_findings to drill into specific results.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, kv.handleScanCluster)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_manifests",
		Description: "Scan Kubernetes YAML manifests (file or directory) for security issues. Returns a summary with finding counts by severity and category. Use get_findings to drill into specific results.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, kv.handleScanManifests)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_findings",
		Description: "Query and filter findings from the most recent scan. Supports filtering by severity, category, namespace, checker ID, and compliance framework. Results are paginated (default 25, max 100 per page).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, kv.handleGetFindings)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_summary",
		Description: "Get a security posture summary of the most recent scan, including finding counts by severity and category, top issues, and compliance framework stats.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, kv.handleGetSummary)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_checks",
		Description: "List available security checks with their categories, severities, supported scan modes, and auto-fix status. Filter by category or scan mode.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, kv.handleListChecks)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_remediation",
		Description: "Get detailed remediation guidance for a specific security check, including fix hints, compliance framework references, and current/desired values for a targeted resource.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, kv.handleGetRemediation)

	return server
}
