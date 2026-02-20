package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// handleGetSummary returns a security posture summary of the most recent scan.
func (kv *KubeVigilMCP) handleGetSummary(
	_ context.Context,
	_ *mcp.CallToolRequest,
	_ GetSummaryInput,
) (*mcp.CallToolResult, ScanSummaryOutput, error) {
	kv.mu.RLock()
	result := kv.lastResult
	kv.mu.RUnlock()

	if result == nil {
		return nil, ScanSummaryOutput{}, fmt.Errorf("get_summary: no scan results available. Run scan_cluster or scan_manifests first")
	}

	return nil, buildSummary(result), nil
}
