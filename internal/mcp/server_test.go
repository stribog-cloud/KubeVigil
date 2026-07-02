package mcp

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

func TestNewKubeVigilMCP(t *testing.T) {
	cfg := config.Default()
	reg := checker.NewRegistry()

	kv := NewKubeVigilMCP(cfg, reg, repoWorkspaceRoot())
	if kv == nil {
		t.Fatal("NewKubeVigilMCP returned nil")
	}
	if kv.config != cfg {
		t.Error("config not set")
	}
	if kv.registry != reg {
		t.Error("registry not set")
	}
	if kv.lastResult != nil {
		t.Error("lastResult should be nil initially")
	}
}

func TestLastResultNilBeforeScan(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.NewRegistry(), repoWorkspaceRoot())
	if kv.LastResult() != nil {
		t.Error("LastResult should be nil before any scan")
	}
}

func TestNewMCPServerRegistersAllTools(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.NewRegistry(), repoWorkspaceRoot())
	server := newMCPServer(kv)
	if server == nil {
		t.Fatal("newMCPServer returned nil")
	}
	// The SDK doesn't expose a way to list registered tools directly,
	// but the server creation would panic if tool registration failed.
	// This test verifies the server constructs without panicking.
}

func TestServerRunsWithInMemoryTransport(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry(), repoWorkspaceRoot())
	server := newMCPServer(kv)

	// Use InMemoryTransport to test that the server can accept connections
	// without needing stdio.
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run(ctx, serverTransport)
	}()

	// Create a client and connect to verify the server is running.
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	sess, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect failed: %v", err)
	}
	defer sess.Close()

	// List tools via the MCP protocol to verify all 6 are registered.
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	if len(tools.Tools) != len(ToolNames) {
		t.Errorf("server has %d tools, want %d", len(tools.Tools), len(ToolNames))
	}

	// Verify each expected tool is present.
	registered := make(map[string]bool)
	for _, tool := range tools.Tools {
		registered[tool.Name] = true
	}
	for _, name := range ToolNames {
		if !registered[name] {
			t.Errorf("tool %q not registered in server", name)
		}
	}

	cancel()
	<-errCh
}

func TestNewServerConvenience(t *testing.T) {
	server := NewServer(config.Default(), checker.DefaultRegistry(), repoWorkspaceRoot())
	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	// Verify it works end-to-end via InMemoryTransport.
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Run(ctx, serverTransport) //nolint:errcheck // test cleanup via cancel

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	sess, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect failed: %v", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	if len(tools.Tools) != len(ToolNames) {
		t.Errorf("server has %d tools, want %d", len(tools.Tools), len(ToolNames))
	}
	cancel()
}

func TestToolNamesContainsAllExpected(t *testing.T) {
	expected := map[string]bool{
		"scan_cluster":    true,
		"scan_manifests":  true,
		"get_findings":    true,
		"get_summary":     true,
		"list_checks":     true,
		"get_remediation": true,
	}
	if len(ToolNames) != len(expected) {
		t.Errorf("ToolNames has %d entries, want %d", len(ToolNames), len(expected))
	}
	for _, name := range ToolNames {
		if !expected[name] {
			t.Errorf("unexpected tool name: %q", name)
		}
	}
}
