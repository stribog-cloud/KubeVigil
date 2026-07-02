package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	mcpserver "github.com/stribog-cloud/kubevigil/internal/mcp"
	"github.com/stribog-cloud/kubevigil/internal/pathguard"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Start the KubeVigil MCP server (stdio transport)",
	Long:  "Launches a Model Context Protocol server over stdin/stdout for AI assistant integration.",
	RunE:  runMCPServer,
}

var mcpWorkspaceRoot string

func init() {
	mcpCmd.Flags().String("transport", "stdio", "transport type (stdio)")
	mcpCmd.Flags().StringVar(&mcpWorkspaceRoot, "workspace-root", "", "root directory for manifest scans (default: KUBEVIGIL_WORKSPACE_ROOT or cwd)")
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServer(_ *cobra.Command, _ []string) error {
	setupLogging()
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	root := mcpWorkspaceRoot
	if root == "" {
		var rootErr error
		root, rootErr = pathguard.DefaultWorkspaceRoot()
		if rootErr != nil {
			return fmt.Errorf("resolving workspace root: %w", rootErr)
		}
	} else {
		abs, absErr := filepath.Abs(root)
		if absErr != nil {
			return fmt.Errorf("resolving workspace root: %w", absErr)
		}
		root = abs
	}
	server := mcpserver.NewServer(cfg, checker.DefaultRegistry(), root)
	return server.Run(context.Background(), &mcp.StdioTransport{})
}
