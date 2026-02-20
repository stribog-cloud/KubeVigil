package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	mcpserver "github.com/stribog-cloud/kubevigil/internal/mcp"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Start the KubeVigil MCP server (stdio transport)",
	Long:  "Launches a Model Context Protocol server over stdin/stdout for AI assistant integration.",
	RunE:  runMCPServer,
}

func init() {
	mcpCmd.Flags().String("transport", "stdio", "transport type (stdio)")
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServer(_ *cobra.Command, _ []string) error {
	setupLogging()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	server := mcpserver.NewServer(cfg, checker.DefaultRegistry())
	return server.Run(context.Background(), &mcp.StdioTransport{})
}
