package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Fprintf(os.Stdout, "KubeVigil %s\n", version.Version)
		fmt.Fprintf(os.Stdout, "  Commit: %s\n", version.Commit)
		fmt.Fprintf(os.Stdout, "  Built:  %s\n", version.Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
