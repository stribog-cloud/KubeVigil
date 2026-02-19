package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	flagConfig  string
	flagOutput  string
	flagNoColor bool
	flagVerbose bool
)

var rootCmd = &cobra.Command{
	Use:           "kubevigil",
	Short:         "KubeVigil — Know your clusters before attackers do",
	Long:          "KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool\nthat scans clusters and manifests for security misconfigurations.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "config file path (default: auto-discover)")
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "text", "output format or file path (text, json, markdown, yaml, html, sarif, junit, csv; or report.html, report.json, etc.)")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "enable verbose logging")
}

// exitError carries a specific exit code through Cobra's error handling.
type exitError struct {
	code int
	err  error
}

// Error returns the underlying error message, implementing the error interface.
func (e *exitError) Error() string { return e.err.Error() }

func execute() int {
	if err := rootCmd.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}
	return 0
}

func setupLogging() {
	level := slog.LevelWarn
	if flagVerbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
