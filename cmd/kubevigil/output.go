package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// outputTarget describes where and in what format to write the report.
type outputTarget struct {
	// Format is the reporter name (e.g., "text", "html", "json").
	Format string
	// Writer is the destination for the report.
	Writer io.Writer
	// File is non-nil when writing to a file (caller must close).
	File *os.File
}

// Close closes the file if one was opened.
func (t *outputTarget) Close() error {
	if t.File != nil {
		return t.File.Close()
	}
	return nil
}

// extensionFormats maps file extensions to reporter format names.
var extensionFormats = map[string]string{
	".html":  "html",
	".htm":   "html",
	".json":  "json",
	".md":    "markdown",
	".yaml":  "yaml",
	".yml":   "yaml",
	".sarif": "sarif",
	".xml":   "junit",
	".csv":   "csv",
	".txt":   "text",
}

// resolveOutput determines whether the --output value is a format name or a
// file path. File paths are detected by checking for a recognized extension.
// When a file path is detected, the format is inferred from the extension and
// the file is opened for writing. Otherwise, the value is treated as a format
// name and output goes to stdout.
func resolveOutput(value string) (*outputTarget, error) {
	// Check if the value has a file extension that maps to a format.
	ext := strings.ToLower(filepath.Ext(value))
	if format, ok := extensionFormats[ext]; ok {
		f, err := os.Create(value)
		if err != nil {
			return nil, fmt.Errorf("creating output file %q: %w", value, err)
		}
		return &outputTarget{Format: format, Writer: f, File: f}, nil
	}

	// Treat as a format name, write to stdout.
	return &outputTarget{Format: value, Writer: os.Stdout}, nil
}
