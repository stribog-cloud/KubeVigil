package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveOutput_FormatNames(t *testing.T) {
	tests := []struct {
		input  string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"html", "html"},
		{"markdown", "markdown"},
		{"yaml", "yaml"},
		{"sarif", "sarif"},
		{"junit", "junit"},
		{"csv", "csv"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			out, err := resolveOutput(tt.input)
			require.NoError(t, err)
			defer out.Close()

			assert.Equal(t, tt.format, out.Format)
			assert.Equal(t, os.Stdout, out.Writer, "format name should write to stdout")
			assert.Nil(t, out.File, "format name should not open a file")
		})
	}
}

func TestResolveOutput_FilePaths(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		ext    string
		format string
	}{
		{".html", "html"},
		{".htm", "html"},
		{".json", "json"},
		{".md", "markdown"},
		{".yaml", "yaml"},
		{".yml", "yaml"},
		{".sarif", "sarif"},
		{".xml", "junit"},
		{".csv", "csv"},
		{".txt", "text"},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			path := filepath.Join(dir, "report"+tt.ext)
			out, err := resolveOutput(path)
			require.NoError(t, err)

			assert.Equal(t, tt.format, out.Format)
			assert.NotNil(t, out.File, "file path should open a file")
			assert.NotEqual(t, os.Stdout, out.Writer, "file path should not write to stdout")

			// Write something and verify it lands in the file.
			_, err = out.Writer.Write([]byte("test content"))
			require.NoError(t, err)
			require.NoError(t, out.Close())

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "test content", string(data))
		})
	}
}

func TestResolveOutput_InvalidFilePath(t *testing.T) {
	out, err := resolveOutput("/nonexistent/dir/report.html")
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestResolveOutput_Close_Idempotent(t *testing.T) {
	// Close on stdout target should be safe.
	out, err := resolveOutput("text")
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close()) // second call safe
}
