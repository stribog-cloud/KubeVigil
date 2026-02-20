package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBackupDir generates a backup directory path based on the source path and current time.
// Format: <sourcePath>.kubevigil-backup-YYYYMMDDTHHMMSS
func DefaultBackupDir(sourcePath string) string {
	timestamp := time.Now().Format("20060102T150405")
	return fmt.Sprintf("%s.kubevigil-backup-%s", sourcePath, timestamp)
}

// CreateBackup copies files to a backup directory, preserving relative paths from sourceBase.
// Creates the backup directory and any needed subdirectories.
// Returns error if backup directory creation fails or any file copy fails.
func CreateBackup(files []string, sourceBase, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return fmt.Errorf("creating backup directory: %w", err)
	}

	for _, f := range files {
		if err := BackupFile(f, sourceBase, backupDir); err != nil {
			return fmt.Errorf("backing up %s: %w", f, err)
		}
	}

	return nil
}

// BackupFile copies a single file to the backup directory, preserving its path relative to sourceBase.
func BackupFile(srcPath, sourceBase, backupDir string) error {
	relPath, err := filepath.Rel(sourceBase, srcPath)
	if err != nil {
		return fmt.Errorf("computing relative path: %w", err)
	}

	// Reject paths that escape the source base (e.g., "../../../etc/passwd").
	if strings.HasPrefix(relPath, "..") {
		return fmt.Errorf("source path %q is outside base %q (path traversal rejected)", srcPath, sourceBase)
	}

	dstPath := filepath.Join(backupDir, relPath)

	// Create parent directories in the backup location.
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("creating backup subdirectory: %w", err)
	}

	// Read the source file content and permissions.
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("stat source file: %w", err)
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading source file: %w", err)
	}

	// Write to backup location preserving permissions.
	if err := os.WriteFile(dstPath, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("writing backup file: %w", err)
	}

	return nil
}

// GenerateRestoreInstructions creates a RESTORE.md file in the backup directory
// with instructions for restoring the original files.
func GenerateRestoreInstructions(backupDir, sourceBase string, files []string) error {
	var b strings.Builder

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	fmt.Fprintf(&b, "# KubeVigil Fix Backup — Restore Instructions\n\n")
	fmt.Fprintf(&b, "Backup created: %s\n", timestamp)
	fmt.Fprintf(&b, "Source: %s\n\n", sourceBase)

	// Quick restore section.
	fmt.Fprintf(&b, "## Quick Restore (all files)\n\n")
	fmt.Fprintf(&b, "```bash\ncp -r %s/* %s/\n```\n\n", backupDir, sourceBase)

	// Individual file restore table.
	fmt.Fprintf(&b, "## Individual File Restore\n\n")
	fmt.Fprintf(&b, "| Backup File | Original Location |\n")
	fmt.Fprintf(&b, "|------------|-------------------|\n")

	type filePair struct {
		backupPath string
		sourcePath string
		relPath    string
	}

	var pairs []filePair
	for _, f := range files {
		relPath, err := filepath.Rel(sourceBase, f)
		if err != nil {
			relPath = filepath.Base(f)
		}
		pairs = append(pairs, filePair{
			backupPath: filepath.Join(backupDir, relPath),
			sourcePath: filepath.Join(sourceBase, relPath),
			relPath:    relPath,
		})
	}

	for _, p := range pairs {
		fmt.Fprintf(&b, "| %s | %s |\n", p.backupPath, p.sourcePath)
	}

	fmt.Fprintf(&b, "\n")

	// Restore commands section.
	fmt.Fprintf(&b, "## Restore Commands\n\n")
	fmt.Fprintf(&b, "```bash\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "cp \"%s\" \"%s\"\n", p.backupPath, p.sourcePath)
	}
	fmt.Fprintf(&b, "```\n")

	restorePath := filepath.Join(backupDir, "RESTORE.md")
	if err := os.WriteFile(restorePath, []byte(b.String()), 0o644); err != nil { //nolint:gosec // Documentation file; world-readable is intentional.
		return fmt.Errorf("writing RESTORE.md: %w", err)
	}

	return nil
}
