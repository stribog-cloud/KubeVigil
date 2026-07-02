// Package pathguard confines filesystem paths to a workspace root for untrusted callers.
package pathguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WorkspaceRootEnv is the environment variable overriding the MCP workspace root.
const WorkspaceRootEnv = "KUBEVIGIL_WORKSPACE_ROOT"

// DefaultWorkspaceRoot returns the absolute workspace root from the environment or cwd.
func DefaultWorkspaceRoot() (string, error) {
	if v := strings.TrimSpace(os.Getenv(WorkspaceRootEnv)); v != "" {
		return filepath.Abs(v)
	}
	return os.Getwd()
}

// ResolveWithinRoot resolves path relative to root, rejecting traversal outside root
// and symlink escapes. The returned path is absolute and cleaned.
func ResolveWithinRoot(root, path string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving workspace root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)

	clean := filepath.Clean(path)
	var candidate string
	switch {
	case filepath.IsAbs(clean):
		candidate = clean
	default:
		candidate = filepath.Join(absRoot, clean)
	}
	candidate = filepath.Clean(candidate)

	if err := assertWithinRoot(absRoot, candidate); err != nil {
		return "", err
	}

	info, err := os.Lstat(candidate)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", candidate, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("path %q is a symlink (rejected for security)", candidate)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return "", fmt.Errorf("path %q is not a regular file or directory", candidate)
	}

	// Re-check after Lstat: a symlink component in a parent could have been missed
	// if the final component is not a symlink but parents are. Walk up from candidate.
	if err := assertNoSymlinkParents(absRoot, candidate); err != nil {
		return "", err
	}

	return candidate, nil
}

// OpenRegularWithinRoot opens a regular file confined to root via a dir-fd-relative walk
// (openat2 RESOLVE_NO_SYMLINKS on Linux; openat+O_NOFOLLOW elsewhere) so symlink swaps on
// parent components or the leaf cannot escape the workspace between validation and read.
func OpenRegularWithinRoot(root, path string) (*os.File, error) {
	confined, err := ResolveWithinRoot(root, path)
	if err != nil {
		return nil, err
	}

	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolving workspace root: %w", err)
	}

	rel, err := filepath.Rel(absRoot, confined)
	if err != nil {
		return nil, fmt.Errorf("path %q outside workspace root %q: %w", confined, absRoot, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("path %q is outside workspace root %q", confined, absRoot)
	}

	return openConfinedRegularFile(absRoot, rel)
}

// AssertWithinRoot reports whether path resides inside root.
func AssertWithinRoot(root, path string) error {
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return fmt.Errorf("resolving workspace root: %w", err)
	}
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}
	return assertWithinRoot(absRoot, absPath)
}

func assertWithinRoot(absRoot, candidate string) error {
	rel, err := filepath.Rel(absRoot, candidate)
	if err != nil {
		return fmt.Errorf("path %q outside workspace root %q: %w", candidate, absRoot, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q is outside workspace root %q", candidate, absRoot)
	}
	return nil
}

func assertNoSymlinkParents(absRoot, candidate string) error {
	dir := candidate
	for {
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(parent, absRoot) {
			break
		}
		info, err := os.Lstat(parent)
		if err != nil {
			return fmt.Errorf("checking parent %q: %w", parent, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path %q traverses symlink parent %q (rejected for security)", candidate, parent)
		}
		if parent == absRoot {
			break
		}
		dir = parent
	}
	return nil
}
