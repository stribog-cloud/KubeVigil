package pathguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// openConfinedRegularFile opens relPath (relative to absRoot) via a dir-fd-relative walk
// so parent-directory symlink swaps cannot escape the workspace between validation and read.
func openConfinedRegularFile(absRoot, relPath string) (*os.File, error) {
	rel := filepath.ToSlash(filepath.Clean(relPath))
	if rel == "." || rel == "" {
		return nil, fmt.Errorf("path %q is not a file", relPath)
	}
	if strings.HasPrefix(rel, "../") || rel == ".." {
		return nil, fmt.Errorf("path %q is outside workspace root %q", relPath, absRoot)
	}

	components := strings.Split(rel, "/")
	return openConfinedAt(absRoot, components)
}
