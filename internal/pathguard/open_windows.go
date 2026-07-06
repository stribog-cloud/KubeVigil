//go:build windows

package pathguard

import (
	"fmt"
	"os"
	"path/filepath"
)

// openConfinedAt opens the file at the given path components under absRoot.
//
// Windows has no openat/O_NOFOLLOW equivalents in the portable syscall
// surface, so confinement is enforced with a best-effort component walk:
// every component is Lstat'd and rejected if it is a symlink or any other
// reparse point surfaced as irregular, and the final handle is re-verified
// with SameFile against the pre-open Lstat to narrow the swap window. This
// is weaker than the Linux openat2 walk and the dir-fd walk on other Unix
// platforms; the platform guarantee tiers are documented in the threat model.
func openConfinedAt(absRoot string, components []string) (*os.File, error) {
	cur := absRoot
	for i, comp := range components {
		isLast := i == len(components)-1
		cur = filepath.Join(cur, comp)

		info, err := os.Lstat(cur)
		if err != nil {
			return nil, fmt.Errorf("opening %q: %w", comp, err)
		}
		mode := info.Mode()
		if mode&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil, fmt.Errorf("path %q is a symlink (rejected for security)", comp)
		}
		if !isLast {
			if !mode.IsDir() {
				return nil, fmt.Errorf("opening %q: not a directory", comp)
			}
			continue
		}
		if !mode.IsRegular() {
			return nil, fmt.Errorf("path component %q is not a regular file", comp)
		}

		f, err := os.OpenFile(cur, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("opening %q: %w", comp, err)
		}
		opened, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("fstat %q: %w", comp, err)
		}
		if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			_ = f.Close()
			return nil, fmt.Errorf("path %q changed during open (rejected for security)", comp)
		}
		return f, nil
	}

	return nil, fmt.Errorf("path %q is not a file", filepath.Join(components...))
}
