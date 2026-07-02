//go:build linux

package pathguard

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openConfinedAt(absRoot string, components []string) (*os.File, error) {
	rootFD, err := unix.Open(absRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening workspace root %q: %w", absRoot, err)
	}
	defer unix.Close(rootFD)

	dirFD := rootFD
	for i, comp := range components {
		isLast := i == len(components)-1

		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if !isLast {
			flags |= unix.O_DIRECTORY
		}

		how := &unix.OpenHow{
			Flags:   uint64(flags),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
		}

		nextFD, err := unix.Openat2(dirFD, comp, how)
		if err != nil {
			return nil, fmt.Errorf("opening %q: %w", comp, err)
		}

		if !isLast {
			if dirFD != rootFD {
				unix.Close(dirFD)
			}
			dirFD = nextFD
			continue
		}

		var stat unix.Stat_t
		if err := unix.Fstat(nextFD, &stat); err != nil {
			unix.Close(nextFD)
			return nil, fmt.Errorf("fstat %q: %w", comp, err)
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			unix.Close(nextFD)
			return nil, fmt.Errorf("path %q is a symlink (rejected for security)", comp)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			unix.Close(nextFD)
			return nil, fmt.Errorf("path component %q is not a regular file", comp)
		}

		return os.NewFile(uintptr(nextFD), filepath.Join(absRoot, filepath.Join(components...))), nil
	}

	return nil, fmt.Errorf("path %q is not a file", filepath.Join(components...))
}
