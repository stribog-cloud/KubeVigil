// Package version provides build version information set via ldflags.
package version

// Version, Commit, and Date are set at build time via ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
