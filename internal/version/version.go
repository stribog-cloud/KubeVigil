// Package version provides build version information set via ldflags.
package version

// Build information variables, set at build time via ldflags.
var (
	// Version is the semantic version of the build (e.g., "v0.3.0"), defaulting to "dev".
	Version = "dev"
	// Commit is the git commit SHA of the build, defaulting to "unknown".
	Commit = "unknown"
	// Date is the build date in RFC 3339 format, defaulting to "unknown".
	Date = "unknown"
)
