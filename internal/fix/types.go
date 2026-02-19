package fix

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// RiskLevel controls which fix safety levels are applied.
type RiskLevel string

const (
	// RiskLevelSafe applies only safe fixes (default).
	RiskLevelSafe RiskLevel = "safe"
	// RiskLevelModerate applies safe and likely_safe fixes.
	RiskLevelModerate RiskLevel = "moderate"
	// RiskLevelAggressive applies safe, likely_safe, and potentially_breaking fixes.
	RiskLevelAggressive RiskLevel = "aggressive"
)

// ParseRiskLevel converts a string to a RiskLevel value.
// Returns an error if the string is not a valid risk level.
func ParseRiskLevel(s string) (RiskLevel, error) {
	switch strings.ToLower(s) {
	case "safe":
		return RiskLevelSafe, nil
	case "moderate":
		return RiskLevelModerate, nil
	case "aggressive":
		return RiskLevelAggressive, nil
	default:
		return "", fmt.Errorf("unknown risk level: %q (valid: safe, moderate, aggressive)", s)
	}
}

// AllowsSafety returns true if the given risk level permits fixes at the given safety level.
// Safe is always allowed. Manual-only is never allowed.
func (r RiskLevel) AllowsSafety(safety checker.FixSafety) bool {
	switch safety {
	case checker.FixSafe:
		return true
	case checker.FixLikelySafe:
		return r == RiskLevelModerate || r == RiskLevelAggressive
	case checker.FixPotentiallyBreaking:
		return r == RiskLevelAggressive
	case checker.FixManualOnly:
		return false
	default:
		return false
	}
}

// Result represents the outcome of a single fix application.
type Result struct {
	// FilePath is the path to the file containing the resource.
	FilePath string `json:"file_path"`
	// Resource is the name of the Kubernetes resource.
	Resource string `json:"resource"`
	// Namespace is the namespace of the resource (empty for cluster-scoped).
	Namespace string `json:"namespace,omitempty"`
	// Kind is the Kubernetes resource kind (Deployment, Pod, etc.).
	Kind string `json:"kind"`
	// CheckID is the kebab-case identifier of the check that produced the finding.
	CheckID string `json:"check_id"`
	// Safety is the risk classification of the fix.
	Safety checker.FixSafety `json:"safety"`
	// Description explains what the fix does.
	Description string `json:"description"`
	// Impact explains what could break if this fix is applied.
	Impact string `json:"impact,omitempty"`
	// Applied indicates whether the fix was actually written to disk.
	Applied bool `json:"applied"`
	// SkipReason explains why a fix was not applied (empty if applied).
	SkipReason string `json:"skip_reason,omitempty"`
}

// Summary is the aggregate result of a fix operation.
type Summary struct {
	// FilesScanned is the total number of files processed.
	FilesScanned int `json:"files_scanned"`
	// FilesModified is the number of files that were modified.
	FilesModified int `json:"files_modified"`
	// FilesFailed is the number of files that encountered errors during processing.
	FilesFailed int `json:"files_failed"`
	// TotalFindings is the total number of fixable findings discovered.
	TotalFindings int `json:"total_findings"`
	// Applied is the number of fixes that were applied.
	Applied int `json:"applied"`
	// Skipped is the number of fixes that were skipped.
	Skipped int `json:"skipped"`
	// ByRisk breaks down applied fixes by safety classification.
	ByRisk map[checker.FixSafety]int `json:"by_risk"`
	// SkipReasons breaks down skipped fixes by reason.
	SkipReasons map[string]int `json:"skip_reasons"`
	// Results is the list of individual fix outcomes.
	Results []Result `json:"results"`
	// Errors is the list of per-file errors encountered during processing.
	Errors []FileError `json:"errors,omitempty"`
	// BackupDir is the path to the backup directory (empty if no backup was created).
	BackupDir string `json:"backup_dir,omitempty"`
}

// FileError records a per-file error encountered during fix processing.
type FileError struct {
	// FilePath is the path to the file that encountered an error.
	FilePath string `json:"file_path"`
	// Err is the error message.
	Err string `json:"error"`
}

// Config holds configuration for a fix operation.
type Config struct {
	// RiskLevel controls which fix safety levels are applied.
	RiskLevel RiskLevel `json:"risk_level"`
	// Apply enables writing fixes to disk. When false, only a diff is shown.
	Apply bool `json:"apply"`
	// DryRun forces dry-run mode even if Apply is true. This is redundant with
	// the default behavior but allows explicit opt-in for clarity.
	DryRun bool `json:"dry_run"`
	// Verify re-scans files after applying fixes to confirm zero findings.
	Verify bool `json:"verify"`
	// Yes bypasses interactive confirmation prompts.
	Yes bool `json:"yes"`
	// AllowSystemNamespaces unlocks fixing resources in system namespaces.
	AllowSystemNamespaces bool `json:"allow_system_namespaces"`
	// BulkThreshold is the number of files above which interactive confirmation
	// is required (unless Yes is true).
	BulkThreshold int `json:"bulk_threshold"`
	// BackupDir is the directory where backups are stored before applying fixes.
	BackupDir string `json:"backup_dir,omitempty"`
	// Checks limits fixes to findings from these specific check IDs.
	Checks []string `json:"checks,omitempty"`
	// Severities limits fixes to findings at these severity levels.
	Severities []string `json:"severities,omitempty"`
	// Namespaces limits fixes to resources in these namespaces.
	Namespaces []string `json:"namespaces,omitempty"`
	// ExcludeNamespaces excludes resources in these namespaces from fixes.
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`
	// Fingerprints limits fixes to findings matching these fingerprint hashes.
	Fingerprints []string `json:"fingerprints,omitempty"`
	// AdditionalSystemNamespaces extends the built-in list of system namespaces
	// that are protected from auto-fixing.
	AdditionalSystemNamespaces []string `json:"additional_system_namespaces,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
// Dry-run is the default mode: Apply is false, RiskLevel is safe,
// and BulkThreshold is 10.
func DefaultConfig() Config {
	return Config{
		RiskLevel:     RiskLevelSafe,
		BulkThreshold: 10,
	}
}

// VerifyResult holds the outcome of a post-fix verification scan.
type VerifyResult struct {
	// TotalBefore is the number of fixable findings before the fix.
	TotalBefore int `json:"total_before"`
	// TotalAfter is the number of fixable findings after the fix.
	TotalAfter int `json:"total_after"`
	// Resolved is the number of findings that were resolved by fixes.
	Resolved int `json:"resolved"`
	// Remaining is the number of fixable findings that persist after fixes.
	Remaining int `json:"remaining"`
	// New is the number of new fixable findings introduced by fixes.
	New int `json:"new"`
	// RemainingFindings maps file paths to the checker IDs of remaining findings.
	RemainingFindings map[string][]string `json:"remaining_findings,omitempty"`
	// Clean is true if no fixable findings remain after the fix.
	Clean bool `json:"clean"`
}

// FindingFingerprint computes a deterministic hash from a finding's identifying
// fields: check ID, resource kind, resource name, namespace, and field path.
// Returns a 12-character hex string suitable for use with --fingerprint.
func FindingFingerprint(f *checker.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s", f.Checker, f.Kind, f.Resource, f.Namespace, f.FieldPath)
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

// ExitCode constants for fix operations.
const (
	// ExitFixSuccess indicates all planned fixes were applied (or dry-run shows changes).
	ExitFixSuccess = 0
	// ExitFixVerifyFailed indicates fixes were applied but --verify found remaining findings.
	ExitFixVerifyFailed = 1
	// ExitFixError indicates a total failure (backup failed, no files could be processed).
	ExitFixError = 2
	// ExitFixConfigError indicates invalid flags or conflicting configuration options.
	ExitFixConfigError = 3
	// ExitFixNothingToDo indicates no fixable findings were found.
	ExitFixNothingToDo = 4
	// ExitFixPartialSuccess indicates some fixes applied but some files failed.
	ExitFixPartialSuccess = 5
)
