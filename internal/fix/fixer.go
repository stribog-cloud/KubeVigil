// Package fix provides the auto-remediation engine for KubeVigil.
package fix

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
)

// Fixer orchestrates the scan → filter → classify → patch → backup → verify pipeline.
type Fixer struct {
	fixRegistry     *Registry
	checkerRegistry *checker.Registry
	scanConfig      *config.Config
	fixConfig       Config
	classifier      *SafetyClassifier
}

// Plan describes all planned fixes across all files.
type Plan struct {
	// Files maps file paths to their individual plans.
	Files map[string]*FilePlan
	// Diffs maps file paths to unified diff strings.
	Diffs map[string]string
	// Summary holds aggregate counts.
	Summary Summary
}

// FilePlan describes all planned fixes for a single file.
type FilePlan struct {
	// Path is the absolute path to the file.
	Path string
	// Fixes is the list of planned fixes for this file.
	Fixes []PlannedFix
	// PatchedContent is the in-memory patched YAML.
	PatchedContent []byte
	// OriginalContent is the original file content.
	OriginalContent []byte
}

// PlannedFix describes a single fix to be applied.
type PlannedFix struct {
	// Finding is the security finding being fixed.
	Finding checker.Finding
	// Strategy is the fix strategy to apply.
	Strategy Strategy
	// Applied indicates whether the fix was successfully applied to the YAML.
	Applied bool
	// SkipReason explains why the fix was skipped (empty if applied).
	SkipReason string
}

// NewFixer creates a Fixer with the given registries and configuration.
func NewFixer(fixReg *Registry, checkerReg *checker.Registry, scanCfg *config.Config, fixCfg *Config) *Fixer {
	return &Fixer{
		fixRegistry:     fixReg,
		checkerRegistry: checkerReg,
		scanConfig:      scanCfg,
		fixConfig:       *fixCfg,
		classifier:      NewSafetyClassifier(fixCfg.AdditionalSystemNamespaces),
	}
}

// Plan scans the given paths and builds a fix plan without modifying any files.
func (f *Fixer) Plan(ctx context.Context, paths []string) (*Plan, error) {
	files, err := collectFiles(paths)
	if err != nil {
		return nil, fmt.Errorf("collecting files: %w", err)
	}

	scanner := engine.NewScanner(f.checkerRegistry, f.scanConfig)

	plan := &Plan{
		Files: make(map[string]*FilePlan),
		Diffs: make(map[string]string),
	}
	plan.Summary.ByRisk = make(map[checker.FixSafety]int)
	plan.Summary.SkipReasons = make(map[string]int)

	for _, file := range files {
		plan.Summary.FilesScanned++

		filePlan, fileErr := f.planFile(ctx, scanner, file)
		if fileErr != nil {
			slog.Warn("error planning file", "file", file, "error", fileErr)
			plan.Summary.FilesFailed++
			plan.Summary.Errors = append(plan.Summary.Errors, FileError{
				FilePath: file,
				Err:      fileErr.Error(),
			})
			continue
		}

		if filePlan == nil {
			continue
		}

		// Count applied and skipped fixes.
		hasApplied := false
		for i := range filePlan.Fixes {
			pf := &filePlan.Fixes[i]
			plan.Summary.TotalFindings++
			if pf.Applied {
				plan.Summary.Applied++
				plan.Summary.ByRisk[pf.Strategy.Safety]++
				hasApplied = true

				plan.Summary.Results = append(plan.Summary.Results, Result{
					FilePath:    file,
					Resource:    pf.Finding.Resource,
					Namespace:   pf.Finding.Namespace,
					Kind:        pf.Finding.Kind,
					CheckID:     pf.Finding.Checker,
					Safety:      pf.Strategy.Safety,
					Description: pf.Strategy.Description,
					Impact:      pf.Strategy.Impact,
					Applied:     true,
				})
			} else {
				plan.Summary.Skipped++
				plan.Summary.SkipReasons[pf.SkipReason]++

				plan.Summary.Results = append(plan.Summary.Results, Result{
					FilePath:    file,
					Resource:    pf.Finding.Resource,
					Namespace:   pf.Finding.Namespace,
					Kind:        pf.Finding.Kind,
					CheckID:     pf.Finding.Checker,
					Safety:      pf.Strategy.Safety,
					Description: pf.Strategy.Description,
					Impact:      pf.Strategy.Impact,
					Applied:     false,
					SkipReason:  pf.SkipReason,
				})
			}
		}

		if hasApplied {
			plan.Files[file] = filePlan
			diff := GenerateDiff(file, filePlan.OriginalContent, filePlan.PatchedContent)
			if diff != "" {
				plan.Diffs[file] = diff
			}
			plan.Summary.FilesModified++
		}
	}

	return plan, nil
}

// Apply writes the planned fixes to disk, creating a backup first.
func (f *Fixer) Apply(ctx context.Context, plan *Plan) (*Summary, error) {
	if len(plan.Files) == 0 {
		return &plan.Summary, nil
	}

	// Collect files to modify.
	var filePaths []string
	for path := range plan.Files {
		filePaths = append(filePaths, path)
	}
	sort.Strings(filePaths)

	// Determine source base for backup structure.
	sourceBase := commonBase(filePaths)

	// Determine backup directory.
	backupDir := f.fixConfig.BackupDir
	if backupDir == "" {
		backupDir = DefaultBackupDir(sourceBase)
	}

	// Create backup.
	if err := CreateBackup(filePaths, sourceBase, backupDir); err != nil {
		return nil, fmt.Errorf("creating backup: %w", err)
	}
	plan.Summary.BackupDir = backupDir

	// Write patched files.
	applied := 0
	failed := 0
	for _, path := range filePaths {
		fp := plan.Files[path]
		info, statErr := os.Stat(path)
		perm := os.FileMode(0o644)
		if statErr == nil {
			perm = info.Mode().Perm()
		}
		if err := os.WriteFile(path, fp.PatchedContent, perm); err != nil {
			slog.Warn("error writing patched file", "file", path, "error", err)
			plan.Summary.Errors = append(plan.Summary.Errors, FileError{
				FilePath: path,
				Err:      err.Error(),
			})
			failed++
			continue
		}
		applied++
	}

	// Generate restore instructions.
	if err := GenerateRestoreInstructions(backupDir, sourceBase, filePaths); err != nil {
		slog.Warn("error generating restore instructions", "error", err)
	}

	// Update summary counts based on actual writes.
	if failed > 0 && applied == 0 {
		// Total failure — nothing written.
		return &plan.Summary, fmt.Errorf("all %d files failed to write", failed)
	}

	// Verify if requested.
	if f.fixConfig.Verify {
		scanner := engine.NewScanner(f.checkerRegistry, f.scanConfig)
		for _, path := range filePaths {
			result, err := scanner.ScanManifest(ctx, path)
			if err != nil {
				slog.Warn("verify scan error", "file", path, "error", err)
				continue
			}
			// Check if any of the fixed checks still have findings.
			for i := range result.Findings {
				if f.fixRegistry.Has(result.Findings[i].Checker) {
					slog.Warn("verify: finding persists after fix",
						"file", path,
						"checker", result.Findings[i].Checker,
						"resource", result.Findings[i].Resource,
					)
				}
			}
		}
	}

	return &plan.Summary, nil
}

// Verify re-scans files from a plan and computes how many findings were resolved,
// how many remain, and whether new ones were introduced.
func (f *Fixer) Verify(ctx context.Context, plan *Plan) (*VerifyResult, error) {
	result := &VerifyResult{
		RemainingFindings: make(map[string][]string),
	}

	// Count applied fixes as TotalBefore.
	result.TotalBefore = plan.Summary.Applied

	scanner := engine.NewScanner(f.checkerRegistry, f.scanConfig)

	// Collect all files that were modified.
	var filePaths []string
	for path := range plan.Files {
		filePaths = append(filePaths, path)
	}
	sort.Strings(filePaths)

	for _, path := range filePaths {
		scanResult, err := scanner.ScanManifest(ctx, path)
		if err != nil {
			slog.Warn("verify scan error", "file", path, "error", err)
			continue
		}

		for i := range scanResult.Findings {
			if f.fixRegistry.Has(scanResult.Findings[i].Checker) {
				result.TotalAfter++
				result.RemainingFindings[path] = append(
					result.RemainingFindings[path],
					scanResult.Findings[i].Checker,
				)
			}
		}
	}

	result.Remaining = result.TotalAfter
	if result.TotalAfter > result.TotalBefore {
		result.New = result.TotalAfter - result.TotalBefore
		result.Resolved = 0
	} else {
		result.Resolved = result.TotalBefore - result.TotalAfter
		result.New = 0
	}
	result.Clean = result.TotalAfter == 0

	return result, nil
}

// Fix is a convenience method that calls Plan followed by Apply (if Apply is enabled).
func (f *Fixer) Fix(ctx context.Context, paths []string) (*Plan, *Summary, error) {
	plan, err := f.Plan(ctx, paths)
	if err != nil {
		return nil, nil, err
	}

	if !f.fixConfig.Apply || f.fixConfig.DryRun {
		return plan, &plan.Summary, nil
	}

	summary, err := f.Apply(ctx, plan)
	return plan, summary, err
}

// maxManifestFileSize is the maximum allowed size for a single YAML manifest file (10 MiB).
const maxManifestFileSize = 10 << 20

// planFile scans a single file and builds a FilePlan.
// Returns nil if there are no fixable findings.
// Rejects files larger than maxManifestFileSize to prevent resource exhaustion.
func (f *Fixer) planFile(ctx context.Context, scanner *engine.Scanner, path string) (*FilePlan, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	if info.Size() > maxManifestFileSize {
		return nil, fmt.Errorf("reading file: file size %d bytes exceeds maximum of %d bytes",
			info.Size(), maxManifestFileSize)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// Scan the file for findings.
	result, err := scanner.ScanManifest(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("scanning file: %w", err)
	}

	if len(result.Findings) == 0 {
		return nil, nil
	}

	// Filter findings and build planned fixes.
	var planned []PlannedFix
	for i := range result.Findings {
		strategy, ok := f.fixRegistry.Get(result.Findings[i].Checker)
		if !ok {
			continue // No fix strategy for this check.
		}

		pf := f.classifyFinding(&result.Findings[i], &strategy)
		planned = append(planned, pf)
	}

	if len(planned) == 0 {
		return nil, nil
	}

	// Separate applied from skipped.
	var toApply []PlannedFix
	for i := range planned {
		if planned[i].Applied {
			toApply = append(toApply, planned[i])
		}
	}

	if len(toApply) == 0 {
		return &FilePlan{
			Path:            path,
			Fixes:           planned,
			OriginalContent: original,
			PatchedContent:  original,
		}, nil
	}

	// Parse the YAML and apply fixes.
	docs, err := ParseDocuments(original)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	for i := range toApply {
		pf := &toApply[i]
		if err := applyFixToDocs(docs, pf); err != nil {
			slog.Warn("error applying fix",
				"file", path,
				"checker", pf.Finding.Checker,
				"resource", pf.Finding.Resource,
				"error", err,
			)
			pf.Applied = false
			pf.SkipReason = fmt.Sprintf("apply_error: %v", err)
		}
	}

	// Serialize patched documents.
	patched, err := SerializeDocuments(docs)
	if err != nil {
		return nil, fmt.Errorf("serializing patched YAML: %w", err)
	}

	// Merge applied status back into planned list.
	allFixes := mergeAppliedStatus(planned, toApply)

	return &FilePlan{
		Path:            path,
		Fixes:           allFixes,
		OriginalContent: original,
		PatchedContent:  patched,
	}, nil
}

// classifyFinding determines whether a finding should be fixed and why.
func (f *Fixer) classifyFinding(finding *checker.Finding, strategy *Strategy) PlannedFix {
	pf := PlannedFix{
		Finding:  *finding,
		Strategy: *strategy,
		Applied:  true,
	}

	// Check filter: fingerprints.
	if len(f.fixConfig.Fingerprints) > 0 {
		fp := FindingFingerprint(finding)
		found := false
		for _, want := range f.fixConfig.Fingerprints {
			if want == fp {
				found = true
				break
			}
		}
		if !found {
			pf.Applied = false
			pf.SkipReason = "fingerprint_not_selected"
			return pf
		}
	}

	// Check filter: specific checks.
	if len(f.fixConfig.Checks) > 0 {
		found := false
		for _, c := range f.fixConfig.Checks {
			if c == finding.Checker {
				found = true
				break
			}
		}
		if !found {
			pf.Applied = false
			pf.SkipReason = "check_not_selected"
			return pf
		}
	}

	// Check filter: severities.
	if len(f.fixConfig.Severities) > 0 {
		found := false
		sevStr := finding.Severity.String()
		for _, s := range f.fixConfig.Severities {
			if strings.EqualFold(s, sevStr) {
				found = true
				break
			}
		}
		if !found {
			pf.Applied = false
			pf.SkipReason = "severity_not_selected"
			return pf
		}
	}

	// Check filter: namespaces.
	if len(f.fixConfig.Namespaces) > 0 {
		found := false
		for _, ns := range f.fixConfig.Namespaces {
			if ns == finding.Namespace {
				found = true
				break
			}
		}
		if !found {
			pf.Applied = false
			pf.SkipReason = "namespace_not_selected"
			return pf
		}
	}

	// Check filter: excluded namespaces.
	for _, ns := range f.fixConfig.ExcludeNamespaces {
		if ns == finding.Namespace {
			pf.Applied = false
			pf.SkipReason = "namespace_excluded"
			return pf
		}
	}

	// System namespace protection (Ring 3).
	if f.classifier.IsSystemNamespace(finding.Namespace) && !f.fixConfig.AllowSystemNamespaces {
		pf.Applied = false
		pf.SkipReason = "system_namespace"
		return pf
	}

	// Risk level gating (Ring 2).
	if !f.fixConfig.RiskLevel.AllowsSafety(strategy.Safety) {
		pf.Applied = false
		pf.SkipReason = "risk_level"
		return pf
	}

	return pf
}

// applyFixToDocs applies a single fix to the matching document.
func applyFixToDocs(docs []*Document, pf *PlannedFix) error {
	// Find the matching document by kind+name+namespace.
	for _, doc := range docs {
		if doc.Node == nil {
			continue
		}

		apiVersion, kind, name, namespace := extractMetadata(doc)
		if apiVersion == "" || kind == "" {
			continue
		}

		if kind != pf.Finding.Kind || name != pf.Finding.Resource {
			continue
		}
		if pf.Finding.Namespace != "" && namespace != pf.Finding.Namespace {
			continue
		}

		// Resolve the YAML path.
		yamlPath := resolveYAMLPath(&pf.Finding, &pf.Strategy, kind)

		// Apply the fix based on operation type.
		var err error
		switch pf.Strategy.Operation {
		case checker.FixOpSet:
			err = SetNode(doc.Node, yamlPath, pf.Strategy.DesiredValue)
		case checker.FixOpAdd:
			err = AddNode(doc.Node, yamlPath, pf.Strategy.DesiredValue)
			if err != nil && strings.Contains(err.Error(), "already exists") {
				// Fall back to SetNode if the field already exists.
				err = SetNode(doc.Node, yamlPath, pf.Strategy.DesiredValue)
			}
		case checker.FixOpRemove:
			err = RemoveNode(doc.Node, yamlPath)
		case checker.FixOpMerge:
			err = MergeNode(doc.Node, yamlPath, pf.Strategy.DesiredValue)
			if err != nil && strings.Contains(err.Error(), "not found") {
				// If the target node doesn't exist yet, use SetNode to create it.
				err = SetNode(doc.Node, yamlPath, pf.Strategy.DesiredValue)
			}
		default:
			return fmt.Errorf("unknown fix operation: %q", pf.Strategy.Operation)
		}

		if err != nil {
			return fmt.Errorf("applying %s to %s %s/%s at %s: %w",
				pf.Strategy.Operation, kind, namespace, name, yamlPath, err)
		}

		doc.Modified = true
		return nil
	}

	return fmt.Errorf("no matching document found for %s %s/%s",
		pf.Finding.Kind, pf.Finding.Namespace, pf.Finding.Resource)
}

// containerRefRe matches a concrete container reference like containers[0] or initContainers[1].
var containerRefRe = regexp.MustCompile(`(?:init)?[Cc]ontainers\[\d+\]`)

// resolveYAMLPath translates a strategy's field path into a full YAML path by
// substituting concrete container indices from the finding and prepending the
// template prefix for the resource kind.
//
// The strategy's field path defines WHICH field to set (e.g., runAsNonRoot).
// The finding's field path may point to a DIFFERENT field (e.g., runAsUser)
// that was detected as problematic. We always use the strategy's target field,
// but substitute the finding's concrete container index for any wildcard.
func resolveYAMLPath(finding *checker.Finding, strategy *Strategy, kind string) string {
	var fieldPath string

	switch {
	case strategy.FieldPath != "" && finding.FieldPath != "":
		// Use the strategy's path (defines the target field to set).
		// Substitute the finding's concrete container index for any [*] wildcard.
		fieldPath = strategy.FieldPath
		if m := containerRefRe.FindString(finding.FieldPath); m != "" {
			fieldPath = strings.Replace(fieldPath, "containers[*]", m, 1)
		}
	case strategy.FieldPath != "":
		fieldPath = strategy.FieldPath
	default:
		fieldPath = finding.FieldPath
	}

	// Strip leading dot from finding paths (e.g., ".spec.containers[0]..." → "spec.containers[0]...").
	fieldPath = strings.TrimPrefix(fieldPath, ".")

	// Prepend the pod spec template prefix based on kind.
	prefix := podSpecPrefix(kind)
	if prefix != "" {
		fieldPath = prefix + fieldPath
	}

	return fieldPath
}

// podSpecPrefix returns the YAML path prefix to prepend to PodSpec-relative paths.
// Mirrors findPodSpecMap in internal/checker/workload/pod_spec.go.
func podSpecPrefix(kind string) string {
	switch kind {
	case "Pod":
		return "" // PodSpec IS at spec.
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		return "spec.template."
	case "CronJob":
		return "spec.jobTemplate.spec.template."
	default:
		return "" // Non-workload kinds: path used as-is.
	}
}

// extractMetadata reads apiVersion, kind, name, and namespace from a Document's YAML nodes.
func extractMetadata(doc *Document) (apiVersion, kind, name, namespace string) {
	if doc.Node == nil {
		return
	}

	content := contentNode(doc.Node)
	if content == nil || content.Kind != mappingNodeKind {
		return
	}

	for i := 0; i < len(content.Content)-1; i += 2 {
		key := content.Content[i].Value
		val := content.Content[i+1]

		switch key {
		case "apiVersion":
			apiVersion = val.Value
		case "kind":
			kind = val.Value
		case "metadata":
			if val.Kind == mappingNodeKind {
				for j := 0; j < len(val.Content)-1; j += 2 {
					mKey := val.Content[j].Value
					mVal := val.Content[j+1]
					switch mKey {
					case "name":
						name = mVal.Value
					case "namespace":
						namespace = mVal.Value
					}
				}
			}
		}
	}
	return
}

const mappingNodeKind = 4 // yaml.MappingNode

// collectFiles walks the given paths and returns all .yaml/.yml files, sorted.
func collectFiles(paths []string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string

	for _, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolving path %s: %w", path, err)
		}

		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", abs, err)
		}

		if !info.IsDir() {
			if isYAMLFile(abs) && !seen[abs] {
				seen[abs] = true
				files = append(files, abs)
			}
			continue
		}

		err = filepath.WalkDir(abs, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if isYAMLFile(p) && !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", abs, err)
		}
	}

	sort.Strings(files)
	return files, nil
}

// isYAMLFile returns true if the file has a .yaml or .yml extension.
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// commonBase finds the longest common directory prefix of the given paths.
func commonBase(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	if len(paths) == 1 {
		return filepath.Dir(paths[0])
	}

	base := filepath.Dir(paths[0])
	for _, p := range paths[1:] {
		dir := filepath.Dir(p)
		for !strings.HasPrefix(dir, base) && base != "/" && base != "." {
			base = filepath.Dir(base)
		}
	}
	return base
}

// mergeAppliedStatus merges the updated applied status from toApply back into
// the full planned list. toApply items that failed get their status updated.
func mergeAppliedStatus(all, applied []PlannedFix) []PlannedFix {
	// Build a map of applied items by finding key.
	type fixKey struct {
		checker   string
		resource  string
		namespace string
		container string
	}
	appliedMap := make(map[fixKey]*PlannedFix, len(applied))
	for i := range applied {
		k := fixKey{
			checker:   applied[i].Finding.Checker,
			resource:  applied[i].Finding.Resource,
			namespace: applied[i].Finding.Namespace,
			container: applied[i].Finding.Container,
		}
		appliedMap[k] = &applied[i]
	}

	result := make([]PlannedFix, len(all))
	for i := range all {
		result[i] = all[i]
		k := fixKey{
			checker:   all[i].Finding.Checker,
			resource:  all[i].Finding.Resource,
			namespace: all[i].Finding.Namespace,
			container: all[i].Finding.Container,
		}
		if updated, ok := appliedMap[k]; ok {
			result[i].Applied = updated.Applied
			result[i].SkipReason = updated.SkipReason
		}
	}
	return result
}
