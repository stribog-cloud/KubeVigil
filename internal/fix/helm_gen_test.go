package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"gopkg.in/yaml.v3"
)

// helmTestPlan builds a Plan with applied results for the given check IDs.
func helmTestPlan(checkIDs ...string) *Plan {
	var results []Result
	for _, id := range checkIDs {
		safety := checker.FixSafe
		switch id {
		case "read-only-rootfs", "run-as-root", "capabilities-not-dropped", "seccomp-profile", "image-pull-policy":
			safety = checker.FixLikelySafe
		case "resource-limits-missing", "resource-requests-missing":
			safety = checker.FixPotentiallyBreaking
		}
		results = append(results, Result{
			CheckID: id,
			Safety:  safety,
			Applied: true,
		})
	}
	return &Plan{
		Summary: Summary{
			Applied: len(results),
			Results: results,
		},
	}
}

func TestGenerateHelmValues_Basic(t *testing.T) {
	plan := helmTestPlan("privileged", "privilege-escalation")
	opts := DefaultHelmValuesOptions()

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Must contain securityContext section.
	if !strings.Contains(content, "securityContext:") {
		t.Error("output missing 'securityContext:' section")
	}

	// Must contain the specific values.
	if !strings.Contains(content, "privileged: false") {
		t.Error("output missing 'privileged: false'")
	}
	if !strings.Contains(content, "allowPrivilegeEscalation: false") {
		t.Error("output missing 'allowPrivilegeEscalation: false'")
	}
}

func TestGenerateHelmValues_PotentiallyBreakingCommented(t *testing.T) {
	plan := helmTestPlan("resource-limits-missing", "resource-requests-missing")
	opts := HelmValuesOptions{
		RiskLevel:          RiskLevelAggressive,
		CommentOutBreaking: true,
	}

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Resources section should be commented out.
	if !strings.Contains(content, "# resources:") {
		t.Error("output missing commented '# resources:' line")
	}

	// Should contain a warning comment.
	if !strings.Contains(content, "potentially breaking") {
		t.Error("output missing 'potentially breaking' warning for commented resources")
	}

	// Verify the values are commented.
	if !strings.Contains(content, "#   limits:") {
		t.Error("output missing commented '#   limits:' line")
	}
}

func TestGenerateHelmValues_PotentiallyBreakingUncommented(t *testing.T) {
	plan := helmTestPlan("resource-limits-missing", "resource-requests-missing")
	opts := HelmValuesOptions{
		RiskLevel:          RiskLevelAggressive,
		CommentOutBreaking: false,
	}

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Resources section should NOT be commented out.
	if !strings.Contains(content, "resources:") {
		t.Error("output missing 'resources:' section")
	}

	// The actual values should not have comment prefix.
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Lines containing "limits:" or "requests:" in the resources section
		// should NOT start with "#" (excluding header comments at top).
		if strings.Contains(line, "limits:") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			// Good - uncommented.
			return
		}
	}
}

func TestGenerateHelmValues_EmptyPlan(t *testing.T) {
	plan := &Plan{
		Summary: Summary{
			Applied: 0,
			Results: nil,
		},
	}
	opts := DefaultHelmValuesOptions()

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Header should still be present.
	if !strings.Contains(content, "KubeVigil Security Values") {
		t.Error("empty plan output missing header")
	}

	// Should not contain any value sections.
	if strings.Contains(content, "securityContext:") {
		t.Error("empty plan output should not contain 'securityContext:' section")
	}
	if strings.Contains(content, "serviceAccount:") {
		t.Error("empty plan output should not contain 'serviceAccount:' section")
	}
}

func TestGenerateHelmValues_MergedSecurityContext(t *testing.T) {
	plan := helmTestPlan(
		"privileged",
		"privilege-escalation",
		"read-only-rootfs",
		"run-as-root",
		"capabilities-not-dropped",
		"seccomp-profile",
	)
	opts := HelmValuesOptions{
		RiskLevel:          RiskLevelModerate,
		CommentOutBreaking: true,
	}

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// All security context values should be under one securityContext: block.
	// Count occurrences of "securityContext:" — should be exactly one.
	count := strings.Count(content, "securityContext:")
	if count != 1 {
		t.Errorf("expected exactly 1 'securityContext:' occurrence, got %d", count)
	}

	// All values should be present.
	for _, want := range []string{
		"privileged: false",
		"allowPrivilegeEscalation: false",
		"readOnlyRootFilesystem: true",
		"runAsNonRoot: true",
		"drop:",
		"- ALL",
		"seccompProfile:",
		"type: RuntimeDefault",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestGenerateHelmValues_Header(t *testing.T) {
	plan := helmTestPlan("privileged")
	tests := []struct {
		name      string
		riskLevel RiskLevel
		wantText  string
	}{
		{"safe_risk", RiskLevelSafe, "Risk level: safe"},
		{"moderate_risk", RiskLevelModerate, "Risk level: moderate"},
		{"aggressive_risk", RiskLevelAggressive, "Risk level: aggressive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := HelmValuesOptions{
				RiskLevel:          tt.riskLevel,
				CommentOutBreaking: true,
			}

			output, err := GenerateHelmValues(plan, opts)
			if err != nil {
				t.Fatalf("GenerateHelmValues() error = %v", err)
			}
			content := string(output)

			if !strings.Contains(content, "KubeVigil Security Values") {
				t.Error("output missing 'KubeVigil Security Values' header")
			}
			if !strings.Contains(content, "Generated for Helm chart hardening") {
				t.Error("output missing 'Generated for Helm chart hardening' line")
			}
			if !strings.Contains(content, tt.wantText) {
				t.Errorf("output missing %q", tt.wantText)
			}
			if !strings.Contains(content, "helm upgrade") {
				t.Error("output missing 'helm upgrade' usage hint")
			}
		})
	}
}

func TestGenerateHelmValues_ParseableYAML(t *testing.T) {
	plan := helmTestPlan(
		"privileged",
		"privilege-escalation",
		"automount-token",
		"image-pull-policy",
	)
	opts := HelmValuesOptions{
		RiskLevel:          RiskLevelModerate,
		CommentOutBreaking: true,
	}

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}

	// Parse the output as YAML to verify it's valid.
	var parsed map[string]any
	if err := yaml.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v\n\nContent:\n%s", err, string(output))
	}

	// Verify some values were parsed correctly.
	sc, ok := parsed["securityContext"].(map[string]any)
	if !ok {
		t.Fatal("parsed output missing 'securityContext' map")
	}
	if priv, ok := sc["privileged"].(bool); !ok || priv {
		t.Error("parsed securityContext.privileged should be false")
	}
	if ape, ok := sc["allowPrivilegeEscalation"].(bool); !ok || ape {
		t.Error("parsed securityContext.allowPrivilegeEscalation should be false")
	}

	// serviceAccount section.
	sa, ok := parsed["serviceAccount"].(map[string]any)
	if !ok {
		t.Fatal("parsed output missing 'serviceAccount' map")
	}
	if amt, ok := sa["automountServiceAccountToken"].(bool); !ok || amt {
		t.Error("parsed serviceAccount.automountServiceAccountToken should be false")
	}

	// image section.
	img, ok := parsed["image"].(map[string]any)
	if !ok {
		t.Fatal("parsed output missing 'image' map")
	}
	if pp, ok := img["pullPolicy"].(string); !ok || pp != "Always" {
		t.Errorf("parsed image.pullPolicy = %v, want 'Always'", pp)
	}
}

func TestGenerateHelmValues_SectionOrder(t *testing.T) {
	plan := helmTestPlan(
		"image-pull-policy",       // image section
		"automount-token",         // serviceAccount section
		"privileged",              // securityContext section
		"resource-limits-missing", // resources section
	)
	opts := HelmValuesOptions{
		RiskLevel:          RiskLevelAggressive,
		CommentOutBreaking: true,
	}

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Verify section order: securityContext → serviceAccount → image → resources.
	scIdx := strings.Index(content, "securityContext:")
	saIdx := strings.Index(content, "serviceAccount:")
	imgIdx := strings.Index(content, "image:")
	// Resources might be commented, so look for both.
	resIdx := strings.Index(content, "resources:")
	if resIdx == -1 {
		resIdx = strings.Index(content, "# resources:")
	}

	if scIdx == -1 || saIdx == -1 || imgIdx == -1 || resIdx == -1 {
		t.Fatalf("missing sections: sc=%d sa=%d img=%d res=%d", scIdx, saIdx, imgIdx, resIdx)
	}

	if scIdx >= saIdx {
		t.Error("securityContext should come before serviceAccount")
	}
	if saIdx >= imgIdx {
		t.Error("serviceAccount should come before image")
	}
	if imgIdx >= resIdx {
		t.Error("image should come before resources")
	}
}

func TestGenerateHelmValues_OnlyAppliedResults(t *testing.T) {
	plan := &Plan{
		Summary: Summary{
			Applied: 1,
			Skipped: 1,
			Results: []Result{
				{CheckID: "privileged", Safety: checker.FixSafe, Applied: true},
				{CheckID: "automount-token", Safety: checker.FixSafe, Applied: false, SkipReason: "system_namespace"},
			},
		},
	}
	opts := DefaultHelmValuesOptions()

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Should include privileged (applied).
	if !strings.Contains(content, "privileged: false") {
		t.Error("output missing applied fix 'privileged: false'")
	}

	// Should NOT include automountServiceAccountToken (not applied).
	if strings.Contains(content, "automountServiceAccountToken") {
		t.Error("output should not include skipped fix 'automountServiceAccountToken'")
	}
}

func TestGenerateHelmValues_UnknownCheckIDIgnored(t *testing.T) {
	plan := helmTestPlan("privileged", "some-unknown-check-id")
	opts := DefaultHelmValuesOptions()

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// Should include the known check.
	if !strings.Contains(content, "privileged: false") {
		t.Error("output missing known check 'privileged: false'")
	}
}

func TestWriteHelmValues(t *testing.T) {
	plan := helmTestPlan("privileged", "automount-token")
	opts := DefaultHelmValuesOptions()

	dir := t.TempDir()
	path := filepath.Join(dir, "security-values.yaml")

	if err := WriteHelmValues(plan, opts, path); err != nil {
		t.Fatalf("WriteHelmValues() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "KubeVigil Security Values") {
		t.Error("written file missing header")
	}
	if !strings.Contains(content, "privileged: false") {
		t.Error("written file missing 'privileged: false'")
	}
	if !strings.Contains(content, "automountServiceAccountToken: false") {
		t.Error("written file missing 'automountServiceAccountToken: false'")
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written file: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("written file permissions = %o, want 0644", info.Mode().Perm())
	}
}

func TestWriteHelmValues_InvalidPath(t *testing.T) {
	plan := helmTestPlan("privileged")
	opts := DefaultHelmValuesOptions()

	err := WriteHelmValues(plan, opts, "/nonexistent/dir/values.yaml")
	if err == nil {
		t.Error("WriteHelmValues() should return error for invalid path")
	}
}

func TestGenerateHelmValues_NilPlan(t *testing.T) {
	opts := DefaultHelmValuesOptions()

	_, err := GenerateHelmValues(nil, opts)
	if err == nil {
		t.Error("GenerateHelmValues(nil) should return error")
	}
}

func TestGenerateHelmValues_DuplicateCheckIDs(t *testing.T) {
	// Simulate a plan where the same check ID appears multiple times
	// (e.g., from multiple containers in the same deployment).
	plan := &Plan{
		Summary: Summary{
			Applied: 2,
			Results: []Result{
				{CheckID: "privileged", Safety: checker.FixSafe, Applied: true, Resource: "app-1"},
				{CheckID: "privileged", Safety: checker.FixSafe, Applied: true, Resource: "app-2"},
			},
		},
	}
	opts := DefaultHelmValuesOptions()

	output, err := GenerateHelmValues(plan, opts)
	if err != nil {
		t.Fatalf("GenerateHelmValues() error = %v", err)
	}
	content := string(output)

	// securityContext should appear exactly once even with duplicate check IDs.
	count := strings.Count(content, "securityContext:")
	if count != 1 {
		t.Errorf("expected 1 'securityContext:' occurrence with duplicates, got %d", count)
	}

	// privileged: false should appear exactly once.
	pvCount := strings.Count(content, "privileged: false")
	if pvCount != 1 {
		t.Errorf("expected 1 'privileged: false' occurrence, got %d", pvCount)
	}
}

func TestDefaultHelmValuesOptions(t *testing.T) {
	opts := DefaultHelmValuesOptions()

	if opts.RiskLevel != RiskLevelSafe {
		t.Errorf("DefaultHelmValuesOptions().RiskLevel = %q, want %q", opts.RiskLevel, RiskLevelSafe)
	}
	if !opts.CommentOutBreaking {
		t.Error("DefaultHelmValuesOptions().CommentOutBreaking should be true")
	}
}

func TestSectionDisplayName(t *testing.T) {
	tests := []struct {
		section string
		want    string
	}{
		{"securityContext", "Security Context"},
		{"serviceAccount", "Service Account"},
		{"image", "Image"},
		{"resources", "Resources"},
		{"unknownSection", "unknownSection"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			got := sectionDisplayName(tt.section)
			if got != tt.want {
				t.Errorf("sectionDisplayName(%q) = %q, want %q", tt.section, got, tt.want)
			}
		})
	}
}

func TestSectionIndex(t *testing.T) {
	testCases := []struct {
		name    string
		section string
		want    int
	}{
		{name: "securityContext", section: "securityContext", want: 0},
		{name: "serviceAccount", section: "serviceAccount", want: 1},
		{name: "image", section: "image", want: 2},
		{name: "resources", section: "resources", want: 3},
		{name: "unknown section returns len(sectionOrder)", section: "unknownSection", want: len(sectionOrder)},
		{name: "empty string returns len(sectionOrder)", section: "", want: len(sectionOrder)},
		{name: "custom section returns len(sectionOrder)", section: "custom", want: len(sectionOrder)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := sectionIndex(tc.section)
			if got != tc.want {
				t.Errorf("sectionIndex(%q) = %d, want %d", tc.section, got, tc.want)
			}
		})
	}
}

func TestWriteSectionComment(t *testing.T) {
	testCases := []struct {
		name    string
		section string
		want    string
	}{
		{name: "securityContext", section: "securityContext", want: "# Security Context\n"},
		{name: "serviceAccount", section: "serviceAccount", want: "# Service Account\n"},
		{name: "image", section: "image", want: "# Image\n"},
		{name: "resources", section: "resources", want: "# Resources\n"},
		{name: "unknown section uses raw name", section: "customSection", want: "# customSection\n"},
		{name: "empty section", section: "", want: "# \n"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			writeSectionComment(&b, tc.section)
			got := b.String()
			if got != tc.want {
				t.Errorf("writeSectionComment(%q) = %q, want %q", tc.section, got, tc.want)
			}
		})
	}
}

func TestWriteHelmValues_EmptyFixPlan(t *testing.T) {
	plan := &Plan{
		Summary: Summary{
			Applied: 0,
			Results: nil,
		},
	}
	opts := DefaultHelmValuesOptions()

	dir := t.TempDir()
	path := filepath.Join(dir, "security-values.yaml")

	if err := WriteHelmValues(plan, opts, path); err != nil {
		t.Fatalf("WriteHelmValues() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}

	content := string(data)
	// Header should be present.
	if !strings.Contains(content, "KubeVigil Security Values") {
		t.Error("empty plan written file missing header")
	}
	// No value sections should be present.
	if strings.Contains(content, "securityContext:") {
		t.Error("empty plan written file should not contain securityContext")
	}
}

func TestWriteHelmValues_SingleFix(t *testing.T) {
	plan := helmTestPlan("privileged")
	opts := DefaultHelmValuesOptions()

	dir := t.TempDir()
	path := filepath.Join(dir, "security-values.yaml")

	if err := WriteHelmValues(plan, opts, path); err != nil {
		t.Fatalf("WriteHelmValues() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "securityContext:") {
		t.Error("written file missing securityContext section")
	}
	if !strings.Contains(content, "privileged: false") {
		t.Error("written file missing 'privileged: false'")
	}
}

func TestWriteHelmValues_MultipleSections(t *testing.T) {
	plan := helmTestPlan("privileged", "automount-token", "image-pull-policy", "resource-limits-missing")
	opts := HelmValuesOptions{
		RiskLevel:          RiskLevelAggressive,
		CommentOutBreaking: false,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "security-values.yaml")

	if err := WriteHelmValues(plan, opts, path); err != nil {
		t.Fatalf("WriteHelmValues() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}

	content := string(data)
	// All four sections should be present (uncommented because CommentOutBreaking=false).
	for _, section := range []string{"securityContext:", "serviceAccount:", "image:", "resources:"} {
		if !strings.Contains(content, section) {
			t.Errorf("written file missing section %q", section)
		}
	}

	// Verify valid YAML.
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("written file is not valid YAML: %v", err)
	}
}
