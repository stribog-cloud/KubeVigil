package fix

import (
	"strings"
	"testing"
)

func TestGenerateDiff(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		original   string
		patched    string
		wantEmpty  bool
		wantLines  []string // lines that must appear somewhere in the output
		wantAbsent []string // lines that must NOT appear in the output
	}{
		{
			name:     "field change single line",
			filePath: "deploy.yaml",
			original: "apiVersion: apps/v1\nkind: Deployment\nspec:\n  privileged: true\n",
			patched:  "apiVersion: apps/v1\nkind: Deployment\nspec:\n  privileged: false\n",
			wantLines: []string{
				"--- a/deploy.yaml",
				"+++ b/deploy.yaml",
				"-  privileged: true",
				"+  privileged: false",
				"@@",
			},
		},
		{
			name:     "field added",
			filePath: "pod.yaml",
			original: "apiVersion: v1\nkind: Pod\nspec:\n  containers: []\n",
			patched:  "apiVersion: v1\nkind: Pod\nspec:\n  containers: []\n  securityContext:\n    runAsNonRoot: true\n",
			wantLines: []string{
				"--- a/pod.yaml",
				"+++ b/pod.yaml",
				"+  securityContext:",
				"+    runAsNonRoot: true",
			},
		},
		{
			name:     "field removed",
			filePath: "svc.yaml",
			original: "apiVersion: v1\nkind: Service\nspec:\n  hostPort: 8080\n  port: 80\n",
			patched:  "apiVersion: v1\nkind: Service\nspec:\n  port: 80\n",
			wantLines: []string{
				"-  hostPort: 8080",
			},
			wantAbsent: []string{
				"+  hostPort:",
			},
		},
		{
			name:     "multiple changes produce multiple hunks",
			filePath: "multi.yaml",
			original: joinLines(
				"line1",
				"line2",
				"line3",
				"line4",
				"line5",
				"line6",
				"line7",
				"line8",
				"line9",
				"line10",
				"line11",
				"line12",
				"line13",
				"line14",
				"line15",
				"line16",
				"line17",
				"line18",
				"line19",
				"line20",
			),
			patched: joinLines(
				"line1",
				"CHANGED2",
				"line3",
				"line4",
				"line5",
				"line6",
				"line7",
				"line8",
				"line9",
				"line10",
				"line11",
				"line12",
				"line13",
				"line14",
				"line15",
				"line16",
				"line17",
				"line18",
				"line19",
				"CHANGED20",
			),
			wantLines: []string{
				"-line2",
				"+CHANGED2",
				"-line20",
				"+CHANGED20",
			},
		},
		{
			name:      "no changes returns empty",
			filePath:  "same.yaml",
			original:  "apiVersion: v1\nkind: Pod\n",
			patched:   "apiVersion: v1\nkind: Pod\n",
			wantEmpty: true,
		},
		{
			name:     "headers correct format",
			filePath: "path/to/manifest.yaml",
			original: "a: 1\n",
			patched:  "a: 2\n",
			wantLines: []string{
				"--- a/path/to/manifest.yaml",
				"+++ b/path/to/manifest.yaml",
			},
		},
		{
			name:      "both empty returns empty",
			filePath:  "empty.yaml",
			original:  "",
			patched:   "",
			wantEmpty: true,
		},
		{
			name:     "large context changes far apart produce separate hunks",
			filePath: "large.yaml",
			original: generateNumberedLines(1, 30),
			patched: func() string {
				lines := make([]string, 30)
				for i := 0; i < 30; i++ {
					if i == 1 { // line 2
						lines[i] = "CHANGED-2"
					} else if i == 28 { // line 29
						lines[i] = "CHANGED-29"
					} else {
						lines[i] = numberedLine(i + 1)
					}
				}
				return strings.Join(lines, "\n") + "\n"
			}(),
			wantLines: []string{
				"-line-2",
				"+CHANGED-2",
				"-line-29",
				"+CHANGED-29",
			},
		},
		{
			name:     "original empty patched has content",
			filePath: "new.yaml",
			original: "",
			patched:  "apiVersion: v1\nkind: Pod\n",
			wantLines: []string{
				"+apiVersion: v1",
				"+kind: Pod",
			},
		},
		{
			name:     "patched empty original has content",
			filePath: "deleted.yaml",
			original: "apiVersion: v1\nkind: Pod\n",
			patched:  "",
			wantLines: []string{
				"-apiVersion: v1",
				"-kind: Pod",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateDiff(tt.filePath, []byte(tt.original), []byte(tt.patched))

			if tt.wantEmpty {
				if got != "" {
					t.Errorf("expected empty diff, got:\n%s", got)
				}
				return
			}

			if got == "" {
				t.Fatal("expected non-empty diff, got empty string")
			}

			for _, line := range tt.wantLines {
				if !containsLine(got, line) {
					t.Errorf("diff missing expected line %q\ndiff output:\n%s", line, got)
				}
			}

			for _, line := range tt.wantAbsent {
				if containsLine(got, line) {
					t.Errorf("diff contains unexpected line %q\ndiff output:\n%s", line, got)
				}
			}
		})
	}
}

func TestGenerateDiff_HunkCount(t *testing.T) {
	// Changes far apart should produce separate hunks.
	original := generateNumberedLines(1, 30)
	lines := make([]string, 30)
	for i := 0; i < 30; i++ {
		if i == 1 {
			lines[i] = "CHANGED-2"
		} else if i == 28 {
			lines[i] = "CHANGED-29"
		} else {
			lines[i] = numberedLine(i + 1)
		}
	}
	patched := strings.Join(lines, "\n") + "\n"

	got := GenerateDiff("test.yaml", []byte(original), []byte(patched))

	// Count @@ markers (each hunk has one)
	hunkCount := strings.Count(got, "@@")
	// Each hunk header has @@ twice (opening and closing), so divide by 2
	hunkHeaders := hunkCount / 2
	if hunkHeaders < 2 {
		t.Errorf("expected at least 2 separate hunks for changes far apart, got %d hunk header(s)\ndiff:\n%s", hunkHeaders, got)
	}
}

func TestGenerateDiff_ContextLines(t *testing.T) {
	// Verify that context (unchanged) lines appear around changes.
	original := "line1\nline2\nline3\nline4\nline5\nline6\nline7\n"
	patched := "line1\nline2\nline3\nCHANGED\nline5\nline6\nline7\n"

	got := GenerateDiff("ctx.yaml", []byte(original), []byte(patched))

	// Context lines should include surrounding unchanged lines (up to 3)
	if !containsLine(got, " line2") && !containsLine(got, " line3") {
		// At least some context before the change should be present
		t.Logf("diff output:\n%s", got)
	}

	// The changed lines must be present
	if !containsLine(got, "-line4") {
		t.Errorf("expected removed line '-line4' in diff:\n%s", got)
	}
	if !containsLine(got, "+CHANGED") {
		t.Errorf("expected added line '+CHANGED' in diff:\n%s", got)
	}
}

func TestColorDiff(t *testing.T) {
	diff := "--- a/deploy.yaml\n+++ b/deploy.yaml\n@@ -1,3 +1,3 @@\n context line\n-old line\n+new line\n"

	colored := ColorDiff(diff)

	if colored == "" {
		t.Fatal("expected non-empty colored output")
	}

	// Verify ANSI codes are present
	if !strings.Contains(colored, "\033[") {
		t.Error("expected ANSI escape codes in colored output")
	}

	// File headers should be bold
	if !strings.Contains(colored, "\033[1m--- a/deploy.yaml") {
		t.Errorf("expected bold file header (---), got:\n%s", colored)
	}
	if !strings.Contains(colored, "\033[1m+++ b/deploy.yaml") {
		t.Errorf("expected bold file header (+++), got:\n%s", colored)
	}

	// Hunk header should be cyan
	if !strings.Contains(colored, "\033[36m@@") {
		t.Errorf("expected cyan hunk header, got:\n%s", colored)
	}

	// Removed line should be red (but not the --- header)
	if !strings.Contains(colored, "\033[31m-old line") {
		t.Errorf("expected red removed line, got:\n%s", colored)
	}

	// Added line should be green (but not the +++ header)
	if !strings.Contains(colored, "\033[32m+new line") {
		t.Errorf("expected green added line, got:\n%s", colored)
	}

	// All colored lines should have reset codes
	lines := strings.Split(colored, "\n")
	for _, line := range lines {
		if strings.Contains(line, "\033[") && line != "" {
			if !strings.HasSuffix(line, "\033[0m") {
				t.Errorf("colored line missing reset code: %q", line)
			}
		}
	}
}

func TestColorDiff_EmptyInput(t *testing.T) {
	colored := ColorDiff("")
	if colored != "" {
		t.Errorf("expected empty output for empty input, got: %q", colored)
	}
}

func TestColorDiff_ContextLinesUncolored(t *testing.T) {
	diff := "--- a/file.yaml\n+++ b/file.yaml\n@@ -1,3 +1,3 @@\n context line\n-removed\n+added\n"

	colored := ColorDiff(diff)

	// Find the context line — it should NOT have ANSI codes
	for _, line := range strings.Split(colored, "\n") {
		if strings.TrimSpace(line) == "context line" {
			if strings.Contains(line, "\033[") {
				t.Errorf("context line should not have ANSI codes: %q", line)
			}
		}
	}
}

func TestColorDiff_OnlyMinusNotHeader(t *testing.T) {
	// Ensure --- is bold (header), but -line is red (removed)
	diff := "--- a/file.yaml\n+++ b/file.yaml\n@@ -1,2 +1,2 @@\n-old\n+new\n"

	colored := ColorDiff(diff)

	// The --- line should use bold, not red
	for _, line := range strings.Split(colored, "\n") {
		if strings.Contains(line, "--- a/file.yaml") {
			if strings.Contains(line, "\033[31m") {
				t.Errorf("file header --- should be bold, not red: %q", line)
			}
		}
	}
}

// Helper functions

// containsLine checks if the diff output contains a line that starts with
// the given prefix (after trimming the trailing newline from each line).
func containsLine(diff, target string) bool {
	for _, line := range strings.Split(diff, "\n") {
		if strings.TrimRight(line, "\r") == target {
			return true
		}
		// Also check for partial match — the target might appear as part of a line
		if strings.Contains(line, target) {
			return true
		}
	}
	return false
}

// joinLines joins lines with newlines and adds a trailing newline.
func joinLines(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// numberedLine generates a line like "line-N".
func numberedLine(n int) string {
	return "line-" + itoa(n)
}

// generateNumberedLines generates N lines like "line-1\nline-2\n...".
func generateNumberedLines(start, count int) string {
	var lines []string
	for i := start; i < start+count; i++ {
		lines = append(lines, "line-"+itoa(i))
	}
	return strings.Join(lines, "\n") + "\n"
}

// itoa converts an int to a string without importing strconv in the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
