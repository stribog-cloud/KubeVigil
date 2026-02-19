package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectGitCLI_LookPath(t *testing.T) {
	// detectGitCLI should find at least one of gh/glab if available,
	// or return an error if neither is installed.
	cli, err := detectGitCLI()
	if err != nil {
		// This is fine in CI where gh/glab may not be installed.
		t.Skipf("no git CLI found: %v", err)
	}
	if cli != "gh" && cli != "glab" {
		t.Errorf("detectGitCLI() = %q, want 'gh' or 'glab'", cli)
	}
}

func TestCheckGitClean(t *testing.T) {
	// Create a temporary git repo.
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	// Create and commit a file.
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "file.txt")
	runGit(t, dir, "commit", "-m", "init")

	// Clean state.
	clean, err := checkGitClean(dir)
	if err != nil {
		t.Fatalf("checkGitClean() error = %v", err)
	}
	if !clean {
		t.Error("expected clean git state")
	}

	// Dirty state.
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	clean, err = checkGitClean(dir)
	if err != nil {
		t.Fatalf("checkGitClean() error = %v", err)
	}
	if clean {
		t.Error("expected dirty git state")
	}
}

func TestDefaultGitPRConfig(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml":  {Path: "/app/deploy.yaml"},
			"/app/service.yaml": {Path: "/app/service.yaml"},
		},
		Summary: Summary{
			Applied:       5,
			FilesModified: 2,
		},
	}
	reportContent := []byte("# Fix Report\nSome content")

	cfg := DefaultGitPRConfig(plan, reportContent)

	if cfg.BranchName == "" {
		t.Error("BranchName should not be empty")
	}
	if cfg.CommitMessage == "" {
		t.Error("CommitMessage should not be empty")
	}
	if cfg.PRTitle == "" {
		t.Error("PRTitle should not be empty")
	}
	if cfg.PRBody == "" {
		t.Error("PRBody should not be empty")
	}
	if len(cfg.ModifiedFiles) != 2 {
		t.Errorf("ModifiedFiles length = %d, want 2", len(cfg.ModifiedFiles))
	}
}

func TestRunGitCommand(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")

	output, err := runGitCommand(dir, "git", "status", "--porcelain")
	if err != nil {
		t.Fatalf("runGitCommand() error = %v", err)
	}
	// Empty output for empty repo is fine.
	_ = output
}

func TestRunGitCommand_Error(t *testing.T) {
	_, err := runGitCommand("/nonexistent", "git", "status")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestDefaultGitPRConfig_BranchNameFormat(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {Path: "/app/deploy.yaml"},
		},
		Summary: Summary{Applied: 1, FilesModified: 1},
	}

	cfg := DefaultGitPRConfig(plan, nil)

	// Branch name should start with kubevigil/fix-.
	if len(cfg.BranchName) < len("kubevigil/fix-") {
		t.Errorf("BranchName too short: %q", cfg.BranchName)
	}
	if cfg.BranchName[:14] != "kubevigil/fix-" {
		t.Errorf("BranchName should start with 'kubevigil/fix-', got %q", cfg.BranchName)
	}
}

func TestDefaultGitPRConfig_PRBodyContainsReport(t *testing.T) {
	plan := &Plan{
		Files:   map[string]*FilePlan{"/a.yaml": {Path: "/a.yaml"}},
		Summary: Summary{Applied: 1, FilesModified: 1},
	}
	report := []byte("## Summary\n\nFixed 1 finding")

	cfg := DefaultGitPRConfig(plan, report)

	if cfg.PRBody == "" {
		t.Fatal("PRBody should not be empty")
	}
	// PR body should contain the report content.
	if len(report) > 0 && !containsAny(cfg.PRBody, "Summary", "Fixed") {
		t.Error("PRBody should reference the report content")
	}
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) > 0 && len(sub) > 0 {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// runGit is a test helper that runs a git command and fails on error.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_COMMITTER_NAME=test",
		"GIT_AUTHOR_EMAIL=test@test.com", "GIT_COMMITTER_EMAIL=test@test.com")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}

func TestCreateGitOpsPR_FailsOnPush(t *testing.T) {
	// Create a temporary git repo with an initial commit.
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	// Create and commit an initial file.
	initialFile := filepath.Join(dir, "initial.yaml")
	require.NoError(t, os.WriteFile(initialFile, []byte("apiVersion: v1\nkind: Pod\n"), 0o644))
	runGit(t, dir, "add", "initial.yaml")
	runGit(t, dir, "commit", "-m", "initial commit")

	// Create a modified file to stage.
	modifiedFile := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(modifiedFile, []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o644))

	cfg := GitPRConfig{
		BranchName:    "kubevigil/test-fix",
		CommitMessage: "fix: test security fixes",
		PRTitle:       "fix: test",
		PRBody:        "Test PR body",
		WorkDir:       dir,
		ModifiedFiles: []string{"deploy.yaml"},
	}

	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	// Should fail at the push step since there is no remote configured.
	assert.True(t, strings.Contains(err.Error(), "pushing branch") || strings.Contains(err.Error(), "push"),
		"error should be about pushing, got: %v", err)
}

func TestCreateGitOpsPR_NoGitCLI(t *testing.T) {
	// Temporarily override PATH to exclude gh and glab.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir()) // empty dir with no executables

	_, err := detectGitCLI()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither")

	// Restore PATH for the full CreateGitOpsPR test.
	t.Setenv("PATH", origPath)
}

// --- Additional gitops edge case tests ---

func TestCreateGitOpsPR_NoGitCLIAvailable(t *testing.T) {
	// Override PATH so neither gh nor glab is found.
	t.Setenv("PATH", t.TempDir())

	cfg := GitPRConfig{
		BranchName:    "kubevigil/test-fix",
		CommitMessage: "fix: test",
		PRTitle:       "fix: test",
		PRBody:        "Test body",
		WorkDir:       t.TempDir(),
		ModifiedFiles: []string{"deploy.yaml"},
	}

	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detecting git CLI")
	// Should also have the install hint.
	assert.Contains(t, err.Error(), "Install gh")
}

func TestCheckGitClean_NotAGitRepo(t *testing.T) {
	// A directory that is not a git repo should return an error.
	dir := t.TempDir()
	_, err := checkGitClean(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checking git status")
}

func TestCheckGitClean_UntrackedFile(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	// Create and commit an initial file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "initial.txt"), []byte("init"), 0o644))
	runGit(t, dir, "add", "initial.txt")
	runGit(t, dir, "commit", "-m", "initial")

	// Add an untracked file — repo should be dirty.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("new"), 0o644))

	clean, err := checkGitClean(dir)
	require.NoError(t, err)
	assert.False(t, clean, "untracked files should make the repo dirty")
}

func TestCreateGitOpsPR_BranchCreationFails(t *testing.T) {
	// Skip if gh is not available (detectGitCLI needs to succeed first).
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}

	// Use a directory that is NOT a git repo — branch creation will fail.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte("kind: Deployment"), 0o644))

	cfg := GitPRConfig{
		BranchName:    "kubevigil/test-fix",
		CommitMessage: "fix: test",
		PRTitle:       "fix: test",
		PRBody:        "Test body",
		WorkDir:       dir,
		ModifiedFiles: []string{"deploy.yaml"},
	}

	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating branch")
}

func TestDefaultGitPRConfig_EmptyPlan(t *testing.T) {
	plan := &Plan{
		Files:   map[string]*FilePlan{},
		Summary: Summary{Applied: 0, FilesModified: 0},
	}

	cfg := DefaultGitPRConfig(plan, nil)

	assert.NotEmpty(t, cfg.BranchName)
	assert.Contains(t, cfg.CommitMessage, "0 KubeVigil security fixes")
	assert.Contains(t, cfg.PRTitle, "0 fixes")
	assert.NotEmpty(t, cfg.PRBody)
	assert.Len(t, cfg.ModifiedFiles, 0)
}

func TestDefaultGitPRConfig_NilReport(t *testing.T) {
	plan := &Plan{
		Files:   map[string]*FilePlan{"/a.yaml": {Path: "/a.yaml"}},
		Summary: Summary{Applied: 3, FilesModified: 1},
	}

	cfg := DefaultGitPRConfig(plan, nil)

	// PR body should NOT contain <details> tag since there's no report.
	assert.NotContains(t, cfg.PRBody, "<details>")
	assert.Contains(t, cfg.PRBody, "3 automated security fixes")
}

func TestDefaultGitPRConfig_WithReport(t *testing.T) {
	plan := &Plan{
		Files:   map[string]*FilePlan{"/a.yaml": {Path: "/a.yaml"}},
		Summary: Summary{Applied: 1, FilesModified: 1},
	}
	report := []byte("## Fix Report\n\nFixed 1 finding")

	cfg := DefaultGitPRConfig(plan, report)

	// PR body should include the report in a details section.
	assert.Contains(t, cfg.PRBody, "<details>")
	assert.Contains(t, cfg.PRBody, "Fix Report")
	assert.Contains(t, cfg.PRBody, "</details>")
}

func TestRunGitCommand_Success(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")

	output, err := runGitCommand(dir, "git", "rev-parse", "--git-dir")
	require.NoError(t, err)
	assert.Contains(t, strings.TrimSpace(output), ".git")
}

func TestRunGitCommand_BadCommand(t *testing.T) {
	_, err := runGitCommand(t.TempDir(), "nonexistent-command-xyz")
	require.Error(t, err)
}
