package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateGitOpsPR_StagingFails(t *testing.T) {
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "initial.yaml"), []byte("apiVersion: v1"), 0o644))
	runGit(t, dir, "add", "initial.yaml")
	runGit(t, dir, "commit", "-m", "initial commit")
	cfg := GitPRConfig{BranchName: "kubevigil/staging-fail", CommitMessage: "fix: test", PRTitle: "fix: test", PRBody: "body", WorkDir: dir, ModifiedFiles: []string{"nonexistent-file.yaml"}}
	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "staging")
}

func TestCreateGitOpsPR_CommitFails(t *testing.T) {
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "initial.yaml"), []byte("apiVersion: v1"), 0o644))
	runGit(t, dir, "add", "initial.yaml")
	runGit(t, dir, "commit", "-m", "initial commit")
	cfg := GitPRConfig{BranchName: "kubevigil/commit-fail", CommitMessage: "fix: empty", PRTitle: "fix: test", PRBody: "body", WorkDir: dir, ModifiedFiles: []string{"initial.yaml"}}
	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committing")
}

func TestCreateGitOpsPR_FullFlowFailsAtPush(t *testing.T) {
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "initial.yaml"), []byte("apiVersion: v1\nkind: Pod\n"), 0o644))
	runGit(t, dir, "add", "initial.yaml")
	runGit(t, dir, "commit", "-m", "initial commit")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "new-deploy.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o644))
	cfg := GitPRConfig{BranchName: "kubevigil/full-flow-test", CommitMessage: "fix: apply", PRTitle: "fix: hardening", PRBody: "Automated", WorkDir: dir, ModifiedFiles: []string{"new-deploy.yaml"}}
	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pushing branch")
}

func TestCreateGitOpsPR_MultipleFilesFailsAtPush(t *testing.T) {
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "initial.yaml"), []byte("init"), 0o644))
	runGit(t, dir, "add", "initial.yaml")
	runGit(t, dir, "commit", "-m", "initial commit")
	for _, name := range []string{"a.yaml", "b.yaml", "c.yaml"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("content: "+name), 0o644))
	}
	cfg := GitPRConfig{BranchName: "kubevigil/multi-file", CommitMessage: "fix: 3 fixes", PRTitle: "fix: multi", PRBody: "Three", BaseBranch: "main", WorkDir: dir, ModifiedFiles: []string{"a.yaml", "b.yaml", "c.yaml"}}
	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pushing branch")
}

func TestCreateGitOpsPR_SucceedsThroughPushFailsAtPRCreation(t *testing.T) {
	// This test exercises the code path AFTER successful push (the PR creation
	// switch for gh/glab), which was the main uncovered portion of CreateGitOpsPR.
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}

	// Set up a local bare remote so push succeeds.
	bareDir := t.TempDir()
	runGit(t, bareDir, "init", "--bare")

	workDir := t.TempDir()
	runGit(t, workDir, "init")
	runGit(t, workDir, "config", "user.email", "test@test.com")
	runGit(t, workDir, "config", "user.name", "Test")
	runGit(t, workDir, "remote", "add", "origin", bareDir)

	// Create and push initial commit.
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "init.yaml"), []byte("init"), 0o644))
	runGit(t, workDir, "add", "init.yaml")
	runGit(t, workDir, "commit", "-m", "initial")
	runGit(t, workDir, "push", "-u", "origin", "HEAD")

	// Create a new file to be fixed.
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "deploy.yaml"),
		[]byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o644))

	cfg := GitPRConfig{
		BranchName:    "kubevigil/test-pr-creation",
		CommitMessage: "fix: test security fixes",
		PRTitle:       "fix: test PR",
		PRBody:        "Test PR body",
		BaseBranch:    "main",
		WorkDir:       workDir,
		ModifiedFiles: []string{"deploy.yaml"},
	}

	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	// Should have gotten past push and failed at gh pr create / glab mr create.
	// The error should mention PR/MR creation, not pushing.
	errMsg := err.Error()
	assert.True(t,
		assert.ObjectsAreEqual(true, containsAny(errMsg, "creating PR", "creating MR")),
		"error should be about PR/MR creation, got: %v", err)
}

func TestCreateGitOpsPR_WithBaseBranch(t *testing.T) {
	// Verify that BaseBranch is correctly passed through to the CLI args.
	// We can't test the actual args passed, but we can verify the flow
	// reaches the PR creation step with BaseBranch set.
	if _, err := exec.LookPath("gh"); err != nil {
		if _, err := exec.LookPath("glab"); err != nil {
			t.Skip("neither gh nor glab available")
		}
	}

	bareDir := t.TempDir()
	runGit(t, bareDir, "init", "--bare")

	workDir := t.TempDir()
	runGit(t, workDir, "init")
	runGit(t, workDir, "config", "user.email", "test@test.com")
	runGit(t, workDir, "config", "user.name", "Test")
	runGit(t, workDir, "remote", "add", "origin", bareDir)

	require.NoError(t, os.WriteFile(filepath.Join(workDir, "init.yaml"), []byte("init"), 0o644))
	runGit(t, workDir, "add", "init.yaml")
	runGit(t, workDir, "commit", "-m", "initial")
	runGit(t, workDir, "push", "-u", "origin", "HEAD")

	require.NoError(t, os.WriteFile(filepath.Join(workDir, "svc.yaml"),
		[]byte("apiVersion: v1\nkind: Service\n"), 0o644))

	cfg := GitPRConfig{
		BranchName:    "kubevigil/test-base-branch",
		CommitMessage: "fix: test with base branch",
		PRTitle:       "fix: test",
		PRBody:        "Test body",
		BaseBranch:    "develop",
		WorkDir:       workDir,
		ModifiedFiles: []string{"svc.yaml"},
	}

	_, err := CreateGitOpsPR(&cfg)
	require.Error(t, err)
	// Error should be about PR creation, not about push.
	assert.True(t,
		containsAny(err.Error(), "creating PR", "creating MR"),
		"error should be about PR/MR creation, got: %v", err)
}

func TestDefaultGitPRConfig_FilesSorted(t *testing.T) {
	plan := &Plan{
		Files:   map[string]*FilePlan{"/z/z.yaml": {Path: "/z/z.yaml"}, "/a/a.yaml": {Path: "/a/a.yaml"}, "/m/m.yaml": {Path: "/m/m.yaml"}},
		Summary: Summary{Applied: 3, FilesModified: 3},
	}
	cfg := DefaultGitPRConfig(plan, nil)
	require.Len(t, cfg.ModifiedFiles, 3)
	assert.Equal(t, "/a/a.yaml", cfg.ModifiedFiles[0])
	assert.Equal(t, "/m/m.yaml", cfg.ModifiedFiles[1])
	assert.Equal(t, "/z/z.yaml", cfg.ModifiedFiles[2])
}
