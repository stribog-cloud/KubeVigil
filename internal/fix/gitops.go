package fix

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// GitPRConfig holds configuration for creating a Git branch and pull request.
type GitPRConfig struct {
	// BranchName is the name of the branch to create.
	BranchName string
	// CommitMessage is the commit message for the fix changes.
	CommitMessage string
	// PRTitle is the title of the pull request.
	PRTitle string
	// PRBody is the body/description of the pull request.
	PRBody string
	// BaseBranch is the base branch for the PR (empty = repo default).
	BaseBranch string
	// WorkDir is the git repository working directory.
	WorkDir string
	// ModifiedFiles is the list of files to stage and commit.
	ModifiedFiles []string
}

// CreateGitOpsPR creates a branch, commits modified files, pushes, and opens a PR.
// Returns the PR URL on success.
func CreateGitOpsPR(cfg *GitPRConfig) (string, error) {
	cli, err := detectGitCLI()
	if err != nil {
		return "", fmt.Errorf("detecting git CLI: %w\nInstall gh (https://cli.github.com/) or glab (https://gitlab.com/gitlab-org/cli)", err)
	}

	// Create and checkout branch.
	if _, err := runGitCommand(cfg.WorkDir, "git", "checkout", "-b", cfg.BranchName); err != nil {
		return "", fmt.Errorf("creating branch %s: %w", cfg.BranchName, err)
	}

	// Stage modified files.
	for _, f := range cfg.ModifiedFiles {
		if _, err := runGitCommand(cfg.WorkDir, "git", "add", f); err != nil {
			return "", fmt.Errorf("staging %s: %w", f, err)
		}
	}

	// Commit.
	if _, err := runGitCommand(cfg.WorkDir, "git", "commit", "-m", cfg.CommitMessage); err != nil {
		return "", fmt.Errorf("committing: %w", err)
	}

	// Push.
	if _, err := runGitCommand(cfg.WorkDir, "git", "push", "-u", "origin", cfg.BranchName); err != nil {
		return "", fmt.Errorf("pushing branch %s: %w\nYou can push manually: git push -u origin %s", cfg.BranchName, err, cfg.BranchName)
	}

	// Create PR.
	var prURL string
	switch cli {
	case "gh":
		args := []string{"pr", "create", "--title", cfg.PRTitle, "--body", cfg.PRBody}
		if cfg.BaseBranch != "" {
			args = append(args, "--base", cfg.BaseBranch)
		}
		output, prErr := runGitCommand(cfg.WorkDir, "gh", args...)
		if prErr != nil {
			return "", fmt.Errorf("creating PR with gh: %w\nYou can create the PR manually at the repository URL", prErr)
		}
		prURL = strings.TrimSpace(output)

	case "glab":
		args := []string{"mr", "create", "--title", cfg.PRTitle, "--description", cfg.PRBody}
		if cfg.BaseBranch != "" {
			args = append(args, "--target-branch", cfg.BaseBranch)
		}
		output, prErr := runGitCommand(cfg.WorkDir, "glab", args...)
		if prErr != nil {
			return "", fmt.Errorf("creating MR with glab: %w\nYou can create the MR manually at the repository URL", prErr)
		}
		prURL = strings.TrimSpace(output)
	}

	return prURL, nil
}

// detectGitCLI checks for available git PR CLI tools.
// Returns "gh" for GitHub CLI, "glab" for GitLab CLI, or an error if neither is found.
func detectGitCLI() (string, error) {
	if _, err := exec.LookPath("gh"); err == nil {
		return "gh", nil
	}
	if _, err := exec.LookPath("glab"); err == nil {
		return "glab", nil
	}
	return "", fmt.Errorf("neither 'gh' (GitHub CLI) nor 'glab' (GitLab CLI) found in PATH")
}

// checkGitClean returns true if the git working tree has no uncommitted changes.
func checkGitClean(workDir string) (bool, error) {
	output, err := runGitCommand(workDir, "git", "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("checking git status: %w", err)
	}
	return strings.TrimSpace(output) == "", nil
}

// DefaultGitPRConfig creates a GitPRConfig with sensible defaults from a fix plan
// and optional report content.
func DefaultGitPRConfig(plan *Plan, reportContent []byte) GitPRConfig {
	timestamp := time.Now().Format("20060102-150405")
	branchName := fmt.Sprintf("kubevigil/fix-%s", timestamp)

	// Collect modified file paths (sorted).
	var files []string
	for path := range plan.Files {
		files = append(files, path)
	}
	sort.Strings(files)

	commitMsg := fmt.Sprintf("fix: apply %d KubeVigil security fixes across %d files",
		plan.Summary.Applied, plan.Summary.FilesModified)

	prTitle := fmt.Sprintf("fix: KubeVigil security hardening (%d fixes)", plan.Summary.Applied)

	var body strings.Builder
	fmt.Fprintf(&body, "## KubeVigil Security Fixes\n\n")
	fmt.Fprintf(&body, "This PR applies %d automated security fixes across %d files.\n\n",
		plan.Summary.Applied, plan.Summary.FilesModified)

	if len(reportContent) > 0 {
		fmt.Fprintf(&body, "<details>\n<summary>Fix Report</summary>\n\n")
		body.Write(reportContent)
		fmt.Fprintf(&body, "\n</details>\n")
	}

	return GitPRConfig{
		BranchName:    branchName,
		CommitMessage: commitMsg,
		PRTitle:       prTitle,
		PRBody:        body.String(),
		ModifiedFiles: files,
	}
}

// runGitCommand executes a command in the given directory and returns its output.
func runGitCommand(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output), nil
}
