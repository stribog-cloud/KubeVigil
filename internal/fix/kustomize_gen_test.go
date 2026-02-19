package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// kustomizeTestPlan returns a test Plan with a single Deployment resource.
func kustomizeTestPlan() *Plan {
	return &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {
				Path: "/app/deploy.yaml",
				Fixes: []PlannedFix{
					{
						Finding: checker.Finding{
							Checker:   "privileged",
							Resource:  "web-app",
							Namespace: "default",
							Kind:      "Deployment",
							Container: "web",
						},
						Strategy: Strategy{
							CheckID:      "privileged",
							Safety:       checker.FixSafe,
							Operation:    checker.FixOpSet,
							FieldPath:    "spec.containers[*].securityContext.privileged",
							DesiredValue: false,
							Description:  "Disables privileged mode.",
						},
						Applied: true,
					},
				},
			},
		},
		Summary: Summary{
			Applied: 1,
			Results: []Result{
				{
					FilePath:    "/app/deploy.yaml",
					Resource:    "web-app",
					Namespace:   "default",
					Kind:        "Deployment",
					CheckID:     "privileged",
					Safety:      checker.FixSafe,
					Description: "Disables privileged mode.",
					Applied:     true,
				},
			},
		},
	}
}

// kustomizeMultiResourcePlan returns a Plan with two different resources.
func kustomizeMultiResourcePlan() *Plan {
	return &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {
				Path: "/app/deploy.yaml",
				Fixes: []PlannedFix{
					{
						Finding: checker.Finding{
							Checker:   "privileged",
							Resource:  "web-app",
							Namespace: "default",
							Kind:      "Deployment",
							Container: "web",
						},
						Strategy: Strategy{
							CheckID:      "privileged",
							Safety:       checker.FixSafe,
							Operation:    checker.FixOpSet,
							FieldPath:    "spec.containers[*].securityContext.privileged",
							DesiredValue: false,
							Description:  "Disables privileged mode.",
						},
						Applied: true,
					},
				},
			},
			"/app/sts.yaml": {
				Path: "/app/sts.yaml",
				Fixes: []PlannedFix{
					{
						Finding: checker.Finding{
							Checker:   "host-pid",
							Resource:  "db",
							Namespace: "data",
							Kind:      "StatefulSet",
							Container: "",
						},
						Strategy: Strategy{
							CheckID:      "host-pid",
							Safety:       checker.FixSafe,
							Operation:    checker.FixOpSet,
							FieldPath:    "spec.hostPID",
							DesiredValue: false,
							Description:  "Disables host PID namespace sharing.",
						},
						Applied: true,
					},
				},
			},
		},
		Summary: Summary{
			Applied: 2,
			Results: []Result{
				{
					FilePath:    "/app/deploy.yaml",
					Resource:    "web-app",
					Namespace:   "default",
					Kind:        "Deployment",
					CheckID:     "privileged",
					Safety:      checker.FixSafe,
					Description: "Disables privileged mode.",
					Applied:     true,
				},
				{
					FilePath:    "/app/sts.yaml",
					Resource:    "db",
					Namespace:   "data",
					Kind:        "StatefulSet",
					CheckID:     "host-pid",
					Safety:      checker.FixSafe,
					Description: "Disables host PID namespace sharing.",
					Applied:     true,
				},
			},
		},
	}
}

// kustomizeMergedFixesPlan returns a Plan where a single resource has multiple fixes.
func kustomizeMergedFixesPlan() *Plan {
	return &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {
				Path: "/app/deploy.yaml",
				Fixes: []PlannedFix{
					{
						Finding: checker.Finding{
							Checker:   "privileged",
							Resource:  "web-app",
							Namespace: "default",
							Kind:      "Deployment",
							Container: "web",
						},
						Strategy: Strategy{
							CheckID:      "privileged",
							Safety:       checker.FixSafe,
							Operation:    checker.FixOpSet,
							FieldPath:    "spec.containers[*].securityContext.privileged",
							DesiredValue: false,
							Description:  "Disables privileged mode.",
						},
						Applied: true,
					},
					{
						Finding: checker.Finding{
							Checker:   "privilege-escalation",
							Resource:  "web-app",
							Namespace: "default",
							Kind:      "Deployment",
							Container: "web",
						},
						Strategy: Strategy{
							CheckID:      "privilege-escalation",
							Safety:       checker.FixSafe,
							Operation:    checker.FixOpSet,
							FieldPath:    "spec.containers[*].securityContext.allowPrivilegeEscalation",
							DesiredValue: false,
							Description:  "Disables privilege escalation.",
						},
						Applied: true,
					},
				},
			},
		},
		Summary: Summary{
			Applied: 2,
			Results: []Result{
				{
					FilePath:    "/app/deploy.yaml",
					Resource:    "web-app",
					Namespace:   "default",
					Kind:        "Deployment",
					CheckID:     "privileged",
					Safety:      checker.FixSafe,
					Description: "Disables privileged mode.",
					Applied:     true,
				},
				{
					FilePath:    "/app/deploy.yaml",
					Resource:    "web-app",
					Namespace:   "default",
					Kind:        "Deployment",
					CheckID:     "privilege-escalation",
					Safety:      checker.FixSafe,
					Description: "Disables privilege escalation.",
					Applied:     true,
				},
			},
		},
	}
}

func TestGenerateKustomizeOverlay_SingleResource(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "overlay")
	plan := kustomizeTestPlan()

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// Verify kustomization.yaml exists.
	kustPath := filepath.Join(outDir, "kustomization.yaml")
	_, err = os.Stat(kustPath)
	require.NoError(t, err, "kustomization.yaml should exist")

	kustContent, err := os.ReadFile(kustPath)
	require.NoError(t, err)
	kustStr := string(kustContent)

	assert.Contains(t, kustStr, "apiVersion: kustomize.config.k8s.io/v1beta1")
	assert.Contains(t, kustStr, "kind: Kustomization")
	assert.Contains(t, kustStr, "deployment-default-web-app.yaml")

	// Verify patch file exists.
	patchPath := filepath.Join(outDir, "deployment-default-web-app.yaml")
	_, err = os.Stat(patchPath)
	require.NoError(t, err, "patch file should exist")

	patchContent, err := os.ReadFile(patchPath)
	require.NoError(t, err)
	patchStr := string(patchContent)

	assert.Contains(t, patchStr, "kind: Deployment")
	assert.Contains(t, patchStr, "name: web-app")
	assert.Contains(t, patchStr, "namespace: default")
}

func TestGenerateKustomizeOverlay_MultipleResources(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "overlay")
	plan := kustomizeMultiResourcePlan()

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// Verify kustomization.yaml lists both patches.
	kustContent, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	kustStr := string(kustContent)

	assert.Contains(t, kustStr, "deployment-default-web-app.yaml")
	assert.Contains(t, kustStr, "statefulset-data-db.yaml")

	// Verify both patch files exist.
	_, err = os.Stat(filepath.Join(outDir, "deployment-default-web-app.yaml"))
	require.NoError(t, err, "deployment patch should exist")

	_, err = os.Stat(filepath.Join(outDir, "statefulset-data-db.yaml"))
	require.NoError(t, err, "statefulset patch should exist")
}

func TestGenerateKustomizeOverlay_MergedFixes(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "overlay")
	plan := kustomizeMergedFixesPlan()

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// Should produce only one patch file for the single resource.
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)

	yamlFiles := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") && e.Name() != "kustomization.yaml" {
			yamlFiles++
		}
	}
	assert.Equal(t, 1, yamlFiles, "should produce one patch file for merged fixes")

	// Verify patch contains both fixes.
	patchContent, err := os.ReadFile(filepath.Join(outDir, "deployment-default-web-app.yaml"))
	require.NoError(t, err)
	patchStr := string(patchContent)

	assert.Contains(t, patchStr, "privileged: false")
	assert.Contains(t, patchStr, "allowPrivilegeEscalation: false")
}

func TestBuildKustomization(t *testing.T) {
	patchFiles := []string{"deployment-default-web-app.yaml", "statefulset-data-db.yaml"}
	content := buildKustomization(patchFiles, RiskLevelSafe)
	str := string(content)

	assert.Contains(t, str, "apiVersion: kustomize.config.k8s.io/v1beta1")
	assert.Contains(t, str, "kind: Kustomization")
	assert.Contains(t, str, "risk level: safe")
	assert.Contains(t, str, "kubectl apply -k")
	assert.Contains(t, str, "- path: deployment-default-web-app.yaml")
	assert.Contains(t, str, "- path: statefulset-data-db.yaml")

	// Verify patches are sorted alphabetically.
	deployIdx := strings.Index(str, "deployment-default-web-app.yaml")
	stsIdx := strings.Index(str, "statefulset-data-db.yaml")
	assert.Less(t, deployIdx, stsIdx, "patches should be sorted alphabetically")
}

func TestBuildKustomization_RiskLevels(t *testing.T) {
	tests := []struct {
		name      string
		riskLevel RiskLevel
		expected  string
	}{
		{name: "safe", riskLevel: RiskLevelSafe, expected: "risk level: safe"},
		{name: "moderate", riskLevel: RiskLevelModerate, expected: "risk level: moderate"},
		{name: "aggressive", riskLevel: RiskLevelAggressive, expected: "risk level: aggressive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := buildKustomization([]string{"patch.yaml"}, tt.riskLevel)
			assert.Contains(t, string(content), tt.expected)
		})
	}
}

func TestResourcePatchFilename(t *testing.T) {
	tests := []struct {
		name     string
		id       ResourceID
		expected string
	}{
		{
			name:     "simple deployment with namespace",
			id:       ResourceID{Kind: "Deployment", Name: "web-app", Namespace: "default"},
			expected: "deployment-default-web-app.yaml",
		},
		{
			name:     "no namespace",
			id:       ResourceID{Kind: "Pod", Name: "test-pod", Namespace: ""},
			expected: "pod-test-pod.yaml",
		},
		{
			name:     "uppercase kind",
			id:       ResourceID{Kind: "StatefulSet", Name: "db", Namespace: "data"},
			expected: "statefulset-data-db.yaml",
		},
		{
			name:     "special chars in name",
			id:       ResourceID{Kind: "Deployment", Name: "web.app/v2", Namespace: "prod"},
			expected: "deployment-prod-web-app-v2.yaml",
		},
		{
			name:     "CronJob kind",
			id:       ResourceID{Kind: "CronJob", Name: "cleanup", Namespace: "batch"},
			expected: "cronjob-batch-cleanup.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resourcePatchFilename(tt.id)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestBuildPatch_Deployment(t *testing.T) {
	id := ResourceID{Kind: "Deployment", Name: "web-app", Namespace: "default"}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:   "privileged",
				Resource:  "web-app",
				Namespace: "default",
				Kind:      "Deployment",
				Container: "web",
			},
			Strategy: Strategy{
				CheckID:      "privileged",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.containers[*].securityContext.privileged",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "apiVersion: apps/v1")
	assert.Contains(t, str, "kind: Deployment")
	assert.Contains(t, str, "name: web-app")
	assert.Contains(t, str, "namespace: default")
	assert.Contains(t, str, "privileged: false")
	// Should have strategic merge patch structure with container name.
	assert.Contains(t, str, "name: web")
}

func TestBuildPatch_Pod(t *testing.T) {
	id := ResourceID{Kind: "Pod", Name: "test-pod", Namespace: ""}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:  "host-pid",
				Resource: "test-pod",
				Kind:     "Pod",
			},
			Strategy: Strategy{
				CheckID:      "host-pid",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.hostPID",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "apiVersion: v1")
	assert.Contains(t, str, "kind: Pod")
	assert.Contains(t, str, "name: test-pod")
	assert.Contains(t, str, "hostPID: false")
	// Should not have namespace since it's empty.
	assert.NotContains(t, str, "namespace:")
}

func TestBuildPatch_MultiContainer(t *testing.T) {
	id := ResourceID{Kind: "Deployment", Name: "multi", Namespace: "default"}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:   "privileged",
				Resource:  "multi",
				Namespace: "default",
				Kind:      "Deployment",
				Container: "app",
			},
			Strategy: Strategy{
				CheckID:      "privileged",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.containers[*].securityContext.privileged",
				DesiredValue: false,
			},
			Applied: true,
		},
		{
			Finding: checker.Finding{
				Checker:   "privileged",
				Resource:  "multi",
				Namespace: "default",
				Kind:      "Deployment",
				Container: "sidecar",
			},
			Strategy: Strategy{
				CheckID:      "privileged",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.containers[*].securityContext.privileged",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "name: app")
	assert.Contains(t, str, "name: sidecar")
	// Both containers should have the fix.
	assert.Equal(t, 2, strings.Count(str, "privileged: false"),
		"should have privileged: false for both containers")
}

func TestGenerateKustomizeOverlay_EmptyPlan(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "overlay")
	plan := &Plan{
		Files:   map[string]*FilePlan{},
		Summary: Summary{Applied: 0, Results: []Result{}},
	}

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// Output directory should not be created when there are no applied fixes.
	_, err = os.Stat(outDir)
	assert.True(t, os.IsNotExist(err), "output dir should not be created for empty plan")
}

func TestGenerateKustomizeOverlay_DirectoryCreation(t *testing.T) {
	// Nested directory that does not exist.
	outDir := filepath.Join(t.TempDir(), "a", "b", "c", "overlay")
	plan := kustomizeTestPlan()

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	info, err := os.Stat(outDir)
	require.NoError(t, err, "nested output directory should be created")
	assert.True(t, info.IsDir(), "should be a directory")

	// Verify files were actually written.
	_, err = os.Stat(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err, "kustomization.yaml should exist in nested dir")
}

func TestGenerateKustomizeOverlay_SkipsUnappliedResults(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "overlay")
	plan := &Plan{
		Files: map[string]*FilePlan{},
		Summary: Summary{
			Applied: 0,
			Skipped: 1,
			Results: []Result{
				{
					FilePath:    "/app/deploy.yaml",
					Resource:    "web-app",
					Namespace:   "default",
					Kind:        "Deployment",
					CheckID:     "privileged",
					Safety:      checker.FixSafe,
					Description: "Disables privileged mode.",
					Applied:     false,
					SkipReason:  "risk_level",
				},
			},
		},
	}

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// No files should be created since nothing was applied.
	_, err = os.Stat(outDir)
	assert.True(t, os.IsNotExist(err), "output dir should not exist for skipped-only plan")
}

func TestBuildPatch_StatefulSet(t *testing.T) {
	id := ResourceID{Kind: "StatefulSet", Name: "db", Namespace: "data"}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:   "host-pid",
				Resource:  "db",
				Namespace: "data",
				Kind:      "StatefulSet",
			},
			Strategy: Strategy{
				CheckID:      "host-pid",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.hostPID",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "apiVersion: apps/v1")
	assert.Contains(t, str, "kind: StatefulSet")
	assert.Contains(t, str, "name: db")
	assert.Contains(t, str, "namespace: data")
	assert.Contains(t, str, "hostPID: false")
}

func TestBuildPatch_Job(t *testing.T) {
	id := ResourceID{Kind: "Job", Name: "migrate", Namespace: "default"}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:   "privileged",
				Resource:  "migrate",
				Namespace: "default",
				Kind:      "Job",
				Container: "runner",
			},
			Strategy: Strategy{
				CheckID:      "privileged",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.containers[*].securityContext.privileged",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "apiVersion: batch/v1")
	assert.Contains(t, str, "kind: Job")
}

func TestBuildPatch_CronJob(t *testing.T) {
	id := ResourceID{Kind: "CronJob", Name: "cleanup", Namespace: "batch"}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:   "privileged",
				Resource:  "cleanup",
				Namespace: "batch",
				Kind:      "CronJob",
				Container: "worker",
			},
			Strategy: Strategy{
				CheckID:      "privileged",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.containers[*].securityContext.privileged",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "apiVersion: batch/v1")
	assert.Contains(t, str, "kind: CronJob")
}

func TestBuildPatch_PodLevelAndContainerLevel(t *testing.T) {
	// A single resource with both a pod-level fix and a container-level fix.
	id := ResourceID{Kind: "Deployment", Name: "mixed", Namespace: "default"}
	fixes := []PlannedFix{
		{
			Finding: checker.Finding{
				Checker:   "host-pid",
				Resource:  "mixed",
				Namespace: "default",
				Kind:      "Deployment",
			},
			Strategy: Strategy{
				CheckID:      "host-pid",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.hostPID",
				DesiredValue: false,
			},
			Applied: true,
		},
		{
			Finding: checker.Finding{
				Checker:   "privileged",
				Resource:  "mixed",
				Namespace: "default",
				Kind:      "Deployment",
				Container: "web",
			},
			Strategy: Strategy{
				CheckID:      "privileged",
				Safety:       checker.FixSafe,
				Operation:    checker.FixOpSet,
				FieldPath:    "spec.containers[*].securityContext.privileged",
				DesiredValue: false,
			},
			Applied: true,
		},
	}

	content, err := buildPatch(id, fixes)
	require.NoError(t, err)

	str := string(content)
	assert.Contains(t, str, "hostPID: false")
	assert.Contains(t, str, "privileged: false")
	assert.Contains(t, str, "name: web")
}

func TestGenerateKustomizeOverlay_ExistingKustomizationWarning(t *testing.T) {
	outDir := t.TempDir()

	// Create a pre-existing kustomization.yaml.
	err := os.WriteFile(filepath.Join(outDir, "kustomization.yaml"), []byte("old content"), 0o644)
	require.NoError(t, err)

	plan := kustomizeTestPlan()

	// Should succeed and overwrite, though it logs a warning.
	err = GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// Verify the new content was written.
	content, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "apiVersion: kustomize.config.k8s.io/v1beta1",
		"kustomization.yaml should be overwritten with new content")
}

func TestExtractContainerSubPath(t *testing.T) {
	testCases := []struct {
		name      string
		fieldPath string
		want      string
	}{
		{
			name:      "regular container with wildcard",
			fieldPath: "spec.containers[*].securityContext.privileged",
			want:      "securityContext.privileged",
		},
		{
			name:      "initContainers does not match containers prefix",
			fieldPath: "spec.initContainers[0].securityContext.runAsNonRoot",
			want:      "",
		},
		{
			name:      "container with named index",
			fieldPath: "spec.containers[sidecar].resources.limits",
			want:      "resources.limits",
		},
		{
			name:      "no containers reference",
			fieldPath: "spec.hostPID",
			want:      "",
		},
		{
			name:      "missing closing bracket",
			fieldPath: "spec.containers[*",
			want:      "",
		},
		{
			name:      "containers at end with dot",
			fieldPath: "spec.containers[*].securityContext",
			want:      "securityContext",
		},
		{
			name:      "containers at end without dot",
			fieldPath: "spec.containers[0]",
			want:      "",
		},
		{
			name:      "empty string",
			fieldPath: "",
			want:      "",
		},
		{
			name:      "deeply nested path after containers",
			fieldPath: "spec.template.spec.containers[*].securityContext.capabilities.drop",
			want:      "securityContext.capabilities.drop",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractContainerSubPath(tc.fieldPath)
			assert.Equal(t, tc.want, got, "extractContainerSubPath(%q)", tc.fieldPath)
		})
	}
}

func TestFindPlannedFix(t *testing.T) {
	testCases := []struct {
		name   string
		plan   *Plan
		result Result
		found  bool
	}{
		{
			name: "fix found - matching file, checkID, and resource",
			plan: &Plan{
				Files: map[string]*FilePlan{
					"/app/deploy.yaml": {
						Path: "/app/deploy.yaml",
						Fixes: []PlannedFix{
							{
								Finding: checker.Finding{
									Checker:  "privileged",
									Resource: "web-app",
								},
								Strategy: Strategy{
									CheckID: "privileged",
								},
								Applied: true,
							},
						},
					},
				},
			},
			result: Result{
				FilePath: "/app/deploy.yaml",
				CheckID:  "privileged",
				Resource: "web-app",
			},
			found: true,
		},
		{
			name: "fix not found - wrong file path",
			plan: &Plan{
				Files: map[string]*FilePlan{
					"/app/deploy.yaml": {
						Path: "/app/deploy.yaml",
						Fixes: []PlannedFix{
							{
								Finding: checker.Finding{
									Checker:  "privileged",
									Resource: "web-app",
								},
								Applied: true,
							},
						},
					},
				},
			},
			result: Result{
				FilePath: "/other/deploy.yaml",
				CheckID:  "privileged",
				Resource: "web-app",
			},
			found: false,
		},
		{
			name: "fix not found - wrong check ID",
			plan: &Plan{
				Files: map[string]*FilePlan{
					"/app/deploy.yaml": {
						Path: "/app/deploy.yaml",
						Fixes: []PlannedFix{
							{
								Finding: checker.Finding{
									Checker:  "privileged",
									Resource: "web-app",
								},
								Applied: true,
							},
						},
					},
				},
			},
			result: Result{
				FilePath: "/app/deploy.yaml",
				CheckID:  "run-as-root",
				Resource: "web-app",
			},
			found: false,
		},
		{
			name: "fix not found - not applied",
			plan: &Plan{
				Files: map[string]*FilePlan{
					"/app/deploy.yaml": {
						Path: "/app/deploy.yaml",
						Fixes: []PlannedFix{
							{
								Finding: checker.Finding{
									Checker:  "privileged",
									Resource: "web-app",
								},
								Applied: false,
							},
						},
					},
				},
			},
			result: Result{
				FilePath: "/app/deploy.yaml",
				CheckID:  "privileged",
				Resource: "web-app",
			},
			found: false,
		},
		{
			name: "empty plan - no files",
			plan: &Plan{
				Files: map[string]*FilePlan{},
			},
			result: Result{
				FilePath: "/app/deploy.yaml",
				CheckID:  "privileged",
				Resource: "web-app",
			},
			found: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := findPlannedFix(tc.plan, &tc.result)
			if tc.found {
				require.NotNil(t, got, "expected to find a PlannedFix")
			} else {
				require.Nil(t, got, "expected nil PlannedFix")
			}
		})
	}
}

func TestGenerateKustomizeOverlay_EmptyAppliedResults(t *testing.T) {
	// Plan has files but all results are not applied.
	outDir := filepath.Join(t.TempDir(), "overlay")
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {
				Path: "/app/deploy.yaml",
				Fixes: []PlannedFix{
					{
						Finding: checker.Finding{
							Checker:  "privileged",
							Resource: "web-app",
						},
						Applied: false,
					},
				},
			},
		},
		Summary: Summary{
			Applied: 0,
			Skipped: 1,
			Results: []Result{
				{
					FilePath: "/app/deploy.yaml",
					CheckID:  "privileged",
					Resource: "web-app",
					Applied:  false,
				},
			},
		},
	}

	err := GenerateKustomizeOverlay(plan, outDir)
	require.NoError(t, err)

	// Output dir should not exist since no fixes were applied.
	_, err = os.Stat(outDir)
	assert.True(t, os.IsNotExist(err), "output dir should not be created when no fixes applied")
}

func TestHighestRiskLevel(t *testing.T) {
	tests := []struct {
		name    string
		results []Result
		want    RiskLevel
	}{
		{
			name:    "empty results",
			results: nil,
			want:    RiskLevelSafe,
		},
		{
			name: "only safe",
			results: []Result{
				{Safety: checker.FixSafe},
				{Safety: checker.FixSafe},
			},
			want: RiskLevelSafe,
		},
		{
			name: "mix safe and likely_safe",
			results: []Result{
				{Safety: checker.FixSafe},
				{Safety: checker.FixLikelySafe},
			},
			want: RiskLevelModerate,
		},
		{
			name: "mix with potentially_breaking",
			results: []Result{
				{Safety: checker.FixSafe},
				{Safety: checker.FixLikelySafe},
				{Safety: checker.FixPotentiallyBreaking},
			},
			want: RiskLevelAggressive,
		},
		{
			name: "only potentially_breaking",
			results: []Result{
				{Safety: checker.FixPotentiallyBreaking},
			},
			want: RiskLevelAggressive,
		},
		{
			name: "only likely_safe",
			results: []Result{
				{Safety: checker.FixLikelySafe},
			},
			want: RiskLevelModerate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := highestRiskLevel(tt.results)
			assert.Equal(t, tt.want, got)
		})
	}
}
