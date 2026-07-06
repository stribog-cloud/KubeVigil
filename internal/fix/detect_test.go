package fix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectHelmManaged_Found(t *testing.T) {
	helmManaged := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app.kubernetes.io/managed-by: Helm
    helm.sh/chart: myapp-0.1.0
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": {
				Path:            "/tmp/deploy.yaml",
				OriginalContent: helmManaged,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 1 {
		t.Fatalf("expected 1 Helm-managed file, got %d", len(result))
	}
	if result[0] != "/tmp/deploy.yaml" {
		t.Errorf("expected /tmp/deploy.yaml, got %s", result[0])
	}
}

func TestDetectHelmManaged_NotFound(t *testing.T) {
	noHelm := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app: web
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": {
				Path:            "/tmp/deploy.yaml",
				OriginalContent: noHelm,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files, got %d: %v", len(result), result)
	}
}

func TestDetectHelmManaged_HelmShLabel(t *testing.T) {
	helmShOnly := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    helm.sh/chart: mychart-0.1.0
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": {
				Path:            "/tmp/deploy.yaml",
				OriginalContent: helmShOnly,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 1 {
		t.Fatalf("expected 1 Helm-managed file, got %d", len(result))
	}
	if result[0] != "/tmp/deploy.yaml" {
		t.Errorf("expected /tmp/deploy.yaml, got %s", result[0])
	}
}

func TestDetectHelmManaged_NilPlan(t *testing.T) {
	// Empty plan with no files.
	plan := &Plan{
		Files: map[string]*FilePlan{},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files for empty plan, got %d", len(result))
	}
}

func TestDetectHelmManaged_CaseInsensitive(t *testing.T) {
	helmLowerCase := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app.kubernetes.io/managed-by: helm
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": {
				Path:            "/tmp/deploy.yaml",
				OriginalContent: helmLowerCase,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 1 {
		t.Fatalf("expected 1 Helm-managed file (case-insensitive), got %d", len(result))
	}
}

func TestDetectHelmManaged_MultipleFiles(t *testing.T) {
	helmManaged := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app.kubernetes.io/managed-by: Helm
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	noHelm := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: other-app
  labels:
    app: other
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/a/deploy.yaml": {
				Path:            "/tmp/a/deploy.yaml",
				OriginalContent: helmManaged,
			},
			"/tmp/b/deploy.yaml": {
				Path:            "/tmp/b/deploy.yaml",
				OriginalContent: noHelm,
			},
			"/tmp/c/deploy.yaml": {
				Path:            "/tmp/c/deploy.yaml",
				OriginalContent: helmManaged,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 2 {
		t.Fatalf("expected 2 Helm-managed files, got %d: %v", len(result), result)
	}
	// Results should be sorted.
	if result[0] != "/tmp/a/deploy.yaml" {
		t.Errorf("expected first result /tmp/a/deploy.yaml, got %s", result[0])
	}
	if result[1] != "/tmp/c/deploy.yaml" {
		t.Errorf("expected second result /tmp/c/deploy.yaml, got %s", result[1])
	}
}

func TestDetectHelmManaged_MalformedYAML(t *testing.T) {
	malformed := []byte(`this is not: valid: yaml: [`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/bad.yaml": {
				Path:            "/tmp/bad.yaml",
				OriginalContent: malformed,
			},
		},
	}

	// Should not panic; malformed YAML is logged and skipped.
	result := DetectHelmManaged(plan)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files for malformed YAML, got %d", len(result))
	}
}

func TestDetectHelmManaged_NoLabels(t *testing.T) {
	noLabels := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`)

	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": {
				Path:            "/tmp/deploy.yaml",
				OriginalContent: noLabels,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files for resource without labels, got %d", len(result))
	}
}

func TestDetectKustomize_Found(t *testing.T) {
	dir := t.TempDir()
	kustomizePath := filepath.Join(dir, "kustomization.yaml")
	if err := os.WriteFile(kustomizePath, []byte("resources:\n  - deploy.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := DetectKustomize([]string{dir})
	if len(result) != 1 {
		t.Fatalf("expected 1 kustomize path, got %d: %v", len(result), result)
	}
	if result[0] != dir {
		t.Errorf("expected %s, got %s", dir, result[0])
	}
}

func TestDetectKustomize_Yml(t *testing.T) {
	dir := t.TempDir()
	kustomizePath := filepath.Join(dir, "kustomization.yml")
	if err := os.WriteFile(kustomizePath, []byte("resources:\n  - deploy.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := DetectKustomize([]string{dir})
	if len(result) != 1 {
		t.Fatalf("expected 1 kustomize path, got %d: %v", len(result), result)
	}
	if result[0] != dir {
		t.Errorf("expected %s, got %s", dir, result[0])
	}
}

func TestDetectKustomize_NotFound(t *testing.T) {
	dir := t.TempDir()
	// No kustomization.yaml or kustomization.yml in the directory.

	result := DetectKustomize([]string{dir})
	if len(result) != 0 {
		t.Fatalf("expected 0 kustomize paths, got %d: %v", len(result), result)
	}
}

func TestDetectKustomize_EmptyInput(t *testing.T) {
	result := DetectKustomize(nil)
	if len(result) != 0 {
		t.Fatalf("expected 0 kustomize paths for nil input, got %d", len(result))
	}

	result = DetectKustomize([]string{})
	if len(result) != 0 {
		t.Fatalf("expected 0 kustomize paths for empty input, got %d", len(result))
	}
}

func TestDetectKustomize_FileInKustomizeDir(t *testing.T) {
	dir := t.TempDir()
	kustomizePath := filepath.Join(dir, "kustomization.yaml")
	if err := os.WriteFile(kustomizePath, []byte("resources:\n  - deploy.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deployPath := filepath.Join(dir, "deploy.yaml")
	if err := os.WriteFile(deployPath, []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pass a file path (not a directory) that lives in a kustomize directory.
	result := DetectKustomize([]string{deployPath})
	if len(result) != 1 {
		t.Fatalf("expected 1 kustomize path, got %d: %v", len(result), result)
	}
	if result[0] != dir {
		t.Errorf("expected %s, got %s", dir, result[0])
	}
}

func TestDetectKustomize_Deduplication(t *testing.T) {
	dir := t.TempDir()
	kustomizePath := filepath.Join(dir, "kustomization.yaml")
	if err := os.WriteFile(kustomizePath, []byte("resources:\n  - deploy.yaml\n  - svc.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deploy := filepath.Join(dir, "deploy.yaml")
	svc := filepath.Join(dir, "svc.yaml")
	if err := os.WriteFile(deploy, []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc, []byte("apiVersion: v1\nkind: Service\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pass the directory and two files in it — should deduplicate.
	result := DetectKustomize([]string{dir, deploy, svc})
	if len(result) != 1 {
		t.Fatalf("expected 1 deduplicated kustomize path, got %d: %v", len(result), result)
	}
	if result[0] != dir {
		t.Errorf("expected %s, got %s", dir, result[0])
	}
}

func TestDetectKustomize_MultipleDirs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir1, "kustomization.yaml"), []byte("resources: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "kustomization.yml"), []byte("resources: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := DetectKustomize([]string{dir1, dir2})
	if len(result) != 2 {
		t.Fatalf("expected 2 kustomize paths, got %d: %v", len(result), result)
	}
	// Results should be sorted.
	if result[0] > result[1] {
		t.Errorf("results not sorted: %v", result)
	}
}

func TestDetectKustomize_NonexistentPath(t *testing.T) {
	// A path that does not exist should be silently skipped.
	result := DetectKustomize([]string{"/nonexistent/path/that/does/not/exist"})
	if len(result) != 0 {
		t.Fatalf("expected 0 kustomize paths for nonexistent path, got %d", len(result))
	}
}

func TestHasHelmLabels(t *testing.T) {
	testCases := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "managed-by Helm label present",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app.kubernetes.io/managed-by: Helm
`,
			want: true,
		},
		{
			name: "helm.sh prefixed label present",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    helm.sh/chart: mychart-0.1.0
`,
			want: true,
		},
		{
			name: "no Helm labels",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app: web
    tier: frontend
`,
			want: false,
		},
		{
			name: "partial label - managed-by non-Helm",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app.kubernetes.io/managed-by: kustomize
`,
			want: false,
		},
		{
			name: "no labels at all",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
`,
			want: false,
		},
		{
			name: "nil docs",
			yaml: "",
			want: false,
		},
		{
			name: "labels present but not a mapping (scalar)",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  labels: not-a-mapping
`,
			want: false,
		},
		{
			name: "labels present but not a mapping (sequence)",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    - app
    - web
`,
			want: false,
		},
		{
			name: "managed-by Helm case insensitive",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  labels:
    app.kubernetes.io/managed-by: HELM
`,
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.yaml == "" {
				got := hasHelmLabels(nil)
				if got != tc.want {
					t.Errorf("hasHelmLabels(nil) = %v, want %v", got, tc.want)
				}
				return
			}

			docs, err := ParseDocuments([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("ParseDocuments() error = %v", err)
			}
			got := hasHelmLabels(docs)
			if got != tc.want {
				t.Errorf("hasHelmLabels() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectHelmManaged_NilPlanActual(t *testing.T) {
	// Truly nil plan, not just empty files.
	result := DetectHelmManaged(nil)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files for nil plan, got %d", len(result))
	}
}

func TestDetectHelmManaged_EmptyOriginalContent(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": {
				Path:            "/tmp/deploy.yaml",
				OriginalContent: nil,
			},
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files for empty content, got %d", len(result))
	}
}

func TestDetectHelmManaged_NilFilePlan(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/tmp/deploy.yaml": nil,
		},
	}

	result := DetectHelmManaged(plan)
	if len(result) != 0 {
		t.Fatalf("expected 0 Helm-managed files for nil FilePlan, got %d", len(result))
	}
}

func TestHasHelmLabels_NilDocumentInSlice(t *testing.T) {
	// A nil *Document mixed with a real, Helm-labeled document should be
	// skipped without panicking, and detection should still succeed on the
	// subsequent valid document.
	validYAML := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app.kubernetes.io/managed-by: Helm
`)
	validDocs, err := ParseDocuments(validYAML)
	if err != nil {
		t.Fatalf("ParseDocuments() error = %v", err)
	}

	docs := []*Document{nil, validDocs[0]}
	got := hasHelmLabels(docs)
	if !got {
		t.Error("expected true when a valid Helm-labeled document follows a nil document")
	}
}

func TestHasHelmLabels_DocumentWithNilNode(t *testing.T) {
	// A *Document whose Node field is nil should be skipped without panicking.
	docs := []*Document{{Node: nil}}
	got := hasHelmLabels(docs)
	if got {
		t.Error("expected false for a document with nil Node")
	}
}
