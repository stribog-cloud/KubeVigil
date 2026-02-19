package fix

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	// Import checker packages to register checkers in the default registry.
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cloud"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cluster"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/crd"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/image"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/network"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/psa"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/rbac"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/scheduling"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/secrets"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/storage"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/supply_chain"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

// benchDeploymentYAML is a single Deployment manifest with security issues
// used as input for YAML parsing and node operation benchmarks.
var benchDeploymentYAML = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: bench-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: bench
  template:
    metadata:
      labels:
        app: bench
    spec:
      containers:
      - name: app
        image: nginx:latest
        ports:
        - containerPort: 80
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
      - name: sidecar
        image: busybox:latest
        securityContext:
          privileged: false
`)

// benchMultiDocYAML is a multi-document YAML file with 5 documents (Deployment,
// Deployment, Service, ServiceAccount, StatefulSet) used for multi-doc parsing
// and serialization benchmarks.
var benchMultiDocYAML = []byte(`---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-1
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-1
  template:
    metadata:
      labels:
        app: app-1
    spec:
      containers:
      - name: main
        image: nginx:latest
        securityContext:
          privileged: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-2
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app-2
  template:
    metadata:
      labels:
        app: app-2
    spec:
      hostNetwork: true
      containers:
      - name: main
        image: redis:latest
        securityContext:
          privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: svc-1
  namespace: default
spec:
  selector:
    app: app-1
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-1
  namespace: default
  annotations:
    note: bench
automountServiceAccountToken: true
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db-1
  namespace: default
spec:
  replicas: 1
  serviceName: db
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
      - name: postgres
        image: postgres:15
        securityContext:
          runAsUser: 0
`)

// BenchmarkParseYAML_Single measures the cost of parsing a single Deployment YAML
// document into a yaml.Node tree via ParseYAML.
func BenchmarkParseYAML_Single(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node, err := ParseYAML(benchDeploymentYAML)
		if err != nil {
			b.Fatal(err)
		}
		_ = node
	}
}

// BenchmarkParseDocuments_Multi measures the cost of parsing a multi-document
// YAML file (5 documents) into Document structs via ParseDocuments.
func BenchmarkParseDocuments_Multi(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		docs, err := ParseDocuments(benchMultiDocYAML)
		if err != nil {
			b.Fatal(err)
		}
		_ = docs
	}
}

// BenchmarkSerializeNode measures the cost of serializing a parsed yaml.Node
// tree back to bytes via SerializeNode.
func BenchmarkSerializeNode(b *testing.B) {
	node, err := ParseYAML(benchDeploymentYAML)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := SerializeNode(node)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

// BenchmarkSerializeDocuments measures the cost of serializing parsed
// multi-document YAML (5 documents) back to bytes via SerializeDocuments.
func BenchmarkSerializeDocuments(b *testing.B) {
	docs, err := ParseDocuments(benchMultiDocYAML)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := SerializeDocuments(docs)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

// BenchmarkFindNode measures the cost of navigating to various paths within a
// parsed yaml.Node tree via FindNode. Each iteration traverses 5 different paths.
func BenchmarkFindNode(b *testing.B) {
	node, err := ParseYAML(benchDeploymentYAML)
	if err != nil {
		b.Fatal(err)
	}

	paths := []string{
		"spec.template.spec.containers[0].securityContext.privileged",
		"metadata.name",
		"spec.replicas",
		"spec.template.spec.containers[0].image",
		"spec.template.spec.containers[1].securityContext.privileged",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			found, err := FindNode(node, p)
			if err != nil {
				b.Fatal(err)
			}
			_ = found
		}
	}
}

// BenchmarkSetNode measures the cost of setting a node value at a deep path.
// Parses a fresh YAML document each iteration because SetNode mutates the tree.
func BenchmarkSetNode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node, err := ParseYAML(benchDeploymentYAML)
		if err != nil {
			b.Fatal(err)
		}
		if err := SetNode(node, "spec.template.spec.containers[0].securityContext.privileged", false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAddNode measures the cost of adding a new node at a path that does
// not yet exist. Parses a fresh YAML document each iteration because AddNode
// mutates the tree.
func BenchmarkAddNode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node, err := ParseYAML(benchDeploymentYAML)
		if err != nil {
			b.Fatal(err)
		}
		if err := AddNode(node, "spec.template.metadata.annotations.benchKey", "benchValue"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRemoveNode measures the cost of removing a node at a deep path.
// Parses a fresh YAML document each iteration because RemoveNode mutates the tree.
func BenchmarkRemoveNode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node, err := ParseYAML(benchDeploymentYAML)
		if err != nil {
			b.Fatal(err)
		}
		if err := RemoveNode(node, "spec.template.spec.containers[0].securityContext.privileged"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMergeNode measures the cost of merging a map value into an existing
// mapping node. Parses a fresh YAML document each iteration because MergeNode
// mutates the tree.
func BenchmarkMergeNode(b *testing.B) {
	mergeValue := map[string]any{
		"newKey1": "value1",
		"newKey2": "value2",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node, err := ParseYAML(benchDeploymentYAML)
		if err != nil {
			b.Fatal(err)
		}
		if err := MergeNode(node, "metadata", mergeValue); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDiffGeneration measures the cost of computing a unified diff between
// original and modified YAML content via GenerateDiff. The diff is computed from
// a single-field change (privileged: true -> false).
func BenchmarkDiffGeneration(b *testing.B) {
	// Parse, modify, and serialize to produce the "after" version.
	node, err := ParseYAML(benchDeploymentYAML)
	if err != nil {
		b.Fatal(err)
	}
	if err := SetNode(node, "spec.template.spec.containers[0].securityContext.privileged", false); err != nil {
		b.Fatal(err)
	}
	after, err := SerializeNode(node)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		diff := GenerateDiff("test.yaml", benchDeploymentYAML, after)
		_ = diff
	}
}

// BenchmarkFixerPlan measures the full Fixer.Plan pipeline (scan -> filter ->
// classify -> patch -> diff) on a medium-sized fixture file from test/benchdata/.
// This benchmark is skipped if the fixture is not found.
func BenchmarkFixerPlan(b *testing.B) {
	// Resolve the medium fixture relative to this test file's location.
	absPath, err := filepath.Abs("../../test/benchdata/medium.yaml")
	if err != nil {
		b.Skipf("resolving benchdata path: %v", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		b.Skipf("fixture not found: %v", err)
	}

	checkerReg := checker.DefaultRegistry()
	fixReg := DefaultRegistry()
	scanCfg := config.Default()
	fixCfg := DefaultConfig()
	fixCfg.RiskLevel = RiskLevelAggressive // Allow all fix safety levels.

	fixer := NewFixer(fixReg, checkerReg, scanCfg, &fixCfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan, err := fixer.Plan(ctx, []string{absPath})
		if err != nil {
			b.Fatal(err)
		}
		_ = plan
	}
}

// BenchmarkGenerateKustomizeOverlay measures the cost of generating a Kustomize
// overlay directory from a fix plan. Uses the medium fixture for a realistic plan.
// This benchmark is skipped if the fixture is not found.
func BenchmarkGenerateKustomizeOverlay(b *testing.B) {
	absPath, err := filepath.Abs("../../test/benchdata/medium.yaml")
	if err != nil {
		b.Skipf("resolving benchdata path: %v", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		b.Skipf("fixture not found: %v", err)
	}

	checkerReg := checker.DefaultRegistry()
	fixReg := DefaultRegistry()
	scanCfg := config.Default()
	fixCfg := DefaultConfig()
	fixCfg.RiskLevel = RiskLevelAggressive

	fixer := NewFixer(fixReg, checkerReg, scanCfg, &fixCfg)
	ctx := context.Background()

	plan, err := fixer.Plan(ctx, []string{absPath})
	if err != nil {
		b.Skipf("planning failed: %v", err)
	}
	if len(plan.Files) == 0 {
		b.Skip("no fixable findings in fixture")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputDir := b.TempDir()
		if err := GenerateKustomizeOverlay(plan, outputDir); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseRoundTrip measures the full parse-serialize round-trip cost for
// a single document: ParseYAML followed by SerializeNode.
func BenchmarkParseRoundTrip(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node, err := ParseYAML(benchDeploymentYAML)
		if err != nil {
			b.Fatal(err)
		}
		out, err := SerializeNode(node)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

// BenchmarkMultiDocRoundTrip measures the full parse-serialize round-trip cost
// for a 5-document YAML file: ParseDocuments followed by SerializeDocuments.
func BenchmarkMultiDocRoundTrip(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		docs, err := ParseDocuments(benchMultiDocYAML)
		if err != nil {
			b.Fatal(err)
		}
		out, err := SerializeDocuments(docs)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}
