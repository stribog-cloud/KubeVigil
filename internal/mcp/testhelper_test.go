package mcp

import (
	"fmt"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

// testFinding creates a Finding with the given parameters.
func testFinding(checkerID, severity, resource, namespace, category string) checker.Finding {
	sev, _ := checker.ParseSeverity(severity)
	return checker.Finding{
		Checker:     checkerID,
		Severity:    sev,
		Resource:    resource,
		Namespace:   namespace,
		Kind:        "Deployment",
		Message:     fmt.Sprintf("Test finding for %s on %s", checkerID, resource),
		Remediation: fmt.Sprintf("Fix %s on %s", checkerID, resource),
	}
}

// testFindingWithFrameworks creates a Finding with framework references.
func testFindingWithFrameworks(checkerID, severity, resource, namespace string, fws []checker.FrameworkRef) checker.Finding {
	f := testFinding(checkerID, severity, resource, namespace, "")
	f.Frameworks = fws
	return f
}

// testFindingWithFixHint creates a Finding with fix hint metadata.
func testFindingWithFixHint(checkerID, severity, resource, namespace string) checker.Finding {
	f := testFinding(checkerID, severity, resource, namespace, "")
	f.CurrentValue = true
	f.DesiredValue = false
	f.FixHint = &checker.FixHint{
		Safety:      checker.FixSafe,
		Description: fmt.Sprintf("Set %s to false", checkerID),
		Operation:   checker.FixOpSet,
	}
	return f
}

// testResult creates a ScanResult with the given findings and metadata.
func testResult(findings []checker.Finding) *checker.ScanResult {
	// Build check categories map from findings.
	categories := make(map[string]string)
	for _, f := range findings {
		if _, ok := categories[f.Checker]; !ok {
			// Infer category from checker registration, or use a default.
			if c, found := checker.Get(f.Checker); found {
				cats := c.Categories()
				if len(cats) > 0 {
					categories[f.Checker] = cats[0].String()
				}
			} else {
				categories[f.Checker] = "Workload"
			}
		}
	}

	return &checker.ScanResult{
		Findings: findings,
		ClusterInfo: checker.ClusterInfo{
			ContextName:   "test-cluster",
			ServerVersion: "v1.30.2",
			NodeCount:     3,
		},
		ScanMeta: checker.ScanMeta{
			ChecksRun:       110,
			ChecksErrored:   0,
			CheckCategories: categories,
		},
	}
}

// testKV creates a KubeVigilMCP with a pre-populated lastResult.
func testKV(findings []checker.Finding) *KubeVigilMCP {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())
	kv.lastResult = testResult(findings)
	return kv
}

// testKVEmpty creates a KubeVigilMCP with no scan result.
func testKVEmpty() *KubeVigilMCP {
	return NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())
}

// sampleFindings returns a representative set of findings for testing.
func sampleFindings() []checker.Finding {
	return []checker.Finding{
		testFinding("privileged", "Critical", "deploy-a", "default", "Workload"),
		testFinding("privileged", "Critical", "deploy-b", "payments", "Workload"),
		testFinding("run-as-root", "High", "deploy-a", "default", "Workload"),
		testFinding("run-as-root", "High", "deploy-c", "payments", "Workload"),
		testFinding("run-as-root", "High", "deploy-d", "monitoring", "Workload"),
		testFinding("capabilities-added", "High", "deploy-a", "default", "Workload"),
		testFinding("image-tag-latest", "Medium", "deploy-a", "default", "Image"),
		testFinding("image-tag-latest", "Medium", "deploy-b", "payments", "Image"),
		testFinding("no-resource-limits", "Low", "deploy-a", "default", "Workload"),
		testFindingWithFrameworks("privileged", "Critical", "deploy-c", "default",
			[]checker.FrameworkRef{
				{Framework: "cis", ControlID: "5.2.1", Title: "Minimize privileged containers"},
				{Framework: "mitre", ControlID: "T1611", Title: "Escape to host"},
			}),
		testFindingWithFixHint("allow-privilege-escalation", "High", "deploy-a", "default"),
	}
}
