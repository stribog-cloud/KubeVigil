package frameworks

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestLookupAll_ReturnsFrameworkRefs(t *testing.T) {
	refs := LookupAll("privileged")
	require.NotEmpty(t, refs, "privileged should map to at least one framework")

	// Verify we get refs from multiple frameworks.
	frameworks := make(map[string]bool)
	for _, ref := range refs {
		frameworks[ref.Framework] = true
	}
	assert.True(t, frameworks["cis"], "privileged should map to CIS")
	assert.True(t, frameworks["mitre"], "privileged should map to MITRE")
	assert.True(t, frameworks["nsa"], "privileged should map to NSA")
}

func TestLookupAll_UnknownCheck(t *testing.T) {
	refs := LookupAll("nonexistent-check")
	assert.Empty(t, refs)
}

func TestLookupByFramework(t *testing.T) {
	refs := LookupByFramework("privileged", "cis")
	require.NotEmpty(t, refs)
	for _, ref := range refs {
		assert.Equal(t, "cis", ref.Framework)
	}
}

func TestLookupByFramework_NoMatch(t *testing.T) {
	refs := LookupByFramework("privileged", "unknown-framework")
	assert.Empty(t, refs)
}

func TestFrameworkNames(t *testing.T) {
	names := FrameworkNames()
	assert.Contains(t, names, "cis")
	assert.Contains(t, names, "mitre")
	assert.Contains(t, names, "nsa")
}

func TestAllCheckersMapped(t *testing.T) {
	// Every registered checker should map to at least one framework.
	// This test uses the known list of all 110 check names.
	allChecks := allCheckNames()
	for _, name := range allChecks {
		t.Run(name, func(t *testing.T) {
			refs := LookupAll(name)
			assert.NotEmpty(t, refs, "check %q should map to at least one framework", name)
		})
	}
}

func TestAttachFrameworks(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical},
		{Checker: "run-as-root", Severity: checker.SeverityHigh},
	}

	AttachFrameworks(findings)

	assert.NotEmpty(t, findings[0].Frameworks, "privileged should have frameworks attached")
	assert.NotEmpty(t, findings[1].Frameworks, "run-as-root should have frameworks attached")
}

func TestAttachFrameworks_Empty(t *testing.T) {
	var findings []checker.Finding
	AttachFrameworks(findings) // should not panic
}

func TestFilterByFramework(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical},
		{Checker: "run-as-root", Severity: checker.SeverityHigh},
	}
	AttachFrameworks(findings)

	filtered := FilterByFramework(findings, "cis")
	// Both checks should map to CIS.
	assert.Len(t, filtered, 2)

	// Filter by nonexistent framework should return empty.
	empty := FilterByFramework(findings, "nonexistent")
	assert.Empty(t, empty)
}

// TestCISControlIDsValid verifies that every CIS control ID used in our mappings
// is a real CIS Kubernetes Benchmark v1.8 control.
func TestCISControlIDsValid(t *testing.T) {
	// Known-good CIS Kubernetes Benchmark v1.8 control IDs.
	validCISControls := map[string]bool{
		// Section 1.1 — Control Plane Node Configuration Files
		"1.1.1": true, "1.1.2": true, "1.1.3": true, "1.1.4": true,
		"1.1.5": true, "1.1.6": true, "1.1.7": true, "1.1.8": true,
		"1.1.9": true, "1.1.10": true, "1.1.11": true, "1.1.12": true,
		"1.1.13": true, "1.1.14": true, "1.1.15": true, "1.1.16": true,
		"1.1.17": true, "1.1.18": true, "1.1.19": true, "1.1.20": true,
		"1.1.21": true,
		// Section 1.2 — API Server
		"1.2.1": true, "1.2.2": true, "1.2.3": true, "1.2.4": true,
		"1.2.5": true, "1.2.6": true, "1.2.7": true, "1.2.8": true,
		"1.2.9": true, "1.2.10": true, "1.2.11": true, "1.2.12": true,
		"1.2.13": true, "1.2.14": true, "1.2.15": true, "1.2.16": true,
		"1.2.17": true, "1.2.18": true, "1.2.19": true, "1.2.20": true,
		"1.2.21": true, "1.2.22": true, "1.2.23": true, "1.2.24": true,
		"1.2.25": true, "1.2.26": true, "1.2.27": true, "1.2.28": true,
		"1.2.29": true, "1.2.30": true,
		// Section 1.3 — Controller Manager
		"1.3.1": true, "1.3.2": true, "1.3.3": true, "1.3.4": true,
		"1.3.5": true, "1.3.6": true, "1.3.7": true,
		// Section 1.4 — Scheduler
		"1.4.1": true, "1.4.2": true,
		// Section 2 — etcd
		"2.1": true, "2.2": true, "2.3": true, "2.4": true,
		"2.5": true, "2.6": true, "2.7": true,
		// Section 3.1 — Authentication and Authorization
		"3.1.1": true, "3.1.2": true, "3.1.3": true,
		// Section 3.2 — Logging
		"3.2.1": true, "3.2.2": true,
		// Section 4.1 — Worker Node Configuration Files
		"4.1.1": true, "4.1.2": true, "4.1.3": true, "4.1.4": true,
		"4.1.5": true, "4.1.6": true, "4.1.7": true, "4.1.8": true,
		"4.1.9": true, "4.1.10": true,
		// Section 4.2 — Kubelet
		"4.2.1": true, "4.2.2": true, "4.2.3": true, "4.2.4": true,
		"4.2.5": true, "4.2.6": true, "4.2.7": true, "4.2.8": true,
		"4.2.9": true, "4.2.10": true, "4.2.11": true, "4.2.12": true,
		"4.2.13": true, "4.2.14": true,
		// Section 4.3 — kube-proxy
		"4.3.1": true,
		// Section 5.1 — RBAC and Service Accounts
		"5.1.1": true, "5.1.2": true, "5.1.3": true, "5.1.4": true,
		"5.1.5": true, "5.1.6": true, "5.1.7": true, "5.1.8": true,
		"5.1.9": true, "5.1.10": true, "5.1.11": true, "5.1.12": true,
		"5.1.13": true,
		// Section 5.2 — Pod Security Standards
		"5.2.1": true, "5.2.2": true, "5.2.3": true, "5.2.4": true,
		"5.2.5": true, "5.2.6": true, "5.2.7": true, "5.2.8": true,
		"5.2.9": true, "5.2.10": true, "5.2.11": true, "5.2.12": true,
		"5.2.13": true,
		// Section 5.3 — Network Policies and CNI
		"5.3.1": true, "5.3.2": true,
		// Section 5.4 — Secrets Management
		"5.4.1": true, "5.4.2": true,
		// Section 5.5 — Extensible Admission Control
		"5.5.1": true,
		// Section 5.6 — General Policies
		"5.6.1": true, "5.6.2": true, "5.6.3": true, "5.6.4": true,
	}

	mappings := cisMappings()
	for checkName, refs := range mappings {
		for _, ref := range refs {
			if !validCISControls[ref.ControlID] {
				t.Errorf("check %q uses invalid CIS v1.8 control ID %q (title: %q)", checkName, ref.ControlID, ref.Title)
			}
			assert.Equal(t, "cis", ref.Framework, "check %q: framework should be cis", checkName)
			assert.Equal(t, "1.8", ref.Version, "check %q: version should be 1.8", checkName)
			assert.NotEmpty(t, ref.Title, "check %q: title should not be empty", checkName)
		}
	}
}

// TestCISMappingAccuracy validates that specific checks map to the correct CIS controls.
func TestCISMappingAccuracy(t *testing.T) {
	mappings := cisMappings()

	tests := []struct {
		check      string
		wantIDs    []string
		wantNotIDs []string
	}{
		{"privileged", []string{"5.2.2"}, []string{"5.2.1", "5.2.5"}},
		{"host-pid", []string{"5.2.3"}, []string{"5.2.2", "5.2.5"}},
		{"host-ipc", []string{"5.2.4"}, []string{"5.2.3"}},
		{"host-network", []string{"5.2.5"}, []string{"5.2.4"}},
		{"host-ports", []string{"5.2.13"}, []string{"5.2.4"}},
		{"host-path-volumes", []string{"5.2.12"}, []string{"5.2.13"}},
		{"privilege-escalation", []string{"5.2.6"}, []string{"5.2.5"}},
		{"run-as-root", []string{"5.2.7"}, []string{"5.2.6"}},
		{"seccomp-profile", []string{"5.6.2"}, nil},
		{"namespace-default-usage", []string{"5.6.4"}, nil},
		{"secrets-unencrypted", []string{"1.2.28", "1.2.29"}, []string{"5.4.1"}},
		{"audit-logging", []string{"1.2.17", "1.2.18"}, []string{"1.2.22", "1.2.23"}},
		{"etcd-encryption", []string{"1.2.28", "1.2.29"}, []string{"1.2.33"}},
		{"image-tag-latest", []string{"5.5.1"}, []string{"5.7.1"}},
		{"rbac-group-bindings", []string{"5.1.7", "5.1.1"}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.check, func(t *testing.T) {
			refs := mappings[tt.check]
			require.NotEmpty(t, refs, "check %q should have CIS mappings", tt.check)

			controlIDs := make(map[string]bool)
			for _, ref := range refs {
				controlIDs[ref.ControlID] = true
			}

			for _, wantID := range tt.wantIDs {
				assert.True(t, controlIDs[wantID], "check %q should map to CIS %s", tt.check, wantID)
			}
			for _, notID := range tt.wantNotIDs {
				assert.False(t, controlIDs[notID], "check %q should NOT map to CIS %s", tt.check, notID)
			}
		})
	}
}

func TestControlCounts(t *testing.T) {
	counts := ControlCounts()
	// All three frameworks should be present.
	assert.Contains(t, counts, "cis")
	assert.Contains(t, counts, "mitre")
	assert.Contains(t, counts, "nsa")
	// Each should have at least 1 control.
	for fw, count := range counts {
		assert.Greater(t, count, 0, "framework %q should have >0 controls", fw)
	}
}

func TestAllControlIDs(t *testing.T) {
	allIDs := AllControlIDs()

	// All three frameworks should be present.
	assert.Contains(t, allIDs, "cis")
	assert.Contains(t, allIDs, "mitre")
	assert.Contains(t, allIDs, "nsa")

	// Each framework has non-empty list and lists are sorted.
	for fw, ids := range allIDs {
		t.Run(fw, func(t *testing.T) {
			assert.NotEmpty(t, ids, "framework %q should have non-empty control IDs", fw)
			assert.True(t, sort.StringsAreSorted(ids), "framework %q control IDs should be sorted", fw)
		})
	}
}

func TestNormalizeFramework(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"cis", "cis"},
		{"cis-1.8", "cis"},
		{"mitre", "mitre"},
		{"mitre-v14", "mitre"},
		{"nsa", "nsa"},
		{"nsa-1.2", "nsa"},
		{"unknown", "unknown"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeFramework(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// allCheckNames returns the names of all 110 registered checkers.
func allCheckNames() []string {
	return []string{
		// Phase 1 — Workload (25)
		"privileged", "capabilities-added", "capabilities-not-dropped",
		"run-as-root", "run-as-high-uid", "run-as-group",
		"read-only-rootfs", "resource-limits-missing", "resource-requests-missing",
		"resource-limits-ratio", "ephemeral-storage-limits",
		"host-pid", "host-ipc", "host-network", "host-ports", "host-path-volumes",
		"privilege-escalation", "seccomp-profile", "apparmor-profile",
		"selinux-options", "proc-mount", "unsafe-sysctls",
		"runtime-class", "share-process-namespace", "ephemeral-container-policy",
		// Phase 2 — Image (9)
		"image-tag-latest", "image-tag-missing", "image-no-digest",
		"image-pull-policy", "image-registry-allowlist", "image-registry-blocklist",
		"image-signature-verification", "image-sbom-attestation", "image-provenance",
		// Phase 2 — RBAC (15)
		"default-service-account", "automount-token", "token-projection-config",
		"rbac-wildcard-verbs", "rbac-wildcard-resources", "rbac-wildcard-apigroups",
		"rbac-escalation-verbs", "rbac-secret-access", "rbac-exec-access",
		"rbac-log-access", "rbac-cluster-admin", "rbac-unused-roles",
		"rbac-group-bindings", "rbac-subject-external", "cloud-iam-binding",
		// Phase 2 — Secrets (7)
		"secrets-in-env", "secrets-unencrypted", "secrets-in-configmap",
		"secrets-default-type", "secrets-stale", "secrets-hardcoded-manifests",
		"external-secrets-sync",
		// Phase 2 — Network (12)
		"network-policy-missing", "network-policy-default-deny",
		"network-policy-overly-permissive", "network-policy-egress-unrestricted",
		"ingress-no-tls", "ingress-wildcard-host", "ingress-class-missing",
		"service-type-loadbalancer", "service-type-nodeport",
		"external-ips", "service-mesh-mtls", "dns-security",
		// Phase 2 — PSA (6)
		"psa-labels-missing", "psa-mode-audit-only", "psa-baseline-violations",
		"psa-restricted-violations", "psa-version-pinning", "psp-still-present",
		// Phase 2 — Scheduling (8)
		"toleration-control-plane", "toleration-all",
		"priority-class-system", "priority-class-missing",
		"pod-disruption-budget", "topology-spread",
		"node-affinity-untrusted", "hpa-without-requests",
		// Phase 2 — Storage (5)
		"pvc-no-encryption", "pvc-reclaim-retain", "csi-driver-security",
		"emptydir-size-limit", "projected-volume-security",
		// Phase 2 — Cluster Configuration (10)
		"namespace-default-usage", "limit-range-missing", "resource-quota-missing",
		"api-server-anonymous", "audit-logging", "admission-controllers",
		"etcd-encryption", "kubelet-config", "component-versions", "deprecated-api-usage",
		// Phase 2 — Supply Chain (5)
		"container-runtime-socket", "liveness-readiness-probes", "startup-probes",
		"lifecycle-hooks", "image-age",
		// Phase 2 — Cloud Provider (4)
		"eks-imds-access", "gke-metadata-concealment", "aks-pod-identity",
		"cloud-provider-detection",
		// Phase 2 — CRD Security (4)
		"crd-validation-missing", "crd-conversion-webhook",
		"cert-manager-expiry", "cert-manager-insecure",
	}
}

// TestMITRETechniqueIDsValid guards against a fabricated or mistyped MITRE
// ATT&CK technique ID slipping into the mappings — the MITRE analogue of
// TestCISControlIDsValid, which the framework lacked. The allowlist is the set
// of real ATT&CK for Containers v14 techniques the project maps to; adding a new
// mapping requires adding its (real) technique ID here deliberately.
func TestMITRETechniqueIDsValid(t *testing.T) {
	validTechniques := map[string]bool{
		"T1006": true, "T1040": true, "T1046": true, "T1048": true,
		"T1057": true, "T1059": true, "T1068": true, "T1071": true,
		"T1071.004": true, "T1078": true, "T1078.001": true, "T1078.004": true,
		"T1190": true, "T1195": true, "T1195.002": true, "T1203": true,
		"T1485": true, "T1489": true, "T1499": true, "T1525": true,
		"T1528": true, "T1530": true, "T1552": true, "T1552.001": true,
		"T1552.005": true, "T1552.007": true, "T1557": true, "T1562": true,
		"T1562.008": true, "T1565.001": true, "T1567": true, "T1580": true,
		"T1584.001": true, "T1609": true, "T1610": true, "T1611": true,
	}
	for checkName, refs := range mitreMappings() {
		for _, ref := range refs {
			if !validTechniques[ref.ControlID] {
				t.Errorf("check %q uses unrecognized MITRE technique ID %q (title: %q) — add it to the allowlist only if it is a real ATT&CK technique", checkName, ref.ControlID, ref.Title)
			}
			assert.Equal(t, "mitre", ref.Framework, "check %q: framework should be mitre", checkName)
			assert.NotEmpty(t, ref.Title, "check %q: MITRE title should not be empty", checkName)
			assert.NotEqual(t, ref.ControlID, ref.Title, "check %q: MITRE title must be the technique name, not the ID repeated", checkName)
		}
	}
}

// TestNSASectionIDsValid guards against a fabricated NSA/CISA Kubernetes
// Hardening Guide v1.2 section ID.
func TestNSASectionIDsValid(t *testing.T) {
	validSections := map[string]bool{
		"1.1": true, "1.2": true, "1.3": true, "1.4": true, "1.5": true,
		"2.1": true,
		"3.1": true, "3.2": true,
		"4.1": true, "4.2": true, "4.3": true,
		"5.1": true, "5.2": true,
		"6.1": true,
		"7.1": true,
	}
	for checkName, refs := range nsaMappings() {
		for _, ref := range refs {
			if !validSections[ref.ControlID] {
				t.Errorf("check %q uses unrecognized NSA/CISA v1.2 section %q (title: %q)", checkName, ref.ControlID, ref.Title)
			}
			assert.Equal(t, "nsa", ref.Framework, "check %q: framework should be nsa", checkName)
			assert.NotEmpty(t, ref.Title, "check %q: NSA title should not be empty", checkName)
			assert.NotEqual(t, ref.ControlID, ref.Title, "check %q: NSA title must be the section name, not the ID repeated", checkName)
		}
	}
}
