package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"

	// Import checker packages to trigger init() registration.
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
)

// TestAllCheckersContract exercises the contract test against ALL registered checkers.
// This test imports all checker packages to ensure their init() functions run.
func TestAllCheckersContract(t *testing.T) {
	checkers := checker.DefaultRegistry().All()
	require.NotEmpty(t, checkers, "expected at least one checker to be registered")

	helpers.RunCheckerContractTests(t, checkers)
}

// TestCheckerRegistration verifies ALL expected checkers are registered.
func TestCheckerRegistration(t *testing.T) {
	registry := checker.DefaultRegistry()

	expected := []string{
		// Phase 1 — Workload (25)
		"privileged",
		"capabilities-added",
		"capabilities-not-dropped",
		"run-as-root",
		"run-as-high-uid",
		"run-as-group",
		"read-only-rootfs",
		"resource-limits-missing",
		"resource-requests-missing",
		"resource-limits-ratio",
		"ephemeral-storage-limits",
		"host-pid",
		"host-ipc",
		"host-network",
		"host-ports",
		"host-path-volumes",
		"privilege-escalation",
		"seccomp-profile",
		"apparmor-profile",
		"selinux-options",
		"proc-mount",
		"unsafe-sysctls",
		"runtime-class",
		"share-process-namespace",
		"ephemeral-container-policy",
		// Phase 2 — Image (9)
		"image-tag-latest",
		"image-tag-missing",
		"image-no-digest",
		"image-pull-policy",
		"image-registry-allowlist",
		"image-registry-blocklist",
		"image-signature-verification",
		"image-sbom-attestation",
		"image-provenance",
		// Phase 2 — RBAC (15)
		"default-service-account",
		"automount-token",
		"token-projection-config",
		"rbac-wildcard-verbs",
		"rbac-wildcard-resources",
		"rbac-wildcard-apigroups",
		"rbac-escalation-verbs",
		"rbac-secret-access",
		"rbac-exec-access",
		"rbac-log-access",
		"rbac-cluster-admin",
		"rbac-unused-roles",
		"rbac-group-bindings",
		"rbac-subject-external",
		"cloud-iam-binding",
		// Phase 2 — Secrets (7)
		"secrets-in-env",
		"secrets-unencrypted",
		"secrets-in-configmap",
		"secrets-default-type",
		"secrets-stale",
		"secrets-hardcoded-manifests",
		"external-secrets-sync",
		// Phase 2 — Network (12)
		"network-policy-missing",
		"network-policy-default-deny",
		"network-policy-overly-permissive",
		"network-policy-egress-unrestricted",
		"ingress-no-tls",
		"ingress-wildcard-host",
		"ingress-class-missing",
		"service-type-loadbalancer",
		"service-type-nodeport",
		"external-ips",
		"service-mesh-mtls",
		"dns-security",
		// Phase 2 — PSA (6)
		"psa-labels-missing",
		"psa-mode-audit-only",
		"psa-baseline-violations",
		"psa-restricted-violations",
		"psa-version-pinning",
		"psp-still-present",
		// Phase 2 — Scheduling (8)
		"toleration-control-plane",
		"toleration-all",
		"priority-class-system",
		"priority-class-missing",
		"pod-disruption-budget",
		"topology-spread",
		"node-affinity-untrusted",
		"hpa-without-requests",
		// Phase 2 — Storage (5)
		"pvc-no-encryption",
		"pvc-reclaim-retain",
		"csi-driver-security",
		"emptydir-size-limit",
		"projected-volume-security",
		// Phase 2 — Cluster Configuration (10)
		"namespace-default-usage",
		"limit-range-missing",
		"resource-quota-missing",
		"api-server-anonymous",
		"audit-logging",
		"admission-controllers",
		"etcd-encryption",
		"kubelet-config",
		"component-versions",
		"deprecated-api-usage",
		// Phase 2 — Supply Chain (5)
		"container-runtime-socket",
		"liveness-readiness-probes",
		"startup-probes",
		"lifecycle-hooks",
		"image-age",
		// Phase 2 — Cloud Provider (4)
		"eks-imds-access",
		"gke-metadata-concealment",
		"aks-pod-identity",
		"cloud-provider-detection",
		// Phase 2 — CRD Security (4)
		"crd-validation-missing",
		"crd-conversion-webhook",
		"cert-manager-expiry",
		"cert-manager-insecure",
	}

	require.Equal(t, 110, registry.Len(), "expected exactly 110 checkers to be registered")

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			c, ok := registry.Get(name)
			require.True(t, ok, "checker %q should be registered", name)
			require.NotNil(t, c)
		})
	}
}
