package mcp

// defaultSeverities maps each checker ID to its default (worst-case) severity.
// This is sourced from the hardcoded Severity field in each checker's Finding
// construction. For checkers with variable severity (e.g., host-path-volumes),
// the worst-case severity is used.
//
// This map is the single source of truth for the list_checks tool's severity
// reporting. When a new checker is added, its severity MUST be added here.
var defaultSeverities = map[string]string{
	// Workload checks
	"privileged":                 "Critical",
	"host-pid":                   "Critical",
	"host-ipc":                   "Critical",
	"host-network":               "Critical",
	"host-path-volumes":          "Critical", // variable: Critical/High/Medium by path
	"host-ports":                 "High",
	"privilege-escalation":       "High",
	"run-as-root":                "High",
	"capabilities-added":         "High",
	"proc-mount":                 "High",
	"unsafe-sysctls":             "High",
	"capabilities-not-dropped":   "Medium",
	"read-only-rootfs":           "Medium",
	"seccomp-profile":            "Medium",
	"apparmor-profile":           "Medium",
	"selinux-options":            "Medium",
	"run-as-group":               "Medium",
	"share-process-namespace":    "Medium",
	"resource-limits-missing":    "Medium",
	"resource-requests-missing":  "Medium",
	"ephemeral-container-policy": "Medium",
	"resource-limits-ratio":      "Low",
	"run-as-high-uid":            "Low",
	"ephemeral-storage-limits":   "Low",
	"runtime-class":              "Low",

	// Image checks
	"image-tag-latest":             "Medium",
	"image-tag-missing":            "Medium",
	"image-pull-policy":            "Medium",
	"image-signature-verification": "Medium",
	"image-registry-allowlist":     "High",
	"image-registry-blocklist":     "Critical",
	"image-no-digest":              "Low",
	"image-provenance":             "Low",
	"image-sbom-attestation":       "Low",

	// RBAC checks
	"rbac-cluster-admin":      "Critical",
	"rbac-wildcard-verbs":     "Critical",
	"rbac-wildcard-resources": "Critical",
	"rbac-wildcard-apigroups": "Critical",
	"rbac-escalation-verbs":   "Critical",
	"default-service-account": "High",
	"automount-token":         "High",
	"rbac-exec-access":        "High",
	"rbac-secret-access":      "High",
	"rbac-group-bindings":     "High",
	"rbac-log-access":         "Medium",
	"token-projection-config": "Medium",
	"cloud-iam-binding":       "Medium",
	"rbac-unused-roles":       "Info",
	"rbac-subject-external":   "Low",

	// Network checks
	"network-policy-missing":             "High",
	"network-policy-default-deny":        "High",
	"ingress-no-tls":                     "High",
	"external-ips":                       "High",
	"service-mesh-mtls":                  "High",
	"network-policy-egress-unrestricted": "Medium",
	"network-policy-overly-permissive":   "Medium",
	"ingress-wildcard-host":              "Medium",
	"service-type-nodeport":              "Medium",
	"service-type-loadbalancer":          "Medium",
	"dns-security":                       "Medium",
	"ingress-class-missing":              "Low",

	// Cluster checks
	"etcd-encryption":         "Critical",
	"audit-logging":           "High",
	"api-server-anonymous":    "High",
	"kubelet-config":          "High",
	"component-versions":      "Medium",
	"namespace-default-usage": "Medium",
	"deprecated-api-usage":    "Medium",
	"admission-controllers":   "Medium",
	"resource-quota-missing":  "Low",
	"limit-range-missing":     "Low",

	// PSA checks
	"psa-baseline-violations":   "High",
	"psa-labels-missing":        "Medium",
	"psa-mode-audit-only":       "Medium",
	"psa-restricted-violations": "Medium",
	"psa-version-pinning":       "Low",
	"psp-still-present":         "Info",

	// Secrets checks
	"secrets-unencrypted":         "Critical",
	"secrets-in-configmap":        "High",
	"secrets-hardcoded-manifests": "High",
	"secrets-in-env":              "Medium",
	"secrets-stale":               "Medium",
	"external-secrets-sync":       "Medium",
	"secrets-default-type":        "Low",

	// Storage checks
	"pvc-no-encryption":         "Medium",
	"pvc-reclaim-retain":        "Medium",
	"projected-volume-security": "Medium",
	"emptydir-size-limit":       "Low",
	"csi-driver-security":       "Low",

	// CRD checks
	"cert-manager-expiry":    "High",
	"crd-conversion-webhook": "High",
	"crd-validation-missing": "Medium",
	"cert-manager-insecure":  "Medium",

	// Cloud checks
	"eks-imds-access":          "High",
	"gke-metadata-concealment": "High",
	"aks-pod-identity":         "Medium",
	"cloud-provider-detection": "Info",

	// Supply chain checks
	"container-runtime-socket":  "Critical",
	"startup-probes":            "Info",
	"liveness-readiness-probes": "Low",
	"lifecycle-hooks":           "Low",
	"image-age":                 "Low",

	// Scheduling checks
	"toleration-control-plane": "High",
	"priority-class-system":    "High",
	"hpa-without-requests":     "Medium",
	"toleration-all":           "Medium",
	"node-affinity-untrusted":  "Medium",
	"priority-class-missing":   "Low",
	"topology-spread":          "Low",
	"pod-disruption-budget":    "Low",
}
