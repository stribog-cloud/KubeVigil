package frameworks

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	registerMapper(nsaMappings)
}

// nsaMappings returns NSA/CISA Kubernetes Hardening Guide v1.2 mappings for all checks.
func nsaMappings() map[string][]checker.FrameworkRef {
	return nsaMappingData
}

// nsa creates a FrameworkRef for an NSA/CISA Kubernetes Hardening Guide section.
func nsa(sectionID, title string) checker.FrameworkRef {
	return checker.FrameworkRef{
		Framework: "nsa",
		Version:   "1.2",
		ControlID: sectionID,
		Title:     title,
	}
}

var nsaMappingData = map[string][]checker.FrameworkRef{
	// Phase 1 — Workload (25)
	"privileged":                 {nsa("1.1", "Non-root containers"), nsa("2.1", "Pod security enforcement")},
	"capabilities-added":         {nsa("1.1", "Non-root containers"), nsa("2.1", "Pod security enforcement")},
	"capabilities-not-dropped":   {nsa("1.1", "Non-root containers")},
	"run-as-root":                {nsa("1.1", "Non-root containers")},
	"run-as-high-uid":            {nsa("1.1", "Non-root containers")},
	"run-as-group":               {nsa("1.1", "Non-root containers")},
	"read-only-rootfs":           {nsa("1.2", "Immutable container filesystems")},
	"resource-limits-missing":    {nsa("1.5", "Resource requests and limits")},
	"resource-requests-missing":  {nsa("1.5", "Resource requests and limits")},
	"resource-limits-ratio":      {nsa("1.5", "Resource requests and limits")},
	"ephemeral-storage-limits":   {nsa("1.5", "Resource requests and limits")},
	"host-pid":                   {nsa("1.3", "Minimized host resource access")},
	"host-ipc":                   {nsa("1.3", "Minimized host resource access")},
	"host-network":               {nsa("1.3", "Minimized host resource access"), nsa("4.1", "Network separation")},
	"host-ports":                 {nsa("1.3", "Minimized host resource access")},
	"host-path-volumes":          {nsa("1.3", "Minimized host resource access")},
	"privilege-escalation":       {nsa("1.1", "Non-root containers"), nsa("2.1", "Pod security enforcement")},
	"seccomp-profile":            {nsa("2.1", "Pod security enforcement")},
	"apparmor-profile":           {nsa("2.1", "Pod security enforcement")},
	"selinux-options":            {nsa("2.1", "Pod security enforcement")},
	"proc-mount":                 {nsa("1.3", "Minimized host resource access")},
	"unsafe-sysctls":             {nsa("2.1", "Pod security enforcement")},
	"runtime-class":              {nsa("2.1", "Pod security enforcement")},
	"share-process-namespace":    {nsa("1.3", "Minimized host resource access")},
	"ephemeral-container-policy": {nsa("2.1", "Pod security enforcement")},

	// Phase 2 — Image (9)
	"image-tag-latest":             {nsa("1.4", "Trusted container images")},
	"image-tag-missing":            {nsa("1.4", "Trusted container images")},
	"image-no-digest":              {nsa("1.4", "Trusted container images")},
	"image-pull-policy":            {nsa("1.4", "Trusted container images")},
	"image-registry-allowlist":     {nsa("1.4", "Trusted container images")},
	"image-registry-blocklist":     {nsa("1.4", "Trusted container images")},
	"image-signature-verification": {nsa("1.4", "Trusted container images")},
	"image-sbom-attestation":       {nsa("1.4", "Trusted container images")},
	"image-provenance":             {nsa("1.4", "Trusted container images")},

	// Phase 2 — RBAC (15)
	"default-service-account": {nsa("3.1", "RBAC policies"), nsa("3.2", "Service account management")},
	"automount-token":         {nsa("3.2", "Service account management")},
	"token-projection-config": {nsa("3.2", "Service account management")},
	"rbac-wildcard-verbs":     {nsa("3.1", "RBAC policies")},
	"rbac-wildcard-resources": {nsa("3.1", "RBAC policies")},
	"rbac-wildcard-apigroups": {nsa("3.1", "RBAC policies")},
	"rbac-escalation-verbs":   {nsa("3.1", "RBAC policies")},
	"rbac-secret-access":      {nsa("3.1", "RBAC policies"), nsa("5.1", "Secrets management")},
	"rbac-exec-access":        {nsa("3.1", "RBAC policies")},
	"rbac-log-access":         {nsa("3.1", "RBAC policies")},
	"rbac-cluster-admin":      {nsa("3.1", "RBAC policies")},
	"rbac-unused-roles":       {nsa("3.1", "RBAC policies")},
	"rbac-group-bindings":     {nsa("3.1", "RBAC policies")},
	"rbac-subject-external":   {nsa("3.1", "RBAC policies")},
	"cloud-iam-binding":       {nsa("3.1", "RBAC policies"), nsa("3.2", "Service account management")},

	// Phase 2 — Secrets (7)
	"secrets-in-env":              {nsa("5.1", "Secrets management")},
	"secrets-unencrypted":         {nsa("5.1", "Secrets management"), nsa("5.2", "Encryption at rest")},
	"secrets-in-configmap":        {nsa("5.1", "Secrets management")},
	"secrets-default-type":        {nsa("5.1", "Secrets management")},
	"secrets-stale":               {nsa("5.1", "Secrets management")},
	"secrets-hardcoded-manifests": {nsa("5.1", "Secrets management")},
	"external-secrets-sync":       {nsa("5.1", "Secrets management")},

	// Phase 2 — Network (12)
	"network-policy-missing":             {nsa("4.1", "Network separation"), nsa("4.2", "Network policy enforcement")},
	"network-policy-default-deny":        {nsa("4.2", "Network policy enforcement")},
	"network-policy-overly-permissive":   {nsa("4.2", "Network policy enforcement")},
	"network-policy-egress-unrestricted": {nsa("4.2", "Network policy enforcement")},
	"ingress-no-tls":                     {nsa("4.3", "TLS encryption")},
	"ingress-wildcard-host":              {nsa("4.1", "Network separation")},
	"ingress-class-missing":              {nsa("4.1", "Network separation")},
	"service-type-loadbalancer":          {nsa("4.1", "Network separation")},
	"service-type-nodeport":              {nsa("4.1", "Network separation")},
	"external-ips":                       {nsa("4.1", "Network separation")},
	"service-mesh-mtls":                  {nsa("4.3", "TLS encryption")},
	"dns-security":                       {nsa("4.1", "Network separation")},

	// Phase 2 — PSA (6)
	"psa-labels-missing":        {nsa("2.1", "Pod security enforcement")},
	"psa-mode-audit-only":       {nsa("2.1", "Pod security enforcement")},
	"psa-baseline-violations":   {nsa("2.1", "Pod security enforcement")},
	"psa-restricted-violations": {nsa("2.1", "Pod security enforcement")},
	"psa-version-pinning":       {nsa("2.1", "Pod security enforcement")},
	"psp-still-present":         {nsa("2.1", "Pod security enforcement")},

	// Phase 2 — Scheduling (8)
	"toleration-control-plane": {nsa("1.3", "Minimized host resource access")},
	"toleration-all":           {nsa("1.3", "Minimized host resource access")},
	"priority-class-system":    {nsa("1.5", "Resource requests and limits")},
	"priority-class-missing":   {nsa("1.5", "Resource requests and limits")},
	"pod-disruption-budget":    {nsa("1.5", "Resource requests and limits")},
	"topology-spread":          {nsa("1.5", "Resource requests and limits")},
	"node-affinity-untrusted":  {nsa("1.3", "Minimized host resource access")},
	"hpa-without-requests":     {nsa("1.5", "Resource requests and limits")},

	// Phase 2 — Storage (5)
	"pvc-no-encryption":         {nsa("5.2", "Encryption at rest")},
	"pvc-reclaim-retain":        {nsa("5.1", "Secrets management")},
	"csi-driver-security":       {nsa("1.3", "Minimized host resource access")},
	"emptydir-size-limit":       {nsa("1.5", "Resource requests and limits")},
	"projected-volume-security": {nsa("5.1", "Secrets management")},

	// Phase 2 — Cluster Configuration (10)
	"namespace-default-usage": {nsa("3.1", "RBAC policies")},
	"limit-range-missing":     {nsa("1.5", "Resource requests and limits")},
	"resource-quota-missing":  {nsa("1.5", "Resource requests and limits")},
	"api-server-anonymous":    {nsa("3.1", "RBAC policies")},
	"audit-logging":           {nsa("6.1", "Audit logging")},
	"admission-controllers":   {nsa("2.1", "Pod security enforcement")},
	"etcd-encryption":         {nsa("5.2", "Encryption at rest")},
	"kubelet-config":          {nsa("3.1", "RBAC policies")},
	"component-versions":      {nsa("7.1", "Upgrade and patching")},
	"deprecated-api-usage":    {nsa("7.1", "Upgrade and patching")},

	// Phase 2 — Supply Chain (5)
	"container-runtime-socket":  {nsa("1.3", "Minimized host resource access")},
	"liveness-readiness-probes": {nsa("1.5", "Resource requests and limits")},
	"startup-probes":            {nsa("1.5", "Resource requests and limits")},
	"lifecycle-hooks":           {nsa("1.3", "Minimized host resource access")},
	"image-age":                 {nsa("1.4", "Trusted container images")},

	// Phase 2 — Cloud Provider (4)
	"eks-imds-access":          {nsa("3.2", "Service account management")},
	"gke-metadata-concealment": {nsa("3.2", "Service account management")},
	"aks-pod-identity":         {nsa("3.2", "Service account management")},
	"cloud-provider-detection": {nsa("7.1", "Upgrade and patching")},

	// Phase 2 — CRD Security (4)
	"crd-validation-missing": {nsa("2.1", "Pod security enforcement")},
	"crd-conversion-webhook": {nsa("2.1", "Pod security enforcement")},
	"cert-manager-expiry":    {nsa("4.3", "TLS encryption")},
	"cert-manager-insecure":  {nsa("4.3", "TLS encryption")},

	// v1.3.0
	"rbac-node-proxy-access":                   {nsa("3.1", "RBAC policies")},
	"rbac-csr-approval":                        {nsa("3.1", "RBAC policies")},
	"rbac-webhook-tampering":                   {nsa("2.1", "Pod security enforcement")},
	"rbac-token-request":                       {nsa("3.1", "RBAC policies")},
	"rbac-crossnamespace-serviceaccount":       {nsa("3.1", "RBAC policies")},
	"rbac-deletecollection-broad":              {nsa("3.1", "RBAC policies")},
	"rbac-aggregation-label-injection":         {nsa("3.1", "RBAC policies")},
	"validatingwebhook-failure-policy-ignore":  {nsa("2.1", "Pod security enforcement")},
	"mutatingwebhook-wildcard-scope":           {nsa("2.1", "Pod security enforcement")},
	"windows-hostprocess":                      {nsa("1.1", "Non-root containers")},
	"serviceaccount-token-manual-volume-mount": {nsa("3.2", "Service account management")},
	"csi-inline-ephemeral-volume":              {nsa("1.3", "minimized host resource access")},
	"serviceaccount-token-secret-legacy":       {nsa("3.2", "Service account management")},
}
