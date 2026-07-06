package frameworks

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	registerMapper(cisMappings)
}

// cisMappings returns CIS Kubernetes Benchmark v1.8 control mappings for all checks.
func cisMappings() map[string][]checker.FrameworkRef {
	return cisMappingData
}

// cis creates a FrameworkRef for a CIS Kubernetes Benchmark v1.8 control.
func cis(controlID, title string) checker.FrameworkRef {
	return checker.FrameworkRef{
		Framework: "cis",
		Version:   "1.8",
		ControlID: controlID,
		Title:     title,
	}
}

// CIS Kubernetes Benchmark v1.8 control ID reference:
//
// Section 1.2 — API Server:
//   1.2.1   --anonymous-auth set to false
//   1.2.11  AlwaysPullImages admission plugin
//   1.2.17  --audit-log-path set
//   1.2.18  --audit-log-maxage set to 30 or appropriate
//   1.2.28  --encryption-provider-config set
//   1.2.29  Encryption providers appropriately configured
//
// Section 4.2 — Kubelet:
//   4.2.1   --anonymous-auth set to false
//
// Section 5.1 — RBAC and Service Accounts:
//   5.1.1   cluster-admin role only used where required
//   5.1.2   Minimize access to secrets
//   5.1.3   Minimize wildcard use in Roles/ClusterRoles
//   5.1.5   Default service accounts not actively used
//   5.1.6   Service Account Tokens only mounted where necessary
//   5.1.7   Avoid use of system:masters group
//   5.1.8   Limit Bind/Impersonate/Escalate permissions
//
// Section 5.2 — Pod Security Standards:
//   5.2.1   At least one active policy control mechanism
//   5.2.2   Minimize admission of privileged containers
//   5.2.3   Minimize admission of containers sharing host PID namespace
//   5.2.4   Minimize admission of containers sharing host IPC namespace
//   5.2.5   Minimize admission of containers sharing host network namespace
//   5.2.6   Minimize admission of containers with allowPrivilegeEscalation
//   5.2.7   Minimize admission of root containers
//   5.2.8   Minimize admission of containers with NET_RAW capability
//   5.2.9   Minimize admission of containers with added capabilities
//   5.2.10  Minimize admission of containers with capabilities assigned
//   5.2.12  Minimize admission of HostPath volumes
//   5.2.13  Minimize admission of containers which use HostPorts
//
// Section 5.3 — Network Policies and CNI:
//   5.3.1   CNI supports Network Policies
//   5.3.2   All Namespaces have Network Policies defined
//
// Section 5.4 — Secrets Management:
//   5.4.1   Prefer secrets as files over environment variables
//   5.4.2   Consider external secret storage
//
// Section 5.5 — Extensible Admission Control:
//   5.5.1   Image Provenance via ImagePolicyWebhook
//
// Section 5.6 — General Policies:
//   5.6.1   Administrative boundaries using namespaces
//   5.6.2   Seccomp profile set to docker/default
//   5.6.3   Apply Security Context to Pods and Containers
//   5.6.4   Default namespace should not be used

var cisMappingData = map[string][]checker.FrameworkRef{
	// Phase 1 — Workload (25)
	"privileged":                 {cis("5.2.2", "Minimize the admission of privileged containers")},
	"capabilities-added":         {cis("5.2.9", "Minimize the admission of containers with added capabilities"), cis("5.2.10", "Minimize the admission of containers with capabilities assigned")},
	"capabilities-not-dropped":   {cis("5.2.8", "Minimize the admission of containers with the NET_RAW capability"), cis("5.2.10", "Minimize the admission of containers with capabilities assigned")},
	"run-as-root":                {cis("5.2.7", "Minimize the admission of root containers")},
	"run-as-high-uid":            {cis("5.2.7", "Minimize the admission of root containers")},
	"run-as-group":               {cis("5.2.7", "Minimize the admission of root containers")},
	"read-only-rootfs":           {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"resource-limits-missing":    {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"resource-requests-missing":  {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"resource-limits-ratio":      {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"ephemeral-storage-limits":   {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"host-pid":                   {cis("5.2.3", "Minimize the admission of containers wishing to share the host process ID namespace")},
	"host-ipc":                   {cis("5.2.4", "Minimize the admission of containers wishing to share the host IPC namespace")},
	"host-network":               {cis("5.2.5", "Minimize the admission of containers wishing to share the host network namespace")},
	"host-ports":                 {cis("5.2.13", "Minimize the admission of containers which use HostPorts")},
	"host-path-volumes":          {cis("5.2.12", "Minimize the admission of HostPath volumes")},
	"privilege-escalation":       {cis("5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation")},
	"seccomp-profile":            {cis("5.6.2", "Ensure that the seccomp profile is set to docker/default in your pod definitions")},
	"apparmor-profile":           {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"selinux-options":            {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"proc-mount":                 {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"unsafe-sysctls":             {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"runtime-class":              {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"share-process-namespace":    {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"ephemeral-container-policy": {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},

	// Phase 2 — Image (9)
	"image-tag-latest":             {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-tag-missing":            {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-no-digest":              {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-pull-policy":            {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-registry-allowlist":     {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-registry-blocklist":     {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-signature-verification": {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-sbom-attestation":       {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"image-provenance":             {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},

	// Phase 2 — RBAC (15)
	"default-service-account": {cis("5.1.5", "Ensure that default service accounts are not actively used"), cis("5.1.6", "Ensure that Service Account Tokens are only mounted where necessary")},
	"automount-token":         {cis("5.1.6", "Ensure that Service Account Tokens are only mounted where necessary")},
	"token-projection-config": {cis("5.1.6", "Ensure that Service Account Tokens are only mounted where necessary")},
	"rbac-wildcard-verbs":     {cis("5.1.1", "Ensure that the cluster-admin role is only used where required"), cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles")},
	"rbac-wildcard-resources": {cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles")},
	"rbac-wildcard-apigroups": {cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles")},
	"rbac-escalation-verbs":   {cis("5.1.1", "Ensure that the cluster-admin role is only used where required"), cis("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster")},
	"rbac-secret-access":      {cis("5.1.2", "Minimize access to secrets")},
	"rbac-exec-access":        {cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},
	"rbac-log-access":         {cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},
	"rbac-cluster-admin":      {cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},
	"rbac-unused-roles":       {cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},
	"rbac-group-bindings":     {cis("5.1.7", "Avoid use of system:masters group"), cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},
	"rbac-subject-external":   {cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},
	"cloud-iam-binding":       {cis("5.1.1", "Ensure that the cluster-admin role is only used where required")},

	// Phase 2 — Secrets (7)
	"secrets-in-env":              {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables"), cis("5.4.2", "Consider external secret storage")},
	"secrets-unencrypted":         {cis("1.2.28", "Ensure that the --encryption-provider-config argument is set as appropriate"), cis("1.2.29", "Ensure that encryption providers are appropriately configured")},
	"secrets-in-configmap":        {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
	"secrets-default-type":        {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
	"secrets-stale":               {cis("5.4.2", "Consider external secret storage")},
	"secrets-hardcoded-manifests": {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
	"external-secrets-sync":       {cis("5.4.2", "Consider external secret storage")},

	// Phase 2 — Network (12)
	"network-policy-missing":             {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"network-policy-default-deny":        {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"network-policy-overly-permissive":   {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"network-policy-egress-unrestricted": {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"ingress-no-tls":                     {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"ingress-wildcard-host":              {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"ingress-class-missing":              {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"service-type-loadbalancer":          {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"service-type-nodeport":              {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"external-ips":                       {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"service-mesh-mtls":                  {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"dns-security":                       {cis("5.3.1", "Ensure that the CNI in use supports Network Policies")},

	// Phase 2 — PSA (6)
	"psa-labels-missing":        {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},
	"psa-mode-audit-only":       {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},
	"psa-baseline-violations":   {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},
	"psa-restricted-violations": {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},
	"psa-version-pinning":       {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},
	"psp-still-present":         {cis("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place")},

	// Phase 2 — Scheduling (8)
	"toleration-control-plane": {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"toleration-all":           {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"priority-class-system":    {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"priority-class-missing":   {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"pod-disruption-budget":    {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"topology-spread":          {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"node-affinity-untrusted":  {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"hpa-without-requests":     {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},

	// Phase 2 — Storage (5)
	"pvc-no-encryption":         {cis("5.4.2", "Consider external secret storage")},
	"pvc-reclaim-retain":        {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"csi-driver-security":       {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"emptydir-size-limit":       {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"projected-volume-security": {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},

	// Phase 2 — Cluster Configuration (10)
	"namespace-default-usage": {cis("5.6.4", "The default namespace should not be used")},
	"limit-range-missing":     {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"resource-quota-missing":  {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"api-server-anonymous":    {cis("1.2.1", "Ensure that the --anonymous-auth argument is set to false")},
	"audit-logging":           {cis("1.2.17", "Ensure that the --audit-log-path argument is set"), cis("1.2.18", "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate")},
	"admission-controllers":   {cis("1.2.11", "Ensure that the admission control plugin AlwaysPullImages is set")},
	"etcd-encryption":         {cis("1.2.28", "Ensure that the --encryption-provider-config argument is set as appropriate"), cis("1.2.29", "Ensure that encryption providers are appropriately configured")},
	"kubelet-config":          {cis("4.2.1", "Ensure that the --anonymous-auth argument is set to false")},
	"component-versions":      {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"deprecated-api-usage":    {cis("5.6.1", "Create administrative boundaries between resources using namespaces")},

	// Phase 2 — Supply Chain (5)
	"container-runtime-socket":  {cis("5.2.12", "Minimize the admission of HostPath volumes")},
	"liveness-readiness-probes": {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"startup-probes":            {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"lifecycle-hooks":           {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"image-age":                 {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},

	// Phase 2 — Cloud Provider (4)
	"eks-imds-access":          {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"gke-metadata-concealment": {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"aks-pod-identity":         {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"cloud-provider-detection": {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},

	// Phase 2 — CRD Security (4)
	"crd-validation-missing": {cis("5.6.3", "Apply Security Context to Your Pods and Containers")},
	"crd-conversion-webhook": {cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller")},
	"cert-manager-expiry":    {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
	"cert-manager-insecure":  {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},

	// v1.3.0
	"network-policy-empty-namespace-selector": {cis("5.3.2", "Ensure that all Namespaces have Network Policies defined")},
	"secrets-envfrom-bulk":                    {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
	"secrets-tls-weak-key":                    {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
	"secrets-in-annotations":                  {cis("5.4.1", "Prefer using secrets as files over secrets as environment variables")},
}
