package frameworks

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	registerMapper(mitreMappings)
}

// mitreMappings returns MITRE ATT&CK for Containers v14 mappings for all checks.
func mitreMappings() map[string][]checker.FrameworkRef {
	return mitreMappingData
}

// mitre creates a FrameworkRef for a MITRE ATT&CK technique.
func mitre(techniqueID, title string) checker.FrameworkRef {
	return checker.FrameworkRef{
		Framework: "mitre",
		Version:   "v14",
		ControlID: techniqueID,
		Title:     title,
	}
}

var mitreMappingData = map[string][]checker.FrameworkRef{
	// Phase 1 — Workload (25)
	"privileged":                 {mitre("T1611", "Escape to Host")},
	"capabilities-added":         {mitre("T1611", "Escape to Host"), mitre("T1068", "Exploitation for Privilege Escalation")},
	"capabilities-not-dropped":   {mitre("T1068", "Exploitation for Privilege Escalation")},
	"run-as-root":                {mitre("T1611", "Escape to Host")},
	"run-as-high-uid":            {mitre("T1068", "Exploitation for Privilege Escalation")},
	"run-as-group":               {mitre("T1068", "Exploitation for Privilege Escalation")},
	"read-only-rootfs":           {mitre("T1565.001", "Stored Data Manipulation")},
	"resource-limits-missing":    {mitre("T1499", "Endpoint Denial of Service")},
	"resource-requests-missing":  {mitre("T1499", "Endpoint Denial of Service")},
	"resource-limits-ratio":      {mitre("T1499", "Endpoint Denial of Service")},
	"ephemeral-storage-limits":   {mitre("T1499", "Endpoint Denial of Service")},
	"host-pid":                   {mitre("T1611", "Escape to Host"), mitre("T1057", "Process Discovery")},
	"host-ipc":                   {mitre("T1611", "Escape to Host")},
	"host-network":               {mitre("T1611", "Escape to Host"), mitre("T1040", "Network Sniffing")},
	"host-ports":                 {mitre("T1611", "Escape to Host")},
	"host-path-volumes":          {mitre("T1611", "Escape to Host"), mitre("T1006", "Direct Volume Access")},
	"privilege-escalation":       {mitre("T1068", "Exploitation for Privilege Escalation"), mitre("T1611", "Escape to Host")},
	"seccomp-profile":            {mitre("T1611", "Escape to Host")},
	"apparmor-profile":           {mitre("T1611", "Escape to Host")},
	"selinux-options":            {mitre("T1068", "Exploitation for Privilege Escalation")},
	"proc-mount":                 {mitre("T1611", "Escape to Host")},
	"unsafe-sysctls":             {mitre("T1611", "Escape to Host")},
	"runtime-class":              {mitre("T1611", "Escape to Host")},
	"share-process-namespace":    {mitre("T1057", "Process Discovery")},
	"ephemeral-container-policy": {mitre("T1610", "Deploy Container")},

	// Phase 2 — Image (9)
	"image-tag-latest":             {mitre("T1525", "Implant Internal Image")},
	"image-tag-missing":            {mitre("T1525", "Implant Internal Image")},
	"image-no-digest":              {mitre("T1525", "Implant Internal Image")},
	"image-pull-policy":            {mitre("T1525", "Implant Internal Image")},
	"image-registry-allowlist":     {mitre("T1525", "Implant Internal Image"), mitre("T1610", "Deploy Container")},
	"image-registry-blocklist":     {mitre("T1525", "Implant Internal Image"), mitre("T1610", "Deploy Container")},
	"image-signature-verification": {mitre("T1525", "Implant Internal Image")},
	"image-sbom-attestation":       {mitre("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain")},
	"image-provenance":             {mitre("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain")},

	// Phase 2 — RBAC (15)
	"default-service-account": {mitre("T1078.001", "Valid Accounts: Default Accounts")},
	"automount-token":         {mitre("T1552.007", "Unsecured Credentials: Container API")},
	"token-projection-config": {mitre("T1552.007", "Unsecured Credentials: Container API")},
	"rbac-wildcard-verbs":     {mitre("T1078", "Valid Accounts")},
	"rbac-wildcard-resources": {mitre("T1078", "Valid Accounts")},
	"rbac-wildcard-apigroups": {mitre("T1078", "Valid Accounts")},
	"rbac-escalation-verbs":   {mitre("T1078", "Valid Accounts"), mitre("T1068", "Exploitation for Privilege Escalation")},
	"rbac-secret-access":      {mitre("T1552", "Unsecured Credentials")},
	"rbac-exec-access":        {mitre("T1609", "Container Administration Command")},
	"rbac-log-access":         {mitre("T1530", "Data from Cloud Storage")},
	"rbac-cluster-admin":      {mitre("T1078", "Valid Accounts")},
	"rbac-unused-roles":       {mitre("T1078", "Valid Accounts")},
	"rbac-group-bindings":     {mitre("T1078", "Valid Accounts")},
	"rbac-subject-external":   {mitre("T1078", "Valid Accounts")},
	"cloud-iam-binding":       {mitre("T1078.004", "Valid Accounts: Cloud Accounts")},

	// Phase 2 — Secrets (7)
	"secrets-in-env":              {mitre("T1552", "Unsecured Credentials")},
	"secrets-unencrypted":         {mitre("T1552", "Unsecured Credentials")},
	"secrets-in-configmap":        {mitre("T1552", "Unsecured Credentials")},
	"secrets-default-type":        {mitre("T1552", "Unsecured Credentials")},
	"secrets-stale":               {mitre("T1552", "Unsecured Credentials")},
	"secrets-hardcoded-manifests": {mitre("T1552.001", "Unsecured Credentials: Credentials In Files")},
	"external-secrets-sync":       {mitre("T1552", "Unsecured Credentials")},

	// Phase 2 — Network (12)
	"network-policy-missing":             {mitre("T1046", "Network Service Discovery")},
	"network-policy-default-deny":        {mitre("T1046", "Network Service Discovery"), mitre("T1071", "Application Layer Protocol")},
	"network-policy-overly-permissive":   {mitre("T1046", "Network Service Discovery")},
	"network-policy-egress-unrestricted": {mitre("T1048", "Exfiltration Over Alternative Protocol")},
	"ingress-no-tls":                     {mitre("T1040", "Network Sniffing"), mitre("T1557", "Adversary-in-the-Middle")},
	"ingress-wildcard-host":              {mitre("T1190", "Exploit Public-Facing Application")},
	"ingress-class-missing":              {mitre("T1190", "Exploit Public-Facing Application")},
	"service-type-loadbalancer":          {mitre("T1190", "Exploit Public-Facing Application")},
	"service-type-nodeport":              {mitre("T1190", "Exploit Public-Facing Application")},
	"external-ips":                       {mitre("T1190", "Exploit Public-Facing Application")},
	"service-mesh-mtls":                  {mitre("T1040", "Network Sniffing"), mitre("T1557", "Adversary-in-the-Middle")},
	"dns-security":                       {mitre("T1071.004", "Application Layer Protocol: DNS")},

	// Phase 2 — PSA (6)
	"psa-labels-missing":        {mitre("T1610", "Deploy Container")},
	"psa-mode-audit-only":       {mitre("T1610", "Deploy Container")},
	"psa-baseline-violations":   {mitre("T1611", "Escape to Host")},
	"psa-restricted-violations": {mitre("T1611", "Escape to Host")},
	"psa-version-pinning":       {mitre("T1610", "Deploy Container")},
	"psp-still-present":         {mitre("T1610", "Deploy Container")},

	// Phase 2 — Scheduling (8)
	"toleration-control-plane": {mitre("T1611", "Escape to Host")},
	"toleration-all":           {mitre("T1610", "Deploy Container")},
	"priority-class-system":    {mitre("T1499", "Endpoint Denial of Service")},
	"priority-class-missing":   {mitre("T1499", "Endpoint Denial of Service")},
	"pod-disruption-budget":    {mitre("T1499", "Endpoint Denial of Service")},
	"topology-spread":          {mitre("T1499", "Endpoint Denial of Service")},
	"node-affinity-untrusted":  {mitre("T1610", "Deploy Container")},
	"hpa-without-requests":     {mitre("T1499", "Endpoint Denial of Service")},

	// Phase 2 — Storage (5)
	"pvc-no-encryption":         {mitre("T1530", "Data from Cloud Storage")},
	"pvc-reclaim-retain":        {mitre("T1530", "Data from Cloud Storage")},
	"csi-driver-security":       {mitre("T1611", "Escape to Host")},
	"emptydir-size-limit":       {mitre("T1499", "Endpoint Denial of Service")},
	"projected-volume-security": {mitre("T1552", "Unsecured Credentials")},

	// Phase 2 — Cluster Configuration (10)
	"namespace-default-usage": {mitre("T1078.001", "Valid Accounts: Default Accounts")},
	"limit-range-missing":     {mitre("T1499", "Endpoint Denial of Service")},
	"resource-quota-missing":  {mitre("T1499", "Endpoint Denial of Service")},
	"api-server-anonymous":    {mitre("T1078.001", "Valid Accounts: Default Accounts")},
	"audit-logging":           {mitre("T1562.008", "Impair Defenses: Disable Cloud Logs")},
	"admission-controllers":   {mitre("T1610", "Deploy Container")},
	"etcd-encryption":         {mitre("T1552", "Unsecured Credentials")},
	"kubelet-config":          {mitre("T1552.007", "Unsecured Credentials: Container API")},
	"component-versions":      {mitre("T1203", "Exploitation for Client Execution")},
	"deprecated-api-usage":    {mitre("T1203", "Exploitation for Client Execution")},

	// Phase 2 — Supply Chain (5)
	"container-runtime-socket":  {mitre("T1611", "Escape to Host"), mitre("T1610", "Deploy Container")},
	"liveness-readiness-probes": {mitre("T1499", "Endpoint Denial of Service")},
	"startup-probes":            {mitre("T1499", "Endpoint Denial of Service")},
	"lifecycle-hooks":           {mitre("T1059", "Command and Scripting Interpreter")},
	"image-age":                 {mitre("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain")},

	// Phase 2 — Cloud Provider (4)
	"eks-imds-access":          {mitre("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API")},
	"gke-metadata-concealment": {mitre("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API")},
	"aks-pod-identity":         {mitre("T1078.004", "Valid Accounts: Cloud Accounts")},
	"cloud-provider-detection": {mitre("T1580", "Cloud Infrastructure Discovery")},

	// Phase 2 — CRD Security (4)
	"crd-validation-missing": {mitre("T1610", "Deploy Container")},
	"crd-conversion-webhook": {mitre("T1557", "Adversary-in-the-Middle")},
	"cert-manager-expiry":    {mitre("T1552", "Unsecured Credentials")},
	"cert-manager-insecure":  {mitre("T1557", "Adversary-in-the-Middle")},

	// v1.3.0
	"rbac-node-proxy-access":                   {mitre("T1611", "Escape to Host")},
	"rbac-csr-approval":                        {mitre("T1078", "Valid Accounts")},
	"rbac-webhook-tampering":                   {mitre("T1562", "Impair Defenses")},
	"rbac-token-request":                       {mitre("T1078", "Valid Accounts")},
	"rbac-deletecollection-broad":              {mitre("T1485", "Data Destruction")},
	"rbac-aggregation-label-injection":         {mitre("T1068", "Exploitation for Privilege Escalation")},
	"gateway-listener-no-tls":                  {mitre("T1557", "Adversary-in-the-Middle")},
	"service-externalname-dangling":            {mitre("T1584.001", "Compromise Infrastructure: Domains")},
	"metadata-service-egress-unblocked":        {mitre("T1552.005", "Cloud Instance Metadata API")},
	"validatingwebhook-failure-policy-ignore":  {mitre("T1562", "Impair Defenses")},
	"mutatingwebhook-wildcard-scope":           {mitre("T1195", "Supply Chain Compromise")},
	"webhook-external-url":                     {mitre("T1557", "Adversary-in-the-Middle")},
	"apiservice-insecure-skip-verify":          {mitre("T1557", "Adversary-in-the-Middle")},
	"host-users-not-isolated":                  {mitre("T1611", "Escape to Host")},
	"windows-hostprocess":                      {mitre("T1611", "Escape to Host")},
	"hostaliases-injection":                    {mitre("T1557", "Adversary-in-the-Middle")},
	"serviceaccount-token-manual-volume-mount": {mitre("T1528", "Steal Application Access Token")},
	"subpath-symlink-risk":                     {mitre("T1611", "Escape to Host")},
	"priority-class-excessive-value":           {mitre("T1499", "Endpoint Denial of Service")},
	"serviceaccount-token-secret-legacy":       {mitre("T1528", "Steal Application Access Token")},
	"secrets-in-annotations":                   {mitre("T1552", "Unsecured Credentials")},
	"poststart-hook-network-call":              {mitre("T1071", "Application Layer Protocol")},
}
