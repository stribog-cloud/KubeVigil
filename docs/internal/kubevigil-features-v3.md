# KubeVigil — Comprehensive Feature Specification v3

## Project Identity

**Name:** KubeVigil (working title — verify availability before launch)
**Tagline:** "Know your clusters before attackers do."
**Category:** Kubernetes Security Posture Management (KSPM) CLI Tool
**License:** Apache 2.0 (recommended for enterprise adoption)
**Language:** Go
**Minimum Go Version:** 1.25+ (required by k8s.io dependencies)
**Minimum Kubernetes Version:** 1.25+ (PSA is GA, PSP removed)

---

## 1. Core Scanning Engine

### 1.1 Scan Modes

- **Live Cluster Scan** — Connect to a running Kubernetes cluster via kubeconfig and scan all or selected namespaces in real time. Supports in-cluster config auto-detection when running as a pod. Gracefully degrades when RBAC restricts access to certain resource types (scans what it can, reports what it couldn't).

- **Manifest Scan (Offline)** — Scan YAML/JSON manifests from disk without requiring a live cluster. Supports single files, directories, recursive directory walks, and multi-document YAML files (separated by `---`). Essential for CI/CD integration and shift-left security. Handles malformed YAML gracefully with per-file error reporting.

- **Helm Chart Scan** — Render Helm charts (with values overrides) and scan the resulting manifests. Supports local charts, remote chart repositories, and OCI-based chart registries. Accepts `--set`, `--values`, and `--set-file` flags matching Helm CLI conventions. Reports findings with source-mapped line numbers back to the original template files where possible.

- **Kustomize Scan** — Build and scan Kustomize overlays. Supports base + overlay stacking. Handles remote bases.

- **Stdin Scan** — Accept manifests piped via stdin for integration with other tools (`kubectl get deployment -o yaml | kubevigil scan -`). Auto-detects single vs multi-document input.

- **Multi-Cluster Scan** — Scan multiple clusters in a single run by specifying multiple kubeconfig contexts (`--contexts prod-eu,prod-us,staging`). Produce a unified or per-cluster report. Scans run concurrently across clusters with per-cluster timeout.

- **Diff Scan** — Compare the live state of a cluster against the desired state defined in Git manifests. Highlight security-relevant drift (e.g., someone `kubectl edit`ed a deployment to add `privileged: true` but the Git manifest doesn't have it).

- **Scan Profiles** — Pre-packaged scan configurations for different use cases:
  - `quick` — Top 15 highest-impact checks only, fast execution, ideal for pre-commit hooks.
  - `standard` — All workload and RBAC checks (default).
  - `deep` — All checks including cluster-level, node-level, and supply chain checks.
  - `compliance-cis` — Only checks that map to CIS Kubernetes Benchmark controls.
  - `compliance-nsa` — Only checks that map to NSA/CISA Hardening Guide.
  - Custom profiles definable in config.

- **Watch Mode** — `kubevigil watch` continuously monitors a cluster for resource changes (via K8s informers) and re-scans changed resources in real time. Outputs findings as a stream (JSON Lines). Useful during development and testing.

- **Inventory Mode** — `kubevigil inventory` scans a cluster and produces a security-annotated inventory of all workloads without judgment — just facts. What images are running, what security contexts are set, what service accounts are used. Useful as a baseline assessment before defining policy.

### 1.2 Scan Targeting & Filtering

- **Namespace filtering** — Include or exclude specific namespaces (`--namespace`, `--exclude-namespace`). Supports comma-separated lists and glob patterns (`--namespace "prod-*"`).
- **Label selectors** — Scan only resources matching a label selector (`--selector app=frontend`).
- **Resource kind filtering** — Limit scan to specific resource types (`--kinds Deployment,StatefulSet,DaemonSet`).
- **Annotation-based skip** — Resources annotated with `kubevigil.io/skip: check-name` are exempted from specific checks. Supports comma-separated check lists and wildcard (`kubevigil.io/skip: "*"` to skip all checks for a resource).
- **Regex-based exclusions** — Exclude resources by name pattern (`--exclude-name "test-.*"`).
- **Owner-aware filtering** — When scanning Pods, optionally roll findings up to the owning controller (Deployment, StatefulSet, DaemonSet, Job) rather than reporting on each Pod replica individually. Enabled by default, disable with `--no-owner-rollup`.
- **Age-based filtering** — Only scan resources created or modified within a time window (`--created-after`, `--modified-after`). Useful for focusing on recent changes.

### 1.3 Checker Architecture

- **Pluggable checker interface** — Every check implements a common `Checker` interface:
  ```go
  type Checker interface {
      Name() string
      Description() string
      Categories() []Category          // workload, rbac, network, etc.
      SupportedModes() []ScanMode      // live, manifest, or both
      RequiredResources() []schema.GroupVersionResource
      Run(ctx context.Context, resources *ResourceCache) ([]Finding, error)
  }
  ```
  The `RequiredResources()` method enables the engine to lazy-load only what's needed and to skip checks gracefully when RBAC doesn't permit access to required resources.

- **Checker registry** — Central registry that discovers and manages all available checkers. Supports both built-in and external checkers. Checkers self-register via Go `init()` functions.

- **Concurrent execution** — Checks run in parallel using `errgroup` with configurable concurrency limits (`--concurrency N`). Each check receives its own context for cancellation. The engine respects the resource dependency DAG — checks sharing the same resource type wait for that resource to be fetched once, then all proceed.

- **Resource cache** — A shared, read-only cache of fetched Kubernetes resources. Populated once per scan based on the union of all enabled checks' `RequiredResources()`. Eliminates redundant API calls. Thread-safe for concurrent checker access.

- **Severity classification** — Every finding is classified: Critical, High, Medium, Low, Info. Configurable per-check severity overrides in config. Severity definitions:
  - **Critical** — Direct path to cluster compromise, container escape, or data breach. Requires immediate action.
  - **High** — Significant security weakness that meaningfully increases attack surface. Fix within days.
  - **Medium** — Defense-in-depth gap. Not directly exploitable alone but weakens posture. Fix within sprint.
  - **Low** — Best practice deviation. Minimal direct risk but improves hygiene. Fix when convenient.
  - **Info** — Informational observation. No direct security impact. Awareness only.

- **Finding fingerprinting** — Each finding gets a stable fingerprint hash based on (check ID + resource UID + container name + specific field path). This enables accurate deduplication across scans, regression detection, and baseline tracking. Fingerprints survive resource recreation if the same misconfiguration reappears.

- **Kubernetes version awareness** — The engine detects the cluster's Kubernetes version (or accepts `--k8s-version` for manifest mode) and adapts checks accordingly. Checks targeting features that don't exist in older versions are automatically skipped. Deprecated API checks adjust their severity based on how close the removal version is.

- **Graceful degradation** — When the tool lacks RBAC permission to list a resource type, it logs a warning, skips affected checks, and reports which checks were skipped and why in the scan summary. The scan succeeds with partial results rather than failing entirely.

- **Auto-remediation hints** — Every finding includes:
  - Human-readable remediation description.
  - A YAML snippet showing the correct configuration.
  - Where feasible, a `kubectl patch` command.
  - A reference URL (CIS benchmark, K8s docs, CVE page).

---

## 2. Security Checks — Built-in Library

### 2.1 Workload Security (Pod / Container Level)

| # | Check ID | Description | Default Severity | CIS Ref |
|---|----------|-------------|-----------------|---------|
| 1 | `privileged` | Containers running with `privileged: true`. Grants full host access, effectively root on the node. | Critical | 5.2.1 |
| 2 | `capabilities-added` | Dangerous Linux capabilities added (SYS_ADMIN, NET_RAW, SYS_PTRACE, DAC_OVERRIDE, SETUID, SETGID, etc.). Each capability is individually classified by risk level. | High | 5.2.7-9 |
| 3 | `capabilities-not-dropped` | Containers not explicitly dropping ALL capabilities and adding back only what's needed. The secure pattern is `drop: ["ALL"]` + selectively `add` required caps. | Medium | 5.2.7 |
| 4 | `run-as-root` | Containers running as root (UID 0) or missing `runAsNonRoot: true`. Checks both pod-level and container-level securityContext with proper inheritance logic (container overrides pod). | High | 5.2.6 |
| 5 | `run-as-high-uid` | Containers running as UID < 10000 (conflict risk with host UIDs). Configurable threshold. | Low | — |
| 6 | `run-as-group` | Containers missing `runAsGroup` or running as GID 0 (root group). | Medium | — |
| 7 | `read-only-rootfs` | Containers without `readOnlyRootFilesystem: true`. Writable root filesystems allow attackers to modify binaries, drop tools, or persist. | Medium | 5.2.4 |
| 8 | `resource-limits-missing` | Containers missing CPU or memory limits. Without limits, a single container can starve the node (DoS). | Medium | 5.4.1 |
| 9 | `resource-requests-missing` | Containers missing CPU or memory requests. Without requests, the scheduler cannot make informed placement decisions. | Medium | 5.4.2 |
| 10 | `resource-limits-ratio` | Limits-to-requests ratio exceeds configurable threshold (default 3x). Extreme overcommitment leads to OOM kills and instability. | Low | — |
| 11 | `ephemeral-storage-limits` | Containers missing ephemeral-storage limits. Unbounded ephemeral storage can fill node disk and cause evictions. | Low | — |
| 12 | `host-pid` | Pods with `hostPID: true`. Grants visibility into all host processes, enables ptrace attacks, and leaks environment variables of other containers. | Critical | 5.2.2 |
| 13 | `host-ipc` | Pods with `hostIPC: true`. Grants access to host shared memory, enabling data exfiltration from other processes. | Critical | 5.2.3 |
| 14 | `host-network` | Pods with `hostNetwork: true`. Bypasses network policies, exposes host network interfaces, and can sniff traffic. | Critical | 5.2.4 |
| 15 | `host-ports` | Containers binding to host ports. Creates port conflicts and exposes services directly on node IPs. Reports specific port numbers. | High | — |
| 16 | `host-path-volumes` | Pods mounting hostPath volumes. Severity varies by path: `/` or `/etc` → Critical; `/var/run/docker.sock` or `/run/containerd/containerd.sock` → Critical (container escape); `/var/log` → High; others → Medium. Configurable sensitive path list. | Critical-Medium | 5.2.12 |
| 17 | `privilege-escalation` | Containers without `allowPrivilegeEscalation: false`. When true (the default), processes can gain more privileges than their parent via setuid binaries, exploits, etc. | High | 5.2.5 |
| 18 | `seccomp-profile` | Pods/containers missing Seccomp profile or not using RuntimeDefault/Localhost. Without Seccomp, containers can use all 300+ Linux syscalls. | Medium | 5.7.2 |
| 19 | `apparmor-profile` | Pods missing AppArmor annotations or K8s 1.30+ `appArmorProfile` field configuration. Version-aware: uses annotation check on <1.30, field check on ≥1.30. | Medium | 5.7.2 |
| 20 | `selinux-options` | SELinux context misconfigurations — running with unconfined type, or explicitly setting dangerous contexts like `spc_t`. | Medium | — |
| 21 | `proc-mount` | Containers with `procMount: Unmasked`. Exposes full `/proc` filesystem which leaks kernel and host information. | High | — |
| 22 | `unsafe-sysctls` | Pods configuring unsafe sysctls without explicit cluster-level allowlisting. Unsafe sysctls can destabilize nodes. | High | — |
| 23 | `runtime-class` | Pods not specifying a RuntimeClass when the cluster has sandboxed runtimes available (gVisor/runsc, Kata Containers). Configurable — only flags when a `RuntimeClass` named in config exists in the cluster. | Low | — |
| 24 | `share-process-namespace` | Pods with `shareProcessNamespace: true`. Allows containers to see and signal each other's processes, which can be a lateral movement path. | Medium | — |

### 2.2 Container Lifecycle (Init, Sidecar, Ephemeral)

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 25 | `init-container-security` | Init containers not subject to the same security controls as regular containers. All checks from 2.1 apply equally to init containers. Many teams harden regular containers but forget init containers. | Same as parent check |
| 26 | `sidecar-container-security` | K8s 1.28+ native sidecar containers (restartPolicy: Always in initContainers) not subject to same security controls. | Same as parent check |
| 27 | `ephemeral-container-policy` | Cluster or namespace allows ephemeral debug containers without security restrictions. Flag when PSA labels would permit debug containers to run as root or privileged. | Medium |

### 2.3 Image Security

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 28 | `image-tag-latest` | Images using `:latest` tag. Mutable tags mean deployments are non-reproducible and rollbacks don't work. | Medium |
| 29 | `image-tag-missing` | Images with no tag specified (implies `:latest`). | Medium |
| 30 | `image-no-digest` | Images not pinned by digest (SHA256). Only digest pinning guarantees immutability. | Low |
| 31 | `image-pull-policy` | `imagePullPolicy` not set to `Always` when using mutable tags. With `IfNotPresent` + mutable tag, nodes can run different image versions. | Medium |
| 32 | `image-registry-allowlist` | Images pulled from registries not in the allowed list. Prevents shadow IT and untrusted image sources. | High |
| 33 | `image-registry-blocklist` | Images pulled from explicitly blocked registries. | Critical |
| 34 | `image-signature-verification` | Images not signed via cosign/Sigstore or Notary. Only flagged when signature verification policy is configured. Checks whether the cluster has a policy engine (Kyverno, Connaisseur) enforcing signatures. | Medium |
| 35 | `image-sbom-attestation` | Images lacking SBOM (Software Bill of Materials) attestation. Only flagged when SBOM policy is configured. Checks for in-toto attestations. | Low |
| 36 | `image-provenance` | Images without SLSA provenance attestation. Verifies the build pipeline producing the image is trustworthy. | Low |

### 2.4 Identity & Access (ServiceAccount / RBAC)

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 37 | `default-service-account` | Pods using the `default` ServiceAccount. The default SA in every namespace auto-mounts a token that may have unintended permissions. | High |
| 38 | `automount-token` | ServiceAccount tokens auto-mounted when not needed. Most workloads don't call the K8s API and should have `automountServiceAccountToken: false`. | High |
| 39 | `token-projection-config` | Pods using legacy (non-projected, non-expiring) ServiceAccount tokens instead of bound projected tokens with audience and expiry. K8s 1.22+ defaults to projected, but legacy mounts may still exist. | Medium |
| 40 | `rbac-wildcard-verbs` | Roles/ClusterRoles granting `*` (all) verbs on any resource. Violates least-privilege. | Critical |
| 41 | `rbac-wildcard-resources` | Roles/ClusterRoles granting access to `*` (all) resources. Even with limited verbs, `*` resources is dangerous. | Critical |
| 42 | `rbac-wildcard-apigroups` | Roles/ClusterRoles with `apiGroups: ["*"]`. Combined with other wildcards, grants unlimited access. | Critical |
| 43 | `rbac-escalation-verbs` | Roles granting `bind`, `escalate`, or `impersonate` verbs. These allow privilege escalation within RBAC itself. | Critical |
| 44 | `rbac-secret-access` | Roles granting `get`, `list`, or `watch` on Secrets. Secrets contain credentials, TLS keys, and tokens. | High |
| 45 | `rbac-exec-access` | Roles granting `create` on `pods/exec` or `pods/attach`. Equivalent to SSH access to any pod matching the role's scope. | High |
| 46 | `rbac-log-access` | Roles granting `get` on `pods/log`. Can expose sensitive application data, credentials in logs. | Medium |
| 47 | `rbac-cluster-admin` | RoleBindings or ClusterRoleBindings to `cluster-admin`. Every binding to cluster-admin should be justified and documented. | Critical |
| 48 | `rbac-unused-roles` | Roles/ClusterRoles that have no bindings (dead roles). Orphaned roles are cleanup candidates and potential attack surface. | Info |
| 49 | `rbac-group-bindings` | Bindings referencing overly broad groups like `system:authenticated` or `system:unauthenticated`. | High |
| 50 | `rbac-subject-external` | RoleBindings referencing subjects not matching any known user/group pattern. Potential misconfiguration or stale binding. | Low |
| 51 | `cloud-iam-binding` | Pods using cloud provider IAM integration (AWS IRSA, GCP Workload Identity, Azure Pod Identity) with overly broad cloud IAM roles. Checks annotations/labels that map to cloud IAM. Does not validate the cloud IAM policy itself (would require cloud API access), but flags the binding for review and cross-references known patterns. | Medium |

### 2.5 Secrets Management

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 52 | `secrets-in-env` | Secrets passed as environment variables instead of volume mounts. Env vars leak into logs, crash dumps, and child processes. Volume mounts can use tmpfs and are updated on rotation. | Medium |
| 53 | `secrets-unencrypted` | Cluster not configured with encryption at rest for etcd Secrets. Without this, anyone with etcd access reads all secrets in plaintext. Detection via EncryptionConfiguration API or heuristic. | Critical |
| 54 | `secrets-in-configmap` | ConfigMaps containing values that look like secrets. Uses multiple detection strategies: regex patterns (password=, token=, api_key=), high Shannon entropy analysis, and known secret format patterns (JWT, AWS keys, private keys). Configurable sensitivity threshold. | High |
| 55 | `secrets-default-type` | Secrets using `Opaque` type where a more specific type exists (e.g., `kubernetes.io/tls`, `kubernetes.io/dockerconfigjson`). Typed secrets get additional validation. | Low |
| 56 | `secrets-stale` | Secrets not rotated within a configurable period (checked via last-modified annotation or resource version age). Default threshold: 90 days. | Medium |
| 57 | `secrets-hardcoded-manifests` | In manifest scan mode, detect hardcoded secret values in YAML files (base64-decoded Secret data containing real values rather than references to external secret managers). | High |
| 58 | `external-secrets-sync` | When ExternalSecrets operator is present, check for sync failures, missing SecretStore references, or stale externally-managed secrets. | Medium |

### 2.6 Network Security

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 59 | `network-policy-missing` | Namespaces with no NetworkPolicy defined. Without policies, every pod can communicate with every other pod (flat network). | High |
| 60 | `network-policy-default-deny` | Namespaces missing a default-deny ingress/egress policy. Even with some policies, without a default-deny, unlabeled pods are wide open. | High |
| 61 | `network-policy-overly-permissive` | NetworkPolicies with empty `podSelector` + empty `from`/`to` (allow-all equivalent). Also flags policies that allow all egress to `0.0.0.0/0` without port restrictions. | Medium |
| 62 | `network-policy-egress-unrestricted` | Pods with unrestricted egress. Without egress policies, compromised pods can exfiltrate data, reach metadata services, and communicate with C2 servers. | Medium |
| 63 | `ingress-no-tls` | Ingress resources without TLS termination configured. Traffic in plaintext. | High |
| 64 | `ingress-wildcard-host` | Ingress using wildcard hosts (`*`). Accepts traffic for any hostname, potentially intercepting traffic meant for other services. | Medium |
| 65 | `ingress-class-missing` | Ingress without `ingressClassName` or deprecated annotation. May be picked up by unintended ingress controller. | Low |
| 66 | `service-type-loadbalancer` | Services exposed as LoadBalancer without annotation controls. Creates cloud load balancers that may be publicly accessible. | Medium |
| 67 | `service-type-nodeport` | Services exposed as NodePort (bypasses ingress controls, exposes on all nodes). | Medium |
| 68 | `external-ips` | Services with `externalIPs` set (CVE-2020-8554 man-in-the-middle risk). | High |
| 69 | `service-mesh-mtls` | When a service mesh (Istio, Linkerd) is detected, check that mutual TLS is enabled and enforced (not permissive mode). Detects mesh via CRDs and checks PeerAuthentication/TrafficPolicy resources. | High |
| 70 | `dns-security` | Check CoreDNS configuration for security issues: external forwarding to insecure resolvers, missing cache size limits, absent rate limiting, and presence of the `debug` plugin in production. Requires access to CoreDNS ConfigMap. | Medium |

### 2.7 Pod Security Standards (PSS) / Pod Security Admission (PSA)

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 71 | `psa-labels-missing` | Namespaces missing PSA enforcement labels (`pod-security.kubernetes.io/enforce`). Without labels, namespaces use the cluster default which may be `privileged`. | Medium |
| 72 | `psa-mode-audit-only` | Namespaces with PSA in `audit` or `warn` mode only, without `enforce`. Violations are logged but not blocked. | Medium |
| 73 | `psa-baseline-violations` | Workloads violating the PSS Baseline profile. This is the minimum acceptable security level for most workloads. | High |
| 74 | `psa-restricted-violations` | Workloads violating the PSS Restricted profile. This is the target security level for hardened workloads. | Medium |
| 75 | `psa-version-pinning` | PSA labels pinned to a specific K8s version (e.g., `v1.25`) rather than `latest`. Pinned versions don't pick up new restrictions on upgrade. | Low |
| 76 | `psp-still-present` | Deprecated PodSecurityPolicy resources still in cluster. PSP was removed in K8s 1.25. Lingering PSPs indicate incomplete migration. | Info |

### 2.8 Scheduling & Availability Security

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 77 | `toleration-control-plane` | Workloads tolerating control-plane/master taints without justification. Only system components should run on control-plane nodes. | High |
| 78 | `toleration-all` | Workloads with `operator: Exists` tolerations (tolerate everything). Can schedule on any node including tainted ones. | Medium |
| 79 | `priority-class-system` | Non-system workloads using `system-cluster-critical` or `system-node-critical` PriorityClasses. Can preempt legitimate system pods. | High |
| 80 | `priority-class-missing` | Workloads without a PriorityClass. During resource pressure, pods without priority are evicted first, potentially causing outages in critical services. | Low |
| 81 | `pod-disruption-budget` | Deployments/StatefulSets with replicas > 1 missing PodDisruptionBudget. Without PDB, all replicas can be evicted simultaneously during node drain. | Low |
| 82 | `topology-spread` | Workloads without topology spread constraints. All replicas may land on the same node, negating HA. | Low |
| 83 | `node-affinity-untrusted` | Workloads with nodeAffinity or nodeSelector targeting nodes with known untrusted labels/taints. Configurable label patterns. | Medium |
| 84 | `hpa-without-requests` | HorizontalPodAutoscaler targeting workloads without resource requests. HPA based on CPU/memory percentage requires requests to be set; without them, autoscaling is unpredictable. | Medium |

### 2.9 Storage Security

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 85 | `pvc-no-encryption` | PersistentVolumeClaims using StorageClasses without encryption configuration. Cloud providers support encrypted volumes but it's not always default. Checks StorageClass parameters and annotations. | Medium |
| 86 | `pvc-reclaim-retain` | PersistentVolumes with `reclaimPolicy: Retain` that are in `Released` state. These volumes contain data but are not bound to any claim — potential data exposure. | Medium |
| 87 | `csi-driver-security` | CSI drivers installed without `podInfoOnMount` or with `volumeLifecycleModes` allowing pre-provisioned access. Checks CSIDriver objects. | Low |
| 88 | `emptydir-size-limit` | `emptyDir` volumes without `sizeLimit`. A container can fill node disk via unlimited emptyDir. | Low |
| 89 | `projected-volume-security` | Projected volumes with `defaultMode` that's too permissive (world-readable token files). Should be 0600 or 0400. | Medium |

### 2.10 Cluster Configuration & Hardening

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 90 | `namespace-default-usage` | Workloads deployed in the `default` namespace. The default namespace lacks isolation policies and is shared by all users. | Medium |
| 91 | `limit-range-missing` | Namespaces without LimitRange defined. Without LimitRange, a single container can request all node resources. | Low |
| 92 | `resource-quota-missing` | Namespaces without ResourceQuota defined. Without quotas, a namespace can consume unlimited cluster resources. | Low |
| 93 | `api-server-anonymous` | Anonymous authentication enabled on API server. Detected by probing the discovery API without credentials. | High |
| 94 | `audit-logging` | API server audit logging not configured or misconfigured. Detected via audit policy ConfigMap if accessible, or API server flags in managed clusters. | High |
| 95 | `admission-controllers` | Critical admission controllers disabled. Checks for: AlwaysPullImages, NodeRestriction, PodSecurity, ServiceAccount. Detection via API server feature gates when accessible. | Medium |
| 96 | `etcd-encryption` | etcd encryption configuration status. Checks EncryptionConfiguration if accessible. In managed clusters, checks provider-specific annotations/APIs. | Critical |
| 97 | `kubelet-config` | Kubelet misconfigurations: anonymous auth enabled, read-only port open (10255), streaming connection idle timeout, event record QPS. Requires Node API access or in-cluster execution. | High |
| 98 | `component-versions` | Control plane component version skew exceeding supported range. Kubelet version more than 2 minor versions behind API server. | Medium |
| 99 | `deprecated-api-usage` | Resources using deprecated or soon-to-be-removed API versions. Severity scales with proximity to removal version: removed → High, deprecated in next version → Medium, deprecated in future → Low. | Medium-Low |

### 2.11 Supply Chain & Build Provenance

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 100 | `container-runtime-socket` | Pods mounting container runtime sockets (`/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/var/run/crio/crio.sock`). Direct socket access = full container escape. | Critical |
| 101 | `liveness-readiness-probes` | Containers missing liveness or readiness probes. Without probes, K8s cannot detect unhealthy containers or route traffic correctly. | Low |
| 102 | `startup-probes` | Containers with slow startup and liveness probes but no startup probe. Can cause restart loops during initialization. | Info |
| 103 | `lifecycle-hooks` | Containers with `preStop` hooks making external network calls (potential data exfiltration on termination). | Low |
| 104 | `image-age` | Container images older than configurable threshold (default: 180 days). Stale images likely have unpatched vulnerabilities. Requires registry API access or annotation-based age tracking. | Low |

### 2.12 Cloud Provider Specific

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 105 | `eks-imds-access` | On EKS, pods able to access EC2 Instance Metadata Service (IMDS) at 169.254.169.254. Without blocking, any pod can steal the node's IAM role credentials. Checks for `hostNetwork` pods and presence of NetworkPolicies blocking metadata IP. | High |
| 106 | `gke-metadata-concealment` | On GKE, Workload Identity not enabled or metadata concealment not configured. Similar IMDS risk as EKS. | High |
| 107 | `aks-pod-identity` | On AKS, deprecated pod identity (aad-pod-identity) still in use instead of Azure Workload Identity. | Medium |
| 108 | `cloud-provider-detection` | Auto-detect cloud provider (EKS, GKE, AKS, DOKS, Linode, Hetzner) from node labels and API server version. Enable provider-specific checks automatically. | Info |

### 2.13 CRD & Custom Resource Security

| # | Check ID | Description | Default Severity |
|---|----------|-------------|-----------------|
| 109 | `crd-validation-missing` | CustomResourceDefinitions without OpenAPI validation schema. Unvalidated CRDs accept any input, potentially including injection payloads. | Medium |
| 110 | `crd-conversion-webhook` | CRDs with conversion webhooks pointing to external/untrusted endpoints. Webhook compromise = data manipulation. | High |
| 111 | `cert-manager-expiry` | When cert-manager is installed, check for Certificates nearing expiry (within 14 days) or in failed state. | High |
| 112 | `cert-manager-insecure` | cert-manager Certificates using weak key algorithms (RSA < 2048, ECDSA < P256) or requesting excessively long durations. | Medium |

---

## 3. Compliance Framework Mapping

Each finding maps to one or more industry compliance frameworks, giving audit reports real-world authority.

### 3.1 Supported Frameworks

| Framework | Version | Description |
|-----------|---------|-------------|
| CIS Kubernetes Benchmark | v1.8, v1.9+ | Primary framework. Full control mapping. Supports version selection. |
| NSA/CISA Kubernetes Hardening Guide | v1.2 | US government hardening guidance. |
| NIST SP 800-190 | — | Application Container Security Guide. |
| MITRE ATT&CK for Containers | v14+ | Map findings to attacker tactics and techniques (e.g., `T1611 - Escape to Host`, `T1552.007 - Container API`). |
| SOC 2 Type II | Trust Services Criteria | Map to CC6 (Logical and Physical Access Controls), CC7 (System Operations), CC8 (Change Management). |
| PCI DSS | v4.0 | Network isolation (Req 1), access control (Req 7), encryption (Req 3-4), vulnerability management (Req 6). |
| HIPAA | Security Rule | Map to Administrative Safeguards (§164.308), Technical Safeguards (§164.312). |
| ISO 27001 | Annex A | Map to relevant information security controls. |
| DISA STIG | Kubernetes STIG | Department of Defense Security Technical Implementation Guide. |
| Custom/Internal | — | Users define their own framework mappings via config. |

### 3.2 Framework Features

- **Framework-filtered reports** — Generate reports scoped to a specific framework: `kubevigil scan --framework cis-1.8`. Only shows findings relevant to that framework.
- **Control coverage dashboard** — Show percentage of framework controls covered by the scan. E.g., "CIS 1.8: 73/91 controls verified (80%)".
- **Gap analysis** — Identify framework controls that kubevigil cannot verify automatically (requiring manual review). Produce a checklist for manual assessment.
- **Evidence generation** — Produce compliance evidence artifacts suitable for auditor review. Each finding includes timestamp, resource state, and remediation status.
- **Multi-framework report** — A single scan can map to multiple frameworks simultaneously. The report shows which frameworks each finding violates.
- **Control pass/fail** — Report not just violations but also controls that pass. Auditors need both.

---

## 4. Reporting & Output

### 4.1 Output Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| Terminal (Text) | — | Human-readable, colored output. Respects `--no-color` and `NO_COLOR` env var. |
| JSON | `.json` | Machine-readable structured output. Schema versioned. |
| JSON Lines | `.jsonl` | Streaming output — one finding per line. Ideal for log aggregation. |
| YAML | `.yaml` | Structured output for K8s-native tooling. |
| Markdown | `.md` | Clean reports for wikis, PRs, or documentation. |
| HTML | `.html` | Self-contained report with collapsible sections, severity filtering, search, charts, and executive summary. Zero external dependencies (inline CSS/JS). Print-friendly. |
| SARIF | `.sarif` | Static Analysis Results Interchange Format. Integrates with GitHub Advanced Security, Azure DevOps, VS Code SARIF Viewer. |
| JUnit XML | `.xml` | CI systems that understand test results (Jenkins, etc.). Each check = test case. |
| CSV | `.csv` | Spreadsheet analysis and ad-hoc filtering. |
| PDF | `.pdf` | Generated from HTML report for formal distribution. Includes cover page, TOC, and page numbers. |
| Prometheus | — | Write findings as Prometheus metrics (push gateway or exposition). |

### 4.2 Report Content

- **Executive summary** — High-level posture score (0-100, weighted), finding counts by severity, top 5 risks, trend compared to last scan (if baseline exists), scan metadata.
- **Cluster metadata** — Kubernetes version, node count/roles, namespace count, container runtime, CNI plugin, context name, scan timestamp, scan duration, kubevigil version.
- **Findings detail** — For each finding: severity, check ID, affected resource (namespace/kind/name), container name (if applicable), specific field path (`.spec.containers[0].securityContext.privileged`), message, remediation steps with YAML snippet, framework references (CIS, MITRE, etc.), finding fingerprint.
- **Resource inventory** — Summary of all scanned resources by kind and namespace. Counts of Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, standalone Pods.
- **Exemption log** — List of all findings that were suppressed by exemptions, with reason, expiry date (if set), and who configured the exemption.
- **Check coverage** — List of all checks that were run, skipped (and why — disabled, insufficient RBAC, unsupported K8s version, not applicable to scan mode), or errored.
- **Scan performance** — Time taken per check, API calls made, resources fetched. Helps optimize scan configuration.

### 4.3 Report Intelligence

- **Posture scoring** — Composite score (0-100) per namespace, per workload, and cluster-wide. Formula: weighted sum based on severity × count, normalized. Weights configurable. Score thresholds: A (90+), B (75-89), C (60-74), D (40-59), F (<40).
- **Attack path analysis** — Correlate multiple findings to identify compound attack paths. E.g., "Container runs as root + hostPath mount to / + no NetworkPolicy = full node compromise from any pod vulnerability." Report these compound risks separately with elevated severity.
- **Finding deduplication** — Group identical findings across replicas/similar workloads. Instead of "50 pods missing readiness probes," show "Deployment web-frontend (50 replicas): missing readiness probe."
- **Remediation priority ranking** — Rank findings by composite priority score: severity × exposure × blast_radius × fix_effort_inverse. An internet-facing critical finding on a 100-replica deployment ranks higher than a critical finding on an internal single-pod Job.
- **Auto-generated remediation YAML** — For applicable findings, generate a corrected YAML patch, a complete fixed manifest, or a Kustomize overlay that fixes the issue.
- **Trend badges** — For each finding in diff mode, show 🆕 (new in this scan), ✅ (resolved since last scan), ⏳ (persisting), 📈 (severity increased), 📉 (severity decreased due to config change).

---

## 5. Configuration & Policy

### 5.1 Configuration File

```yaml
# .kubevigil.yaml (auto-discovered in cwd, home dir, XDG, or --config)
version: "1"                         # Config schema version for forward compat

settings:
  severity_threshold: medium         # Minimum severity to include in reports
  concurrency: 10                    # Max concurrent checks
  timeout: 300s                      # Global scan timeout
  fail_on: high                      # CI exit code threshold
  k8s_version: "1.29"               # Target K8s version (for manifest mode)
  scan_profile: standard            # quick, standard, deep, or custom
  owner_rollup: true                # Roll pod findings up to owning controller
  deduplication: true               # Group identical findings across replicas

checks:
  enabled: all                       # "all" or explicit list
  disabled:
    - image-no-digest               # Not enforced in our workflow yet
    - image-sbom-attestation        # Not ready yet
  
  overrides:
    image-tag-latest:
      severity: high                # Override default severity
    resource-limits-missing:
      severity: low                 # We handle limits via LimitRange

policies:
  images:
    allowed_registries:
      - registry.acme.example.com
      - gcr.io/distroless
      - docker.io/library
    blocked_registries:
      - docker.io/untrusted
    max_image_age_days: 180
  
  capabilities:
    allowed:
      - NET_BIND_SERVICE
    dangerous:                        # Override built-in dangerous list
      - SYS_ADMIN
      - SYS_PTRACE
      - NET_RAW
  
  resources:
    max_limits:
      cpu: "4"
      memory: "8Gi"
    max_limits_to_requests_ratio: 3
  
  labels:
    required:
      - app.kubernetes.io/name
      - app.kubernetes.io/team
    recommended:
      - app.kubernetes.io/version
  
  networking:
    host_port_max: 1024
    require_default_deny: true
    require_egress_policy: true
  
  secrets:
    max_age_days: 90
    entropy_threshold: 4.5            # Shannon entropy for secret detection
  
  rbac:
    max_cluster_admin_bindings: 3
    flag_unused_roles: true

exemptions:
  - namespace: kube-system
    checks: [privileged, host-namespaces, host-path-volumes]
    reason: "System components require elevated access"
    approved_by: "mangesh@stribog.io"
  
  - namespace: monitoring
    resource: prometheus-node-exporter
    kind: DaemonSet
    checks: [host-network, host-pid]
    reason: "Node exporter requires host-level access for metrics"
    expires: "2026-06-30"
  
  - annotation: kubevigil.io/skip

frameworks:
  - cis-1.8
  - mitre-attack

reporting:
  output: text                        # Default output format
  include_passing: false             # Include passing checks in report
  group_by: namespace                # namespace, severity, check, team
  max_findings: 0                    # 0 = unlimited
```

### 5.2 Configuration Features

- **Config file discovery** — Auto-discover `.kubevigil.yaml` in: current directory → parent directories (up to git root) → `~/.config/kubevigil/` (XDG) → `~/.kubevigil.yaml` → explicit `--config` path. First found wins. `--config` overrides all.
- **Config merging** — Layer multiple configs: `kubevigil scan --config base.yaml --config env-prod.yaml`. Later configs override earlier ones. Exemptions are additive.
- **Environment variable overrides** — All config options settable via `KUBEVIGIL_*` env vars. Nested keys use underscores: `KUBEVIGIL_SETTINGS_CONCURRENCY=20`.
- **Config validation** — `kubevigil config validate` checks syntax, semantic validity (check IDs exist, severities are valid, exemption resources reference real kinds), and reports warnings for potential issues.
- **Config generation** — `kubevigil config init` generates a starter config interactively. `kubevigil config init --from-scan` generates a config with exemptions pre-populated from a scan (for establishing a baseline on an existing cluster).
- **Config schema** — Published JSON Schema for editor autocompletion and validation. VS Code settings snippet included.
- **Config versioning** — Schema version field (`version: "1"`) for forward compatibility. Tool warns when config version is newer than supported.

### 5.3 Custom Policies (OPA/Rego)

- **Custom check plugins** — Write custom checks in Rego (Open Policy Agent) that integrate into the checker framework. Each Rego policy has access to the full resource object and produces findings in a standard format.
- **Policy bundles** — Load policy bundles from local directories, Git repositories, or remote HTTP/OCI endpoints. Bundles include Rego policies + metadata (descriptions, severities, framework mappings).
- **Policy testing** — `kubevigil policy test` command to test custom policies against fixture manifests with expected-finding assertions.
- **Built-in policy library** — Ship common extended policies (organizational naming conventions, mandatory annotations, environment-specific rules) as an optional downloadable policy bundle.
- **YAML-based simple checks** — Define simple pattern-matching checks in YAML for non-programmers (see Section 12).

---

## 6. CLI Interface & UX

### 6.1 Commands

```
SCAN COMMANDS
  kubevigil scan                         Main scan (live cluster, default context)
  kubevigil scan --file <path>           Scan manifests from file/directory
  kubevigil scan --file <path> -R        Recursive directory scan
  kubevigil scan --helm <chart>          Scan Helm chart
  kubevigil scan --helm <chart> -f vals  Scan Helm chart with values
  kubevigil scan --kustomize <dir>       Scan Kustomize overlay
  kubevigil scan -                       Scan from stdin
  kubevigil scan --contexts a,b,c        Multi-cluster scan

INFORMATION COMMANDS
  kubevigil list checks                  List all checks with descriptions
  kubevigil list checks --verbose        Include remediation, references, framework mapping
  kubevigil list frameworks              List supported compliance frameworks
  kubevigil list profiles                List available scan profiles
  kubevigil explain <check-id>           Deep-dive: what, why, how to fix, attack scenario, refs
  kubevigil inventory                    Security-annotated resource inventory (no judgment)

REMEDIATION COMMANDS
  kubevigil fix <path>                   Auto-fix manifests (with .bak backup)
  kubevigil fix --dry-run <path>         Show diff without modifying
  kubevigil fix --checks X,Y <path>      Fix only specific checks
  kubevigil fix --severity critical,high Fix only critical+high findings
  kubevigil fix --kustomize <path>       Generate Kustomize overlay instead of patching

COMPARISON COMMANDS
  kubevigil diff <file1> <file2>         Compare two scan result files
  kubevigil diff --baseline <file>       Compare current scan against baseline
  kubevigil baseline create              Save current scan as accepted baseline
  kubevigil baseline update              Update baseline with current scan

CONTINUOUS COMMANDS
  kubevigil watch                        Continuous monitoring via K8s informers
  kubevigil serve                        Run as HTTP server (webhook + metrics)

CONFIGURATION COMMANDS
  kubevigil config init                  Generate starter config interactively
  kubevigil config init --from-scan      Generate config with exemptions from current scan
  kubevigil config validate              Validate config file
  kubevigil config show                  Show effective merged config

DEVELOPMENT COMMANDS
  kubevigil dev new-check <name>         Scaffold new check (code, test, docs)
  kubevigil policy test <dir>            Test custom Rego policies

UTILITY COMMANDS
  kubevigil completion <shell>           Shell completion (bash, zsh, fish, powershell)
  kubevigil version                      Version, build info, Go version, K8s client version
  kubevigil version --check              Check for updates
```

### 6.2 Global Flags

```
--kubeconfig string         Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
--context string            Kubernetes context to use
--namespace string          Scan specific namespace(s), comma-separated or glob
--exclude-namespace string  Exclude namespace(s)
--selector string           Label selector filter
--checks string             Enable only these checks (comma-separated)
--exclude-checks string     Disable these checks
--severity string           Minimum severity: critical, high, medium, low, info
--output string             Output format: text, json, jsonl, yaml, markdown, html, sarif, junit, csv
--output-file string        Write report to file instead of stdout
--config string             Path to config file
--profile string            Scan profile: quick, standard, deep
--fail-on string            Exit code 1 if findings >= severity (for CI)
--no-color                  Disable colored output
--quiet                     Suppress all output except exit code
--verbose                   Verbose output (API calls, timing)
--debug                     Debug output (full traces, raw API responses)
--concurrency int           Max concurrent checks (default: 10)
--timeout duration          Global scan timeout (default: 5m)
--k8s-version string        Target K8s version (manifest mode)
```

### 6.3 Terminal UX

- **Progress indicator** — Real-time spinner with: namespaces scanned, checks completed, findings so far, elapsed time. Uses stderr so stdout remains clean for piping.
- **Colored severity output** — Critical=Red bold, High=Red, Medium=Yellow, Low=Cyan, Info=Gray. Respects `NO_COLOR` env var and `--no-color` flag. Auto-detects non-TTY and disables color.
- **Interactive mode** — `kubevigil scan --interactive` for step-through of findings. Per finding: view details, apply fix, skip, add exemption, or quit.
- **Quiet mode** — `--quiet` suppresses all output except the exit code. For CI pipelines that only care about pass/fail.
- **Table output** — `--output table` for compact columnar display. Sortable by severity, namespace, check.
- **Resource tree view** — `--group-by tree` shows findings organized as namespace → kind → resource → container hierarchy.
- **Pager integration** — Auto-pipes to `$PAGER` (less, more) when output exceeds terminal height. Disable with `--no-pager`.
- **Shell completion** — Context-aware completion for namespaces, check IDs, context names. Generated for bash, zsh, fish, PowerShell.

---

## 7. Auto-Remediation Engine

### 7.0 Design Philosophy

**The default path is safe, and you have to actively opt into danger.**

`kubevigil fix` does NOT directly patch live clusters. It operates on source manifests (YAML files) and generates artifacts (patched manifests, kubectl commands, Kustomize overlays, Helm values) that operators apply through their existing deployment workflow (GitOps, `kubectl apply`, Helm upgrade, etc.). This is the auditable, GitOps-friendly approach.

The tool protects ignorant users from destroying things unintentionally while allowing knowledgeable operators to do whatever they need with explicit opt-in. Every layer of danger requires an additional explicit flag.

### 7.1 Core Behavior: Dry-Run by Default

**`kubevigil fix` without `--apply` only shows what would change. It modifies nothing.**

```
kubevigil fix ./manifests/                      # ONLY shows diff. Modifies nothing.
kubevigil fix ./manifests/ --apply              # Actually modifies files (safe fixes only).
kubevigil fix ./manifests/ --apply --risk-level moderate   # Includes "likely safe" fixes.
kubevigil fix ./manifests/ --apply --risk-level aggressive # Includes "potentially breaking" fixes.
```

This is the single most impactful safeguard. The default behavior is safe — the destructive behavior requires explicit intent via `--apply`.

### 7.2 Fix Capabilities

- **Manifest patching** — `kubevigil fix <path>` rewrites YAML manifests to resolve findings. Preserves comments, formatting, key ordering, blank lines, and indentation style using a YAML round-trip library (node-level manipulation via `gopkg.in/yaml.v3`, not marshal/unmarshal which destroys formatting). Supports single files, directories, recursive directory walks, and multi-document YAML files (separated by `---`). Fixes only the documents that have findings — preserves untouched documents verbatim.
- **Dry-run mode (default)** — Without `--apply`, shows unified diff of what would change. Colored diff output (green = added, red = removed). This IS the default — not a flag you add. For fixes classified as "likely_safe" or "potentially_breaking", the diff includes inline **"What Could Break"** warnings directly below the relevant change, ensuring the user sees impact information at the point of change rather than buried in a separate report.
- **Selective fixing** — Fix only specific checks (`--checks privileged,run-as-root`), severity levels (`--severity critical,high`), namespaces (`--namespace production`), or by finding fingerprint (`--fingerprint <hash>`). Supports `--exclude-namespace` and `--exclude-infra` for infrastructure namespaces.
- **Backup creation** — Always creates backup before modifying originals. Backups stored in a structured backup directory (not scattered `.bak` files): `<source>.bak-<timestamp>/` mirroring the source directory structure. Prints restore command after every fix operation.
- **kubectl patch generation** — `--output kubectl` generates copy-pasteable `kubectl patch` commands organized by namespace. Operators review and execute selectively. Commands are generated, NEVER executed by the tool.
- **Kustomize overlay generation** — `--kustomize <path>` generates a `security-overlay/` directory with `kustomization.yaml` and strategic merge patches applicable as a Kustomize overlay.
- **Helm values generation** — For known Helm chart patterns (common value paths for securityContext, resources, podSecurityContext, etc.), generate a `security-values.yaml` overriding insecure defaults. Detects Helm-managed resources by labels (`app.kubernetes.io/managed-by: Helm`) and warns against direct manifest patching.
- **GitOps PR generation** — `kubevigil fix --git-pr` creates a branch, commits fixes, and opens a PR/MR. Requires `gh` (GitHub) or `glab` (GitLab) CLI. Includes fix report as PR description.
- **Fix report** — Every fix operation generates a detailed changelog-style report documenting every change: file path, check ID, what changed, risk classification, and rollback instructions. Saved alongside the backup directory.
- **Fix validation** — `--verify` flag re-scans after applying fixes to confirm findings are resolved. Reports any remaining findings.

### 7.3 Fix Safety — Layered Safeguard Model

Five concentric rings of protection prevent accidental damage. An ignorant user must break through multiple barriers before causing harm.

#### Ring 1 — Dry-Run by Default

`kubevigil fix` without `--apply` modifies nothing. It only shows a diff. The safe behavior is the default.

#### Ring 2 — Fix Safety Classification

Even with `--apply`, the tool only auto-applies fixes at or below the configured risk level. The default risk level is `safe` — only fixes with zero risk of breaking anything.

| Classification | Risk Level Flag | Description | Examples |
|---|---|---|---|
| **Safe** | Default (`--apply` alone) | Zero risk of breaking. Unambiguously correct. | `privileged: false`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true` |
| **Likely Safe** | `--risk-level moderate` | Very low risk. Could theoretically break edge cases. | `drop: ["ALL"]` capabilities, `runAsNonRoot: true`, `automountServiceAccountToken: false` |
| **Potentially Breaking** | `--risk-level aggressive` | Could impact functionality. Requires operator judgment. | Specific `runAsUser` UID, dropping `NET_RAW`, setting resource limits |
| **Manual Only** | N/A (never auto-fixed) | Cannot auto-fix. Generates guidance only. | RBAC restructuring, NetworkPolicy creation, secrets migration |

Each fix in the output includes a **"What Could Break"** note explaining the impact:

```
Fix: readOnlyRootFilesystem: true
Risk: Likely Safe
⚠️  Could break: Applications that write to the container filesystem
   (temp files, caches, logs written to /var/log inside container).
   If your app writes files, add an emptyDir volume for the write path.
```

#### Ring 3 — System Namespace Hard Block

Resources in recognized system namespaces are NEVER auto-fixed, regardless of risk level flags. They require the explicit `--i-understand-system-namespaces` flag (intentionally long and awkward — a friction mechanism).

**Recognized system namespaces** (built-in, extensible via config):
- `kube-system`, `kube-public`, `kube-node-lease`
- `rook-ceph`, `rook-ceph-system`
- `calico-system`, `calico-apiserver`, `tigera-operator`
- `cilium`, `cilium-system`
- `ingress-nginx`, `traefik`, `traefik-system`
- `cert-manager`
- `monitoring`, `prometheus`, `grafana`
- `istio-system`, `linkerd`, `linkerd-cni`
- `metallb-system`
- `longhorn-system`, `openebs`
- Any namespace matching configurable patterns

**Known-workload detection** — Even outside system namespaces, the tool detects system-critical workloads by image name, well-known labels, or resource patterns:
- CNI plugins (Calico, Cilium, Flannel) → need `hostNetwork`, `privileged`
- Storage operators (Rook-Ceph, Longhorn, OpenEBS) → need `privileged`, `hostPath`
- Node exporters (Prometheus) → need `hostPID`, `hostNetwork`
- kube-proxy → needs `hostNetwork`, capabilities
- CoreDNS → needs `NET_BIND_SERVICE`

When detected:
```
⛔ SKIPPED: calico-node (DaemonSet in kube-system)
   Reason: Detected as CNI plugin (image: calico/node:v3.27)
   CNI plugins require elevated privileges by design.
   These findings are expected and should be exempted, not fixed.
```

#### Ring 4 — Interactive Confirmation for Bulk Operations

When `--apply` would modify more than a configurable threshold (default: 10 files), the tool pauses for confirmation:

```
⚠️  This will modify 47 files across 12 namespaces.

  Safe fixes:          31 (will be applied)
  Skipped (system ns):  8 (protected)
  Skipped (risk > safe): 8 (use --risk-level to include)
  
  Namespaces affected: production, staging, dev, qa, ...
  Backup directory:    ./manifests.bak-20260217T143022/
  
  Review the dry-run output first?  [Y/n]    ← defaults to YES
  Apply 31 safe fixes?              [y/N]    ← defaults to NO
```

**CI mode detection** — When `CI=true` env var is set or stdin is non-TTY:
- `--apply` without `--yes` fails with: `Error: --apply in non-interactive mode requires --yes flag.`
- With `--yes`, still prints the summary (visible in CI logs) but proceeds without prompting.

The `--yes` flag skips confirmation but does NOT bypass system namespace protection or risk classification.

#### Ring 5 — Mandatory Backup with Restore Instructions

Every fix operation creates a structured backup directory:

```
./manifests.bak-20260217T143022/
├── production/
│   ├── deployment-web.yaml     # original before fix
│   └── deployment-api.yaml
├── staging/
│   └── deployment-web.yaml
└── RESTORE.md                  # Generated restore instructions
```

After every fix, the tool prints:
```
Backup created: ./manifests.bak-20260217T143022/

To restore ALL files:
  cp -r ./manifests.bak-20260217T143022/* ./manifests/

To restore a single file:
  cp ./manifests.bak-20260217T143022/production/deployment-web.yaml ./manifests/production/
```

### 7.4 Fix Impact Summary

Before and after every fix operation (including dry-run), a summary is displayed:

```
KubeVigil Fix Summary
─────────────────────
Files scanned:       156
Files to modify:      23
Findings total:       65

By risk classification:
  Safe fixes:          31  [will be applied]
  Likely safe fixes:   12  [skipped — use --risk-level moderate]
  Potentially breaking: 4  [skipped — use --risk-level aggressive]
  Manual only:          0  [guidance printed below]

Skipped:
  System namespaces:   14  [kube-system(8), rook-ceph(4), calico-system(2)]
  Exempted:             3  [annotation-based]
  Already fixed:        1

Backup: ./manifests.bak-20260217T143022/
Report: ./manifests.bak-20260217T143022/FIX-REPORT.md
```

### 7.5 Fix Report

Every fix generates a changelog-style report saved alongside backups:

```markdown
# KubeVigil Fix Report — 2026-02-17T14:30:22Z

## Summary
- Files modified: 23 / 156 scanned
- Fixes applied: 31
- Risk level: safe (default)

## Changes by File

### production/deployment-web.yaml (3 fixes)

1. **privileged: true → false**
   Check: privileged | Severity: Critical | Risk: Safe
   
2. **Added: allowPrivilegeEscalation: false**
   Check: privilege-escalation | Severity: High | Risk: Safe
   
3. **Added: readOnlyRootFilesystem: true**
   Check: read-only-rootfs | Severity: Medium | Risk: Likely Safe
   ⚠️  Container "app" has no volume mounts for writable paths.

## Skipped (System Namespaces)
- kube-system/kube-proxy: host-network (expected for kube-proxy)
- rook-ceph/rook-ceph-osd: privileged (expected for storage operator)
```

### 7.6 Helm and Kustomize Awareness

**Helm-managed resources** — When the tool detects Helm labels (`app.kubernetes.io/managed-by: Helm`, `helm.sh/chart`) on resources in manifest files, it warns:
```
⚠️  These resources appear to be Helm-managed. Direct manifest patches
   will be overwritten on next `helm upgrade`. Consider:
   kubevigil fix --output helm-values ./manifests/
```

**Kustomize-managed resources** — When `kustomization.yaml` or `kustomization.yml` is detected in the target directory:
```
⚠️  Kustomize structure detected. Patching base manifests may conflict
   with overlays. Consider:
   kubevigil fix --kustomize ./overlays/security/ ./manifests/
```

### 7.7 Fix Conflict Resolution

When multiple fixes target the same YAML node (e.g., two checks both want to modify `securityContext`), fixes are merged intelligently rather than applied sequentially:

- Fixes to different fields within the same parent node are merged.
- If two fixes set the same field to different values, the higher-severity check's fix takes precedence and the conflict is reported.
- The fix report documents any merge decisions made.

### 7.7a Partial Failure Resilience

When processing large directories, individual file failures MUST NOT crash the entire fix operation. The fixer handles errors on a per-file basis:

- **Malformed YAML** — File is skipped, error recorded, remaining files continue processing.
- **Permission denied** — File is skipped (read-only or insufficient permissions), error recorded, remaining files continue.
- **Unexpected YAML structure** — File is skipped, error recorded, remaining files continue.
- **Backup failure** — If backup of a specific file fails, that file is NOT patched (safety first), but other files continue.

**No all-or-nothing behavior.** Already-patched files are NOT rolled back when a subsequent file fails. The backup exists for manual rollback if needed.

The fix summary reports both successes and failures:

```
Fix Summary:
  Applied:    23 files patched successfully
  Failed:      2 files (see errors below)

  Errors:
    ✗ manifests/broken.yaml — YAML parse error at line 42: unexpected mapping key
    ✗ manifests/readonly.yaml — permission denied: write access required

  Exit code: 5 (partial success)
```

**Fix-specific exit codes** (in addition to scan exit codes in Section 8.1):

| Code | Meaning |
|------|---------|
| `0` | Fix successful — all planned fixes applied (or dry-run shows changes) |
| `1` | Fix applied but `--verify` found remaining findings |
| `2` | Fix error — total failure (backup failed, no files could be processed) |
| `3` | Configuration error (invalid flags, conflicting options) |
| `4` | No fixable findings found (nothing to do — informational) |
| `5` | Partial success — some fixes applied but N files failed |

### 7.7b Configuration File Integration

The existing `.kubevigil.yaml` config file supports fix-specific settings:

```yaml
fix:
  # Additional system namespaces (extends built-in defaults, never replaces them)
  additionalSystemNamespaces:
    - "custom-infra"
    - "vault"
    - "my-operator-system"
  # Override bulk confirmation threshold (default: 10 files)
  bulkThreshold: 20
  # Default backup directory (default: <source>.bak-<timestamp>/)
  backupDir: "/tmp/kubevigil-backups/"
```

**Rules:**
- `additionalSystemNamespaces` is ADDITIVE — extends `DefaultSystemNamespaces`, never replaces them. Users cannot use config to remove a built-in system namespace from protection.
- CLI flags always override config file values.
- All fix config is optional — sensible defaults apply without any config.

### 7.8 Finding Struct Extension for Fix Support

The `Finding` struct carries enough context for the fixer to generate patches:

```go
type Finding struct {
    // ... existing fields ...
    FieldPath    string      // JSON path to problematic field (e.g., "spec.containers[0].securityContext.privileged")
    CurrentValue interface{} // Current insecure value (e.g., true)
    DesiredValue interface{} // Recommended secure value (e.g., false)
    FixHint      *FixHint    // Optional structured fix metadata
}

type FixHint struct {
    Safety      FixSafety   // safe, likely_safe, potentially_breaking, manual_only
    Description string      // What the fix does
    Impact      string      // What could break
    Operation   FixOp       // set, add, remove, merge
}

type FixSafety string
const (
    FixSafe               FixSafety = "safe"
    FixLikelySafe         FixSafety = "likely_safe"
    FixPotentiallyBreaking FixSafety = "potentially_breaking"
    FixManualOnly         FixSafety = "manual_only"
)

type FixOp string
const (
    FixOpSet    FixOp = "set"    // Set field to DesiredValue
    FixOpAdd    FixOp = "add"    // Add field with DesiredValue (field doesn't exist)
    FixOpRemove FixOp = "remove" // Remove field entirely
    FixOpMerge  FixOp = "merge"  // Merge DesiredValue into existing map/list
)
```

### 7.9 CLI Command Reference

```
kubevigil fix <path>                                # Dry-run: show diff only
kubevigil fix <path> --apply                        # Apply safe fixes
kubevigil fix <path> --apply --risk-level moderate   # Include likely-safe fixes
kubevigil fix <path> --apply --risk-level aggressive # Include potentially-breaking fixes
kubevigil fix <path> --apply --yes                  # Skip confirmation (CI mode)

# Selective fixing
kubevigil fix <path> --checks privileged,run-as-root
kubevigil fix <path> --severity critical,high
kubevigil fix <path> --namespace production
kubevigil fix <path> --exclude-namespace kube-system
kubevigil fix <path> --exclude-infra
kubevigil fix <path> --fingerprint <hash>

# Output generators (no --apply needed — these produce artifacts, not modifications)
kubevigil fix <path> --output kubectl               # kubectl patch commands
kubevigil fix <path> --output helm-values            # security-values.yaml
kubevigil fix <path> --kustomize ./overlays/sec/     # Kustomize overlay directory

# Validation and reporting
kubevigil fix <path> --apply --verify               # Re-scan after fixing
kubevigil fix <path> --apply --report ./report.md    # Save fix report to specific path

# GitOps
kubevigil fix <path> --apply --git-pr               # Create branch + PR (requires gh/glab)

# System namespace override
kubevigil fix <path> --apply --risk-level aggressive --i-understand-system-namespaces

# Backup control
kubevigil fix <path> --apply --backup-dir /tmp/backups/
```

### 7.10 Ignorant vs. Knowledgeable User Gate

| Action | Default (no flags) | Explicit flags required |
|---|---|---|
| See what would change | ✅ Always works | — |
| Apply safe fixes | — | `--apply` |
| Apply moderate-risk fixes | — | `--apply --risk-level moderate` |
| Apply aggressive fixes | — | `--apply --risk-level aggressive` |
| Touch system namespaces | ❌ Hard blocked | `--apply --risk-level aggressive --i-understand-system-namespaces` |
| Skip confirmation | — | `--yes` |
| Run unattended in CI | ❌ Fails without `--yes` | `--apply --yes` (still prints summary) |

Every layer of danger requires an additional explicit opt-in. An ignorant user who runs `kubevigil fix ./manifests/` gets the safe experience — they see a diff, learn what would change, and can proceed deliberately.

---

## 8. CI/CD Integration

### 8.1 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` severity. |
| `1` | Findings found at or above threshold. |
| `2` | Scan error (connection failure, auth issue, timeout). |
| `3` | Configuration error (invalid config, invalid flags). |
| `4` | Partial scan — some checks skipped due to errors (findings still reported). |

### 8.2 CI Platform Support

- **GitHub Actions** — Official action (`stribog/kubevigil-action`). Uploads SARIF to GitHub Security tab. Posts PR comment with finding summary (new/resolved/persisting). Annotates changed files with inline findings. Caches scan baseline between runs.
- **GitLab CI** — Template (`.gitlab-ci.yml` include). Uploads artifacts. Posts MR comment. Supports GitLab SAST report format.
- **Jenkins** — Jenkinsfile library. JUnit report integration. Build status based on findings.
- **Azure DevOps** — Pipeline task. SARIF integration with Azure Boards.
- **Argo CD** — Pre-sync hook resource manifest. Blocks deployment if scan fails. PostSync hook for drift detection.
- **Flux** — Notification provider integration. Health check for scan CronJob.
- **Tekton** — Tekton Task and Pipeline definitions.
- **Generic CI** — Works in any CI via exit codes + JSON/SARIF output + artifact upload.

### 8.3 CI Features

- **Baseline management** — `kubevigil baseline create` captures current findings as accepted baseline. Subsequent scans only flag new findings. Baselines stored as JSON files (committable to Git). Baseline auto-expires stale entries.
- **PR decoration** — Post scan summaries as PR/MR comments. Shows: new findings (🆕), resolved findings (✅), persisting findings, posture score change. Configurable comment format.
- **Gate policies** — Block deployments if scan results exceed configured thresholds. Policies expressed as: "fail if critical > 0 OR high > 5 OR posture_score < 70".
- **Incremental scanning** — In CI, detect changed manifests from `git diff` and scan only those. Significantly faster for large repos. Falls back to full scan if base branch is unavailable.
- **Scan caching** — Cache resource fetches and scan results. In CI, restore cache from previous run to enable delta reporting without re-scanning unchanged resources.

---

## 9. Continuous Monitoring (Operator Mode)

### 9.1 In-Cluster Deployment

- **Kubernetes Operator** — Deploy kubevigil as a controller using `controller-runtime` that watches for resource changes (create, update) and scans new/modified workloads. Findings stored as CRD instances (`SecurityFinding` custom resource) for visibility via `kubectl`.
- **CronJob mode** — Deploy as a CronJob for periodic full-cluster scans. Results stored as ConfigMap, written to PVC, or pushed to external storage. Simpler than operator — good for smaller clusters.
- **Helm chart** — Official Helm chart for both operator and CronJob deployment modes. Configurable via `values.yaml`. Includes ServiceAccount, ClusterRole, and RBAC resources.
- **Air-gapped support** — All container images available as tarballs for `docker load` / `ctr import`. Helm chart supports private registry configuration. No external network calls at runtime.

### 9.2 Monitoring Features

- **Admission Webhook (Validating)** — Reject or warn on insecure workloads at deploy time. Two modes:
  - `enforce` — Reject resources with findings above configured severity. Returns detailed rejection message with remediation.
  - `audit` — Allow all resources but log findings. Sets annotation `kubevigil.io/audit-result` on admitted resources.
  - Configurable per-namespace (e.g., enforce in production, audit in staging).
  - Supports `failurePolicy: Ignore` for safety — webhook unavailability doesn't block deployments.

- **Admission Webhook (Mutating)** — Optionally auto-fix common issues at admission time. Off by default. When enabled, only applies "safe" fixes (see Section 7.2). Sets annotation `kubevigil.io/mutated: "checks=privileged,run-as-root"` for audit trail.

- **Prometheus metrics** — Expose finding counts, scan duration, and posture scores:
  ```
  kubevigil_findings_total{severity="critical", check="privileged", namespace="production"}
  kubevigil_findings_by_namespace{namespace="production", severity="critical"} 
  kubevigil_scan_duration_seconds{scan_type="full"}
  kubevigil_scan_resources_total{kind="Deployment"}
  kubevigil_posture_score{namespace="production", scope="namespace"}
  kubevigil_posture_score{scope="cluster"}
  kubevigil_last_scan_timestamp_seconds
  kubevigil_check_duration_seconds{check="rbac-wildcard-verbs"}
  kubevigil_exemptions_total{namespace="kube-system", check="privileged"}
  kubevigil_webhook_requests_total{action="admit", result="pass"}
  kubevigil_webhook_latency_seconds{action="admit"}
  ```

- **Grafana dashboard** — Pre-built dashboard JSON:
  - Cluster posture score gauge
  - Findings by severity over time (stacked area chart)
  - Top 10 failing checks (bar chart)
  - Namespace comparison (heatmap)
  - Trend line with deployment markers
  - Webhook admit/reject rate

- **Alert rules** — Pre-built Prometheus/Alertmanager rules:
  - `KubeVigilCriticalFinding` — New critical finding detected (immediate alert).
  - `KubeVigilPostureDegraded` — Cluster posture score dropped >10 points in 24h.
  - `KubeVigilScanFailed` — CronJob scan failed to complete.
  - `KubeVigilWebhookDown` — Admission webhook not responding.

- **Event generation** — Emit Kubernetes Events on scanned resources with finding details. Events appear in `kubectl describe` output for the affected resource.

### 9.3 Notifications

- **Slack** — Post scan summaries and critical findings to configurable Slack channels. Rich formatting with severity colors. Thread replies for finding details.
- **Microsoft Teams** — Adaptive card notifications via incoming webhook.
- **Webhook** — Generic webhook (HTTP POST with JSON payload) for custom integrations. Configurable URL, headers, retry policy.
- **Email** — SMTP-based email reports on schedule or threshold breach. HTML-formatted email with inline report.
- **PagerDuty** — Alert integration for critical findings. Supports Events API v2.
- **OpsGenie** — Alert integration with priority mapping.

---

## 10. Trend Analysis & Comparison

### 10.1 Scan History

- **Scan result storage** — Store scan results in:
  - Local SQLite database (`~/.kubevigil/history.db`) — default for CLI usage.
  - In-cluster CRD (`SecurityScanResult`) — for operator mode.
  - S3-compatible storage — for team/enterprise usage.
  - PostgreSQL — for centralized multi-cluster tracking.
- **Automatic retention** — Configurable retention period (default: 90 days, keep last 100 scans per cluster).
- **Trend tracking** — Track finding counts over time per check, severity, namespace, team. Detect patterns: improving, degrading, stable, oscillating.
- **Regression detection** — Automatically detect when previously resolved findings reappear. Regression findings get elevated severity and special flagging in reports.

### 10.2 Comparison

- **Scan diff** — Compare any two scan results: `kubevigil diff scan-20250601.json scan-20250614.json`. Shows new, resolved, and persisting findings with clear visual indicators.
- **Cluster comparison** — Compare security posture across multiple clusters: `kubevigil diff --clusters prod-eu,prod-us`. Highlights policy inconsistencies.
- **Pre/post deployment comparison** — Compare scan before and after a deployment: `kubevigil diff --baseline pre-deploy.json`. Validates that deployment didn't introduce new security issues.
- **Historical trend charts** — In HTML reports, include interactive charts (powered by embedded Chart.js) showing posture score and finding counts over time.
- **SLA tracking** — Track mean time to remediation (MTTR) per severity level. "Average time from finding detection to resolution: Critical=2.1 days, High=8.3 days."

---

## 11. Multi-Tenancy & Enterprise Features

### 11.1 Multi-Cluster

- **Cluster registry** — Define clusters in config with metadata (environment, region, team, criticality):
  ```yaml
  clusters:
    - context: prod-eu
      environment: production
      region: eu-west-1
      criticality: high
    - context: staging
      environment: staging
      criticality: medium
  ```
- **Unified reporting** — Single report spanning multiple clusters with per-cluster breakdown and cross-cluster summary.
- **Cluster posture comparison** — Rank clusters by security posture score. Identify outliers.
- **Fleet-wide policy enforcement** — Apply the same policy config across all clusters. Report which clusters are non-compliant with the fleet policy.
- **Configuration drift** — Detect when clusters that should have identical configurations have diverged (e.g., staging has a NetworkPolicy that production doesn't).

### 11.2 Team & Ownership

- **Resource ownership mapping** — Map findings to teams via:
  - Labels (`team`, `app.kubernetes.io/team`).
  - Annotations (`kubevigil.io/team`).
  - Namespace ownership (defined in config).
  - Default team for unmapped resources.
- **Team-specific reports** — Generate per-team reports: `kubevigil scan --group-by team --team platform`.
- **Team-specific configs** — Different teams can have different exemptions, severity overrides, and notification channels.
- **Notification routing** — Route findings to the responsible team's Slack channel, email, or PagerDuty service.
- **RACI matrix** — In reports, show who is Responsible, Accountable, Consulted, Informed for each finding based on team ownership.

### 11.3 RBAC for the Tool Itself

- **Minimal RBAC** — The tool requires only read access. Document and ship the minimal ClusterRole:
  ```yaml
  rules:
  - apiGroups: ["", "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io", 
                 "policy", "storage.k8s.io", "admissionregistration.k8s.io"]
    resources: ["*"]
    verbs: ["get", "list"]
  ```
- **Scoped RBAC** — For namespace-scoped scans, support Role (not ClusterRole) with namespace-limited access.
- **RBAC audit of self** — `kubevigil scan --check-permissions` validates whether the tool's ServiceAccount has sufficient access for the configured checks. Reports which checks will be skipped due to insufficient RBAC.

---

## 12. Extensibility & Plugin System

### 12.1 Plugin Architecture

- **Go plugin interface** — External checks compiled as Go plugins (`.so` files) that implement the `Checker` interface. Loaded via `--plugin-dir` flag. Version compatibility checked at load time.

- **Rego/OPA policies** — Write custom checks in Rego without recompiling. Each policy receives the Kubernetes resource as input and returns findings:
  ```rego
  package kubevigil.custom.require_team_label

  violation[msg] {
    input.kind == "Deployment"
    not input.metadata.labels.team
    msg := "Deployment must have a 'team' label"
  }
  ```

- **YAML-based simple checks** — For non-programmers. Define checks declaratively:
  ```yaml
  custom_checks:
    - id: require-team-label
      description: "All Deployments must have a 'team' label"
      kinds: [Deployment, StatefulSet, DaemonSet]
      severity: medium
      match:
        field: .metadata.labels.team
        operator: missing
      remediation: "Add a 'team' label to the resource metadata"
      framework_refs:
        custom: ["ORG-SEC-001"]
    
    - id: no-default-namespace
      description: "No workloads in default namespace"
      kinds: [Deployment, StatefulSet, DaemonSet, Job, CronJob]
      severity: medium
      match:
        field: .metadata.namespace
        operator: equals
        value: "default"
  ```

- **Webhook-based checks** — Call an external webhook for each resource to get pass/fail. For integrating with proprietary scanning systems. Configurable timeout, retry, and circuit breaker.

### 12.2 SDK

- **Go SDK** — Importable Go packages for embedding scanning in other Go applications:
  ```go
  import (
      "github.com/stribog/kubevigil/pkg/scanner"
      "github.com/stribog/kubevigil/pkg/checker"
      "github.com/stribog/kubevigil/pkg/report"
  )
  
  s := scanner.New(scanner.WithKubeconfig(path), scanner.WithChecks(checker.All()))
  results, err := s.Scan(ctx)
  rpt := report.NewJSON(results)
  ```
- **API stability** — Packages under `pkg/` are public API with semver guarantees. Packages under `internal/` are private. Breaking changes only in major versions.
- **Event hooks** — Register callbacks: `OnScanStart`, `OnCheckComplete`, `OnFindingDetected`, `OnScanComplete`. For custom processing, metrics, or integration.

---

## 13. Performance & Scalability

### 13.1 Performance Features

- **Concurrent scanning** — Configurable worker pool (`--concurrency`). Default scales with CPU count (GOMAXPROCS).
- **API call batching** — List operations instead of individual gets. Single `List Deployments` instead of N `Get Deployment` calls.
- **Resource cache** — Fetch each resource type once, share across all checks. Cache is read-only and thread-safe.
- **Lazy resource loading** — Only fetch resource types needed by enabled checks. If only running `privileged` and `run-as-root` checks, only Pods and owning controllers are fetched.
- **Pagination** — For large clusters, use K8s API pagination (500 items/page) to bound memory usage.
- **Rate limiting** — Configurable API QPS and burst limits to avoid overwhelming the API server. Default: 50 QPS, 100 burst (matching kubectl defaults).
- **Timeout controls** — Per-check timeout (default: 30s), global scan timeout (default: 5m), API call timeout (default: 10s).
- **Memory efficiency** — Stream-process resources where possible. Don't hold all resources in memory for very large clusters — process in batches by namespace.

### 13.2 Scalability Targets

| Metric | Target | How |
|--------|--------|-----|
| 1,000+ namespaces | < 60s scan time | Concurrent namespace processing, resource caching |
| 10,000+ pods | < 120s, < 500MB memory | Pagination, streaming, owner rollup |
| 50,000+ resources | < 300s, < 1GB memory | Batch processing by namespace |
| 100+ checks | < 10% overhead vs 20 checks | Shared resource cache, concurrent execution |
| Multi-document 10MB YAML | < 5s | Streaming YAML parser, no full-file buffering |

### 13.3 Performance Observability

- **Scan timing report** — `--verbose` shows per-check timing, per-resource-type fetch timing, total API calls.
- **Built-in benchmark suite** — `go test -bench` benchmarks for: check execution, report generation, YAML parsing, config loading.
- **Profiling support** — `--pprof` flag enables pprof HTTP endpoint for CPU/memory profiling during scans.

---

## 14. Developer Experience & Community

### 14.1 Documentation

- **Getting started guide** — Quick start: install, first scan, interpret results, fix first issue. Under 5 minutes.
- **Check reference** — Detailed page for every check: what it detects, why it matters, real-world attack scenario, how to fix (with YAML examples), framework mappings, false positive guidance.
- **Architecture guide** — Design decisions, code organization, data flow, how to add a new check.
- **Contributing guide** — CONTRIBUTING.md with coding standards, PR process, commit conventions, check authoring tutorial, code of conduct.
- **FAQ** — Common questions, comparison with other tools, troubleshooting, "why does check X flag my resource" explanations.
- **Security policy** — SECURITY.md with responsible disclosure process, supported versions, security update timeline.
- **API reference** — Godoc for all public `pkg/` packages.
- **Docs site** — Static site (Hugo or Docusaurus) published to GitHub Pages. Versioned docs matching tool releases.

### 14.2 Community

- **Check authoring tutorial** — Step-by-step guide: scaffold → implement → test → document → PR. Complete in 30 minutes.
- **Check template generator** — `kubevigil dev new-check require-annotations` scaffolds:
  - `internal/checker/require_annotations.go` — Check implementation with TODO markers.
  - `internal/checker/require_annotations_test.go` — Test file with table-driven test skeleton.
  - `test/fixtures/require_annotations_pass.yaml` — Passing fixture.
  - `test/fixtures/require_annotations_fail.yaml` — Failing fixture.
  - `docs/checks/require-annotations.md` — Documentation template.
- **Integration test suite** — Kind-based integration tests that spin up real clusters, deploy fixtures, and validate checks against live resources.
- **Fixture library** — Extensive YAML fixtures (secure and insecure variants) for every check. Used in tests and documentation.
- **Changelog automation** — Conventional commits + automated changelog generation via GoReleaser.
- **Release automation** — GoReleaser-based multi-platform builds with checksums, Cosign signing, and SBOM generation.

### 14.3 Distribution

| Channel | Command / Method |
|---------|-----------------|
| Homebrew (macOS/Linux) | `brew install kubevigil` |
| Krew (kubectl plugin) | `kubectl krew install audit` |
| Go install | `go install github.com/stribog/kubevigil/cmd/kubevigil@latest` |
| Docker | `docker run ghcr.io/stribog/kubevigil scan` |
| GitHub Releases | Signed binaries: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 |
| Nix | `nix-env -iA nixpkgs.kubevigil` |
| Scoop (Windows) | `scoop install kubevigil` |
| AUR (Arch Linux) | `yay -S kubevigil` |
| DEB / RPM | Published to packagecloud or GitHub releases |
| OCI artifact | `crane pull ghcr.io/stribog/kubevigil:latest` |

---

## 15. Differentiators vs. Existing Tools

### 15.1 Design Philosophy

- **Opinionated but overridable** — Ships with strong security defaults but every check, severity, and threshold is configurable. The tool has opinions; the user has the final say.
- **Fix, don't just find** — Every finding includes actionable remediation. The `fix` command actually patches manifests. Most tools stop at reporting.
- **Compliance-native** — Framework mapping is a first-class feature, not an afterthought. Auditors can use the output directly.
- **Solo-operator friendly** — Designed for the reality that many clusters are managed by small teams or solopreneurs. Sensible defaults, minimal config to get started, maximum signal-to-noise ratio.
- **Offline-first** — Full feature parity between live and manifest scan modes. Works in air-gapped environments.
- **Composable** — Every feature works via stdin/stdout pipes, JSON output, and exit codes. Integrates into any workflow.

### 15.2 Competitive Matrix

| Feature | KubeVigil | Polaris | kube-bench | kubescape | Trivy | kube-linter |
|---------|-----------|---------|------------|-----------|-------|-------------|
| Live cluster scan | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Manifest scan | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Helm chart scan | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Auto-remediation | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CIS benchmark | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| MITRE ATT&CK | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Admission webhook | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Trend tracking | ✅ | ❌ | ❌ | ✅* | ❌ | ❌ |
| SARIF output | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Custom policies (Rego) | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| YAML custom checks | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multi-cluster | ✅ | ❌ | ❌ | ✅* | ❌ | ❌ |
| Supply chain (SBOM) | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Solo-operator friendly | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Vulnerability scanning | ❌† | ❌ | ❌ | ✅ | ✅ | ❌ |

*\* Requires cloud/SaaS component. † By design — kubevigil focuses on misconfiguration, not CVEs. Integrates with Trivy/Grype for vulnerability data.*

---

## 16. Testing Strategy

### 16.1 Philosophy: Test Pyramid + Shift-Left + TDD

KubeVigil adopts a **Test Pyramid** strategy (many unit tests → fewer integration tests → minimal E2E tests) combined with **Shift-Left** principles (catch issues as early as possible in the development cycle) and **strict TDD** (Red → Green → Refactor for every feature).

Contract Testing serves as the **glue** between layers — ensuring that the interfaces between components (checker → engine, engine → reporter, CLI → engine) remain stable without requiring full integration tests for every change.

```
                    ╱╲
                   ╱ E2E ╲              Few, slow, high confidence
                  ╱────────╲            Real Kind clusters
                 ╱ Contract  ╲          Interface & schema validation
                ╱──────────────╲        Between every component boundary
               ╱  Integration   ╲       Fake K8s client, real checkers
              ╱──────────────────╲      Component combinations
             ╱     Unit Tests     ╲     Fast, isolated, exhaustive
            ╱──────────────────────╲    Every function, every branch
```

**Target ratios:** 70% unit / 15% integration / 10% contract / 5% E2E

### 16.2 TDD Workflow (Mandatory for All Code)

Every feature and every check follows the Red-Green-Refactor cycle:

**For a new security check (e.g., `privileged`):**

```
Step 1 — RED: Write the failing test first
  → Create test/fixtures/privileged_fail.yaml (insecure manifest)
  → Create test/fixtures/privileged_pass.yaml (secure manifest)
  → Write TestPrivilegedCheck with table-driven test cases
  → Run test → FAIL (checker doesn't exist yet)

Step 2 — GREEN: Minimal implementation
  → Implement PrivilegedChecker that passes all test cases
  → Run test → PASS

Step 3 — REFACTOR: Clean up
  → Extract common patterns
  → Improve error messages
  → Add edge cases to test table
  → Run test → still PASS
```

**For infrastructure code (reporter, config, CLI):**

```
Step 1 — Write the contract/interface test first
  → Define the expected input/output contract
  → Test against the interface, not the implementation

Step 2 — Implement to satisfy the contract

Step 3 — Refactor with confidence (tests protect you)
```

### 16.3 Unit Tests

Unit tests are the foundation. Every function, every branch, every error path.

**16.3.1 Checker Unit Tests**

Each checker gets its own test file with exhaustive table-driven tests:

```go
// internal/checker/privileged_test.go
func TestPrivilegedChecker(t *testing.T) {
    tests := []struct {
        name           string
        fixture        string          // Path to YAML fixture
        expectedCount  int             // Expected number of findings
        expectedSev    Severity        // Expected severity
        expectResource string          // Expected resource in finding
        expectContainer string         // Expected container name
    }{
        // Positive cases (should detect)
        {
            name:            "privileged_true",
            fixture:         "testdata/privileged/pod-privileged-true.yaml",
            expectedCount:   1,
            expectedSev:     SeverityCritical,
            expectResource:  "test-pod",
            expectContainer: "main",
        },
        {
            name:            "privileged_true_init_container",
            fixture:         "testdata/privileged/pod-privileged-init.yaml",
            expectedCount:   1,
            expectContainer: "init-setup",
        },
        {
            name:            "privileged_true_multiple_containers",
            fixture:         "testdata/privileged/pod-privileged-multi.yaml",
            expectedCount:   2,     // Both containers are privileged
        },
        {
            name:            "privileged_in_deployment",
            fixture:         "testdata/privileged/deployment-privileged.yaml",
            expectedCount:   1,
        },
        {
            name:            "privileged_in_statefulset",
            fixture:         "testdata/privileged/statefulset-privileged.yaml",
            expectedCount:   1,
        },
        {
            name:            "privileged_in_daemonset",
            fixture:         "testdata/privileged/daemonset-privileged.yaml",
            expectedCount:   1,
        },
        {
            name:            "privileged_in_job",
            fixture:         "testdata/privileged/job-privileged.yaml",
            expectedCount:   1,
        },
        {
            name:            "privileged_in_cronjob",
            fixture:         "testdata/privileged/cronjob-privileged.yaml",
            expectedCount:   1,
        },
        // Negative cases (should NOT detect)
        {
            name:           "privileged_false",
            fixture:        "testdata/privileged/pod-privileged-false.yaml",
            expectedCount:  0,
        },
        {
            name:           "privileged_not_set",
            fixture:        "testdata/privileged/pod-no-security-context.yaml",
            expectedCount:  0,    // Not set ≠ privileged (default is false)
        },
        {
            name:           "privileged_false_explicit",
            fixture:        "testdata/privileged/pod-secure.yaml",
            expectedCount:  0,
        },
        // Edge cases
        {
            name:           "empty_pod_spec",
            fixture:        "testdata/privileged/pod-empty-spec.yaml",
            expectedCount:  0,
        },
        {
            name:           "nil_security_context",
            fixture:        "testdata/privileged/pod-nil-security-context.yaml",
            expectedCount:  0,
        },
        {
            name:           "pod_level_security_context_only",
            fixture:        "testdata/privileged/pod-level-sc-only.yaml",
            expectedCount:  0,    // privileged is container-level only
        },
        // Sidecar (K8s 1.28+)
        {
            name:            "privileged_native_sidecar",
            fixture:         "testdata/privileged/pod-privileged-sidecar.yaml",
            expectedCount:   1,
            expectContainer: "log-collector",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            resources := loadFixture(t, tt.fixture)
            checker := NewPrivilegedChecker()
            findings, err := checker.Run(context.Background(), resources)
            require.NoError(t, err)
            assert.Len(t, findings, tt.expectedCount)
            if tt.expectedCount > 0 && tt.expectedSev != 0 {
                assert.Equal(t, tt.expectedSev, findings[0].Severity)
            }
            if tt.expectContainer != "" {
                assert.Equal(t, tt.expectContainer, findings[0].Container)
            }
        })
    }
}
```

**16.3.2 Config Unit Tests**

```go
func TestConfigParsing(t *testing.T) {
    // Valid configs
    // Invalid configs (malformed YAML, unknown check IDs, invalid severity)
    // Config merging (base + overlay)
    // Environment variable overrides
    // Default values
    // Config discovery (file search order)
    // Exemption validation (expired, future, matching)
    // Severity overrides
}
```

**16.3.3 Report Unit Tests**

```go
func TestJSONReport(t *testing.T) {
    // Empty findings
    // Single finding
    // Multiple findings with all severities
    // Finding with all fields populated
    // Deduplication
    // Sorting
    // Schema compliance (validate against JSON schema)
}

func TestTextReport(t *testing.T) {
    // Uses golden file comparison
    // No-color mode
    // Truncation for very long messages
    // Unicode handling
}
```

**16.3.4 Finding Unit Tests**

```go
func TestFindingFingerprint(t *testing.T) {
    // Same resource, same check → same fingerprint
    // Different resource, same check → different fingerprint
    // Same resource, different check → different fingerprint
    // Resource recreation (new UID) with same misconfiguration → stable fingerprint
    // Fingerprint stability across tool versions
}

func TestSeverityOrdering(t *testing.T) {
    // Critical > High > Medium > Low > Info
    // Sorting
    // Filtering by threshold
}
```

**16.3.5 Resource Processing Unit Tests**

```go
func TestOwnerRollup(t *testing.T) {
    // Pod owned by Deployment → finding on Deployment
    // Pod owned by StatefulSet → finding on StatefulSet
    // Pod owned by DaemonSet → finding on DaemonSet
    // Pod owned by Job → finding on Job
    // Pod owned by ReplicaSet owned by Deployment → finding on Deployment (two-level)
    // Standalone Pod → finding on Pod
    // Pod with multiple owners → finding on first owner
}

func TestMultiDocumentYAML(t *testing.T) {
    // Single document
    // Multiple documents separated by ---
    // Empty documents between separators
    // Malformed document in middle (others still parsed)
    // Non-K8s documents (skipped gracefully)
}
```

### 16.4 Contract Tests (The Glue)

Contract tests validate that component interfaces remain stable. They sit between unit and integration tests, catching interface breakage without requiring heavy infrastructure.

**16.4.1 Checker Interface Contract**

Every checker must satisfy these contracts:

```go
// internal/checker/contract_test.go
func TestAllCheckersContract(t *testing.T) {
    registry := NewRegistry()
    RegisterAll(registry)

    for _, checker := range registry.All() {
        t.Run(checker.Name(), func(t *testing.T) {
            // Contract: Name() returns non-empty, kebab-case string
            assert.NotEmpty(t, checker.Name())
            assert.Regexp(t, `^[a-z][a-z0-9-]+$`, checker.Name())

            // Contract: Description() returns non-empty string
            assert.NotEmpty(t, checker.Description())

            // Contract: Categories() returns at least one category
            assert.NotEmpty(t, checker.Categories())
            for _, cat := range checker.Categories() {
                assert.Contains(t, validCategories, cat)
            }

            // Contract: SupportedModes() returns at least one mode
            assert.NotEmpty(t, checker.SupportedModes())

            // Contract: RequiredResources() returns valid GVRs
            for _, gvr := range checker.RequiredResources() {
                assert.NotEmpty(t, gvr.Resource)
            }

            // Contract: Run() with empty resources returns no findings, no error
            findings, err := checker.Run(context.Background(), EmptyResourceCache())
            assert.NoError(t, err)
            assert.Empty(t, findings)

            // Contract: Run() with cancelled context returns error
            ctx, cancel := context.WithCancel(context.Background())
            cancel()
            _, err = checker.Run(ctx, EmptyResourceCache())
            assert.Error(t, err)

            // Contract: Run() findings have required fields
            findings, err = checker.Run(context.Background(), loadCheckerFixtures(t, checker.Name()))
            assert.NoError(t, err)
            for _, f := range findings {
                assert.NotEmpty(t, f.Checker)
                assert.Equal(t, checker.Name(), f.Checker)
                assert.NotEmpty(t, f.Message)
                assert.NotEmpty(t, f.Remediation)
                assert.True(t, f.Severity >= SeverityInfo && f.Severity <= SeverityCritical)
                assert.NotEmpty(t, f.Resource)
                assert.NotEmpty(t, f.Kind)
            }
        })
    }
}
```

**16.4.2 Report Format Contracts**

```go
// internal/report/contract_test.go
func TestAllReportersContract(t *testing.T) {
    sampleFindings := generateSampleFindings() // Deterministic test data

    reporters := map[string]Reporter{
        "json":     NewJSONReporter(),
        "yaml":     NewYAMLReporter(),
        "text":     NewTextReporter(),
        "markdown": NewMarkdownReporter(),
        "sarif":    NewSARIFReporter(),
        "junit":    NewJUnitReporter(),
        "csv":      NewCSVReporter(),
    }

    for name, reporter := range reporters {
        t.Run(name, func(t *testing.T) {
            // Contract: Generate() with empty findings produces valid output
            out, err := reporter.Generate(context.Background(), &ScanResult{Findings: nil})
            assert.NoError(t, err)
            assert.NotEmpty(t, out)

            // Contract: Generate() with findings produces valid output
            out, err = reporter.Generate(context.Background(), &ScanResult{Findings: sampleFindings})
            assert.NoError(t, err)
            assert.NotEmpty(t, out)

            // Contract: Output is valid format
            validateFormat(t, name, out)
        })
    }
}

func validateFormat(t *testing.T, format string, data []byte) {
    switch format {
    case "json":
        assert.True(t, json.Valid(data))
        // Validate against published JSON schema
        validateJSONSchema(t, data, "schemas/report-v1.json")
    case "sarif":
        assert.True(t, json.Valid(data))
        validateJSONSchema(t, data, "schemas/sarif-2.1.0.json")
    case "junit":
        // Validate XML structure
        var testsuites JUnitTestSuites
        assert.NoError(t, xml.Unmarshal(data, &testsuites))
    case "csv":
        reader := csv.NewReader(bytes.NewReader(data))
        records, err := reader.ReadAll()
        assert.NoError(t, err)
        assert.Greater(t, len(records), 0) // At least header row
    }
}
```

**16.4.3 K8s API Response Contracts**

Validate that the tool handles real K8s API responses correctly, even when the API shape changes between versions:

```go
// internal/k8s/contract_test.go
func TestResourceCacheContract(t *testing.T) {
    // Contract: Cache handles nil responses gracefully
    // Contract: Cache handles empty list responses
    // Contract: Cache handles paginated responses (continue token)
    // Contract: Cache handles mixed resource versions (v1, v1beta1)
    // Contract: Cache is thread-safe for concurrent reads
    // Contract: Cache respects context cancellation during fetch
}
```

**16.4.4 CLI ↔ Engine Contract**

```go
// cmd/kubevigil/contract_test.go
func TestCLIEngineContract(t *testing.T) {
    // Contract: --output json produces valid JSON parseable by report.ParseJSON()
    // Contract: --fail-on critical exits 0 when only medium findings exist
    // Contract: --fail-on critical exits 1 when critical findings exist
    // Contract: --namespace flag is passed correctly to scan engine
    // Contract: --checks flag enables only specified checks
    // Contract: Exit codes match specification (0, 1, 2, 3, 4)
}
```

**16.4.5 Config Schema Contract**

```go
func TestConfigSchemaContract(t *testing.T) {
    // Contract: Every check ID referenced in default config exists in registry
    // Contract: Every severity value in config is valid
    // Contract: Config version field is present and matches supported versions
    // Contract: JSON schema file validates all example configs
    // Contract: Config roundtrip (parse → serialize → parse) is lossless
}
```

### 16.5 Integration Tests

Integration tests validate component combinations with realistic (but controlled) data.

**16.5.1 Checker + Fake K8s Client**

```go
// test/integration/checker_test.go
func TestPrivilegedCheckerIntegration(t *testing.T) {
    // Create a fake K8s clientset with realistic resources
    client := fake.NewSimpleClientset(
        &appsv1.Deployment{
            ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "production"},
            Spec: appsv1.DeploymentSpec{
                Template: corev1.PodTemplateSpec{
                    Spec: corev1.PodSpec{
                        Containers: []corev1.Container{{
                            Name:  "app",
                            Image: "nginx:1.25",
                            SecurityContext: &corev1.SecurityContext{
                                Privileged: boolPtr(true),
                            },
                        }},
                    },
                },
            },
        },
    )

    // Run the checker against the fake client
    cache := NewResourceCache(client)
    cache.Fetch(context.Background())

    checker := NewPrivilegedChecker()
    findings, err := checker.Run(context.Background(), cache)

    require.NoError(t, err)
    require.Len(t, findings, 1)
    assert.Equal(t, "production", findings[0].Namespace)
    assert.Equal(t, "web", findings[0].Resource)
    assert.Equal(t, "app", findings[0].Container)
    assert.Contains(t, findings[0].Remediation, "privileged")
}
```

**16.5.2 Full Scan Pipeline (Manifest Mode)**

```go
func TestFullScanManifestMode(t *testing.T) {
    // Scan a directory of fixtures
    // Verify correct number of findings per check
    // Verify report generation
    // Verify exit code
    // Verify exemptions are applied
    // Verify severity filtering
}
```

**16.5.3 Config + Exemptions Integration**

```go
func TestExemptionsIntegration(t *testing.T) {
    // Load config with exemptions
    // Scan resources that match exemptions
    // Verify findings are suppressed
    // Verify exemption log records suppressed findings
    // Verify expired exemptions are not honored
    // Verify annotation-based exemptions
}
```

**16.5.4 Report Pipeline Integration**

```go
func TestReportPipelineIntegration(t *testing.T) {
    // Scan → findings → JSON report → parse JSON → verify
    // Scan → findings → SARIF report → validate SARIF schema → verify
    // Scan → findings → HTML report → verify contains expected content
    // Scan → findings → Markdown report → verify formatting
}
```

**16.5.5 Fix Integration**

```go
func TestFixIntegration(t *testing.T) {
    // Load insecure manifest
    // Run scan → findings detected
    // Run fix on manifest
    // Re-scan fixed manifest → zero findings
    // Verify YAML formatting preserved (comments, ordering)
    // Verify backup file created
}
```

### 16.6 End-to-End Tests

E2E tests run the real binary against real Kubernetes clusters (Kind). These are slow and run in CI only (not on every commit).

**16.6.1 Kind Cluster Test Suite**

```go
// test/e2e/e2e_test.go (build tag: //go:build e2e)

func TestE2E_LiveClusterScan(t *testing.T) {
    // Setup: Create Kind cluster, deploy insecure fixtures
    cluster := setupKindCluster(t)
    defer cluster.Teardown()
    deployFixtures(t, cluster, "test/e2e/fixtures/insecure/")

    // Test: Run kubevigil binary against cluster
    out, exitCode := runKubeVigil(t, "--kubeconfig", cluster.Kubeconfig(),
        "--output", "json", "--fail-on", "critical")

    // Verify: Check findings
    assert.Equal(t, 1, exitCode)
    var result ScanResult
    require.NoError(t, json.Unmarshal(out, &result))
    assert.Greater(t, len(result.Findings), 0)

    // Verify: Critical findings exist
    hasCritical := false
    for _, f := range result.Findings {
        if f.Severity == SeverityCritical {
            hasCritical = true
            break
        }
    }
    assert.True(t, hasCritical)
}

func TestE2E_SecureCluster(t *testing.T) {
    // Deploy only hardened resources
    // Verify zero findings
}

func TestE2E_NamespaceFilter(t *testing.T) {
    // Deploy to multiple namespaces
    // Scan with --namespace filter
    // Verify only findings from filtered namespace
}

func TestE2E_FixAndRescan(t *testing.T) {
    // Deploy insecure resource
    // Scan → findings
    // Fix → apply fixed manifests
    // Re-scan → zero findings for fixed checks
}

func TestE2E_AdmissionWebhook(t *testing.T) {
    // Install webhook in Kind cluster
    // Attempt to deploy insecure resource → rejected
    // Deploy secure resource → admitted
    // Check audit events for webhook decisions
}

func TestE2E_MultiDocumentStdin(t *testing.T) {
    // Pipe multi-document YAML via stdin
    // Verify all documents scanned
}

func TestE2E_ExitCodes(t *testing.T) {
    // Test all exit codes (0, 1, 2, 3, 4) against real scenarios
}
```

**16.6.2 Cross-Version Testing**

```go
func TestE2E_KubernetesVersions(t *testing.T) {
    versions := []string{"1.25", "1.26", "1.27", "1.28", "1.29", "1.30"}
    for _, v := range versions {
        t.Run("k8s-"+v, func(t *testing.T) {
            cluster := setupKindCluster(t, withKubernetesVersion(v))
            defer cluster.Teardown()
            // Run standard test suite against each version
            // Verify version-aware checks adapt correctly
        })
    }
}
```

### 16.7 Specialized Test Types

**16.7.1 Golden File Tests (Reports)**

Report output is compared against committed golden files. When report format changes intentionally, golden files are regenerated.

```go
func TestTextReport_GoldenFile(t *testing.T) {
    findings := loadDeterministicFindings()
    report := NewTextReporter(WithNoColor())
    output, _ := report.Generate(context.Background(), findings)

    golden := filepath.Join("testdata", "golden", "text-report.txt")
    if *update {
        os.WriteFile(golden, output, 0644)
        return
    }
    expected, _ := os.ReadFile(golden)
    assert.Equal(t, string(expected), string(output))
}
```

**16.7.2 Fuzzing**

Fuzz testing for parsers and input handlers to catch panics and edge cases:

```go
func FuzzYAMLManifestParsing(f *testing.F) {
    // Seed corpus with valid manifests
    f.Add([]byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test"))

    f.Fuzz(func(t *testing.T, data []byte) {
        // Must not panic
        _, _ = ParseManifests(data)
    })
}

func FuzzConfigParsing(f *testing.F) {
    f.Add([]byte("version: \"1\"\nsettings:\n  severity_threshold: medium"))
    f.Fuzz(func(t *testing.T, data []byte) {
        _, _ = ParseConfig(data)
    })
}

func FuzzJSONReportParsing(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        _, _ = ParseScanResult(data)
    })
}
```

**16.7.3 Property-Based Tests**

Using `gopter` or `rapid` for property-based testing of invariants:

```go
func TestPropertyFindingFingerprint(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        // Property: fingerprint is deterministic
        finding := generateRandomFinding(t)
        fp1 := finding.Fingerprint()
        fp2 := finding.Fingerprint()
        assert.Equal(t, fp1, fp2)
    })

    rapid.Check(t, func(t *rapid.T) {
        // Property: different check IDs → different fingerprints
        f1 := generateRandomFinding(t)
        f2 := f1
        f2.Checker = f1.Checker + "-different"
        assert.NotEqual(t, f1.Fingerprint(), f2.Fingerprint())
    })
}

func TestPropertySeveritySorting(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        // Property: sorting by severity is stable and total
        findings := generateRandomFindings(t, rapid.IntRange(0, 100).Draw(t, "count"))
        sorted := SortBySeverity(findings)
        for i := 1; i < len(sorted); i++ {
            assert.GreaterOrEqual(t, sorted[i-1].Severity, sorted[i].Severity)
        }
    })
}
```

**16.7.4 Mutation Testing**

Use `go-mutesting` or `gremlins` to verify test suite quality. Target: >80% mutation kill rate.

```bash
# CI step
gremlins unleash --threshold 0.80 ./internal/checker/...
```

Mutation testing mutates source code (flipping conditions, removing statements, changing operators) and verifies that tests catch the mutations. A low kill rate indicates weak tests.

**16.7.5 Benchmark Tests**

Performance regression detection:

```go
func BenchmarkFullScan_50Deployments(b *testing.B) {
    resources := generateResources(50, "Deployment")
    checkers := AllCheckers()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        runCheckers(checkers, resources)
    }
}

func BenchmarkFullScan_500Deployments(b *testing.B) { ... }
func BenchmarkFullScan_5000Deployments(b *testing.B) { ... }

func BenchmarkJSONReportGeneration(b *testing.B) { ... }
func BenchmarkYAMLParsing_LargeFile(b *testing.B) { ... }
func BenchmarkConfigLoading(b *testing.B) { ... }
```

**16.7.6 Snapshot Tests (Schema Evolution)**

Detect unintended changes to output schemas:

```go
func TestJSONOutputSchema_Snapshot(t *testing.T) {
    // Generate JSON output from deterministic input
    // Compare against committed schema snapshot
    // Fail if schema changed (forcing intentional schema version bump)
}
```

### 16.8 Test Infrastructure

**16.8.1 Test Fixture Organization**

```
test/
├── fixtures/                       # Shared YAML fixtures
│   ├── privileged/
│   │   ├── pod-privileged-true.yaml
│   │   ├── pod-privileged-false.yaml
│   │   ├── pod-privileged-init.yaml
│   │   ├── pod-privileged-sidecar.yaml
│   │   ├── deployment-privileged.yaml
│   │   ├── statefulset-privileged.yaml
│   │   ├── daemonset-privileged.yaml
│   │   ├── job-privileged.yaml
│   │   └── cronjob-privileged.yaml
│   ├── capabilities/
│   ├── run-as-root/
│   ├── ... (per-check fixture directories)
│   ├── secure/                     # Fully hardened resources (zero findings)
│   │   ├── deployment-secure.yaml
│   │   └── ...
│   ├── combined/                   # Resources with multiple issues
│   │   ├── deployment-everything-wrong.yaml
│   │   └── ...
│   └── configs/                    # Test config files
│       ├── valid-full.yaml
│       ├── valid-minimal.yaml
│       ├── invalid-syntax.yaml
│       ├── invalid-check-id.yaml
│       └── ...
├── golden/                         # Golden file outputs
│   ├── text-report.txt
│   ├── json-report.json
│   ├── markdown-report.md
│   └── ...
├── integration/                    # Integration test code
├── e2e/                            # E2E test code (build-tagged)
│   └── fixtures/                   # E2E-specific manifests
│       ├── insecure/
│       └── secure/
├── helpers/                        # Shared test utilities
│   ├── fixture_loader.go
│   ├── assertion_helpers.go
│   ├── kind_cluster.go
│   └── fake_client.go
└── schemas/                        # Output validation schemas
    ├── report-v1.json              # JSON Schema for report output
    ├── sarif-2.1.0.json            # SARIF schema
    └── config-v1.json              # Config file schema
```

**16.8.2 Test Helpers**

```go
// test/helpers/fixture_loader.go

// LoadFixture reads a YAML fixture and returns a ResourceCache
func LoadFixture(t *testing.T, path string) *ResourceCache

// LoadFixtureRaw reads raw YAML bytes
func LoadFixtureRaw(t *testing.T, path string) []byte

// MustLoadConfig loads a config file or fails
func MustLoadConfig(t *testing.T, path string) *Config

// AssertFinding checks that a finding matches expected values
func AssertFinding(t *testing.T, finding Finding, expected ExpectedFinding)

// RunCheckerWithFixture is a convenience for: load fixture → run checker → return findings
func RunCheckerWithFixture(t *testing.T, checker Checker, fixturePath string) []Finding
```

**16.8.3 Test Data Generation**

```go
// test/helpers/generators.go

// GenerateDeployment creates a Deployment with configurable security settings
func GenerateDeployment(opts ...DeploymentOption) *appsv1.Deployment

// GeneratePod creates a Pod for testing
func GeneratePod(opts ...PodOption) *corev1.Pod

// Options:
// WithPrivileged(bool)
// WithRunAsRoot(bool)
// WithCapabilities(add, drop []string)
// WithResourceLimits(cpu, mem string)
// WithHostNetwork(bool)
// WithNamespace(string)
// WithLabels(map[string]string)
// etc.
```

### 16.9 CI Pipeline Test Stages

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  # Stage 1: Fast feedback (< 2 minutes)
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: golangci/golangci-lint-action@v4
        with:
          args: --timeout=5m

  unit:
    runs-on: ubuntu-latest
    steps:
      - run: go test -race -count=1 -coverprofile=coverage.out ./internal/... ./pkg/...
      - run: go tool cover -func=coverage.out | grep total
      - uses: codecov/codecov-action@v4

  # Stage 2: Deeper validation (< 5 minutes)
  contract:
    runs-on: ubuntu-latest
    needs: [unit]
    steps:
      - run: go test -race -tags=contract ./test/contract/...

  integration:
    runs-on: ubuntu-latest
    needs: [unit]
    steps:
      - run: go test -race -count=1 ./test/integration/...

  fuzz:
    runs-on: ubuntu-latest
    needs: [unit]
    steps:
      - run: go test -fuzz=. -fuzztime=60s ./internal/...

  # Stage 3: Comprehensive (< 15 minutes, only on main/release)
  e2e:
    runs-on: ubuntu-latest
    needs: [integration, contract]
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')
    strategy:
      matrix:
        k8s-version: ["1.27", "1.28", "1.29", "1.30"]
    steps:
      - uses: helm/kind-action@v1
        with:
          node_image: kindest/node:v${{ matrix.k8s-version }}.0
      - run: go test -race -tags=e2e -count=1 -timeout=15m ./test/e2e/...

  benchmark:
    runs-on: ubuntu-latest
    needs: [unit]
    if: github.ref == 'refs/heads/main'
    steps:
      - run: go test -bench=. -benchmem ./internal/... | tee bench.txt
      - uses: benchmark-action/github-action-benchmark@v1

  mutation:
    runs-on: ubuntu-latest
    needs: [unit]
    if: github.ref == 'refs/heads/main'
    steps:
      - run: gremlins unleash --threshold 0.75 ./internal/checker/...

  # Stage 4: Release validation
  release-test:
    runs-on: ubuntu-latest
    needs: [e2e]
    if: startsWith(github.ref, 'refs/tags/')
    steps:
      - run: goreleaser build --snapshot --clean
      - run: ./dist/kubevigil_linux_amd64/kubevigil version
      - run: ./dist/kubevigil_linux_amd64/kubevigil scan --file test/fixtures/secure/ --fail-on info
```

### 16.10 Test Quality Metrics & Enforcement

| Metric | Target | Enforcement |
|--------|--------|-------------|
| Line coverage | ≥ 85% | CI gate (codecov) |
| Branch coverage | ≥ 80% | CI gate |
| Checker coverage | 100% of checkers have tests | Contract test verifies |
| Fixture coverage | Every check has pass + fail fixtures | CI check script |
| Mutation kill rate | ≥ 75% | Weekly CI job |
| Fuzz corpus | No panics in 60s fuzz runs | CI gate |
| Benchmark regression | < 10% degradation vs baseline | Benchmark action alert |
| Test execution time | Unit < 30s, Integration < 120s, E2E < 600s | CI timeout |
| Golden file freshness | Updated on schema changes | CI check |
| Zero flaky tests | No test marked `t.Skip("flaky")` | Linter rule |

### 16.11 Test Philosophy Summary

```
SHIFT-LEFT:
  Pre-commit → lint + unit tests (< 30s via git hook)
  PR → lint + unit + contract + integration + fuzz (< 5 min)
  Main → all of above + E2E + benchmark + mutation (< 15 min)
  Release → all of above + multi-K8s-version E2E + release binary test

TDD CYCLE (enforced by code review):
  1. Write test (including fixture YAML) FIRST
  2. Verify test fails (Red)
  3. Implement minimal code to pass (Green)
  4. Refactor (clean, extract, generalize)
  5. Add edge cases to test table
  6. Verify contract tests still pass

CONTRACT TESTING (the glue):
  Checker ↔ Registry: All checkers satisfy Checker interface contract
  Engine ↔ Reporter: All reporters handle all finding shapes
  CLI ↔ Engine: Exit codes, flags, and output format contracts
  Tool ↔ K8s API: Resource shape and pagination contracts
  Tool ↔ User: Output schema contracts (JSON Schema, SARIF Schema)
```

---

## 17. Roadmap Phases

### Phase 1 — Foundation (MVP, Weeks 1-4)
Core scanning engine, resource cache, checker interface + registry, 15 workload security checks (all of 2.1), live cluster and manifest scan modes, text + JSON output, basic CLI with cobra, basic config with exemptions. **Full TDD from day one.** Unit tests + contract tests for checker interface.

### Phase 2 — Breadth (Weeks 5-8)
Complete check library (all 112 checks across all categories), RBAC and network checks, CIS benchmark mapping, HTML + Markdown + SARIF output, `--fail-on` for CI, severity filtering. Integration tests with fake K8s client.

### Phase 3 — Remediation (Weeks 9-11)
`kubevigil fix` auto-remediation engine. Dry-run by default (safe-by-design). YAML round-trip patching preserving comments/formatting. Five-ring safety model: dry-run default, fix classification (safe/likely-safe/potentially-breaking/manual-only), system namespace hard block with known-workload detection, interactive bulk confirmation, mandatory structured backups with restore instructions. Finding struct extended with CurrentValue/DesiredValue/FixHint. Selective fixing by check, severity, namespace, fingerprint. kubectl patch generation, Kustomize overlay generation, Helm values generation, GitOps PR generation. Fix report (changelog). --verify re-scan. CI mode detection. Fix integration tests (scan → fix → re-scan → zero findings). YAML round-trip tests (comment/format preservation). E2E fix scenarios.

### Phase 4 — Distribution (Weeks 12-13)
GoReleaser producing cross-platform binaries (Linux/macOS/Windows, amd64/arm64). GitHub Releases with prebuilt binaries, checksums, and CHANGELOG excerpt. Homebrew tap. Krew kubectl plugin manifest. Dockerfile + container image. One-liner install script. README installation instructions overhaul.

### Phase 5 — Feedback & Hardening (Weeks 14-16)
Real-world testing against production clusters. Severity calibration and false-positive tuning. Bug fixes from early adopters. Check noise reduction. UX polish based on user feedback. Documentation improvements driven by user confusion.

### Phase 6 — CI/CD (Weeks 17-19)
GitHub Action, baseline management, PR decoration, incremental scanning, JUnit output. E2E tests with Kind clusters. Multi-K8s-version testing matrix.

### Phase 7 — Continuous (Weeks 20-23)
Admission webhook (validating + mutating), CronJob deployment, Prometheus metrics, Grafana dashboard, Slack notifications. Webhook E2E tests.

### Phase 8 — Enterprise (Weeks 24-29)
Multi-cluster scanning, trend analysis with SQLite storage, team ownership mapping, custom Rego policies, scan comparison. Property-based tests for trend analysis.

### Phase 9 — Ecosystem (Weeks 30+)
Go SDK with public API, plugin system, check template generator, comprehensive docs site, Helm chart distribution, Cosign binary signing. Benchmark regression tracking, mutation testing gate.

---

## Appendix A: Go Learning Progression

| Phase | Go Concepts Practiced |
|-------|----------------------|
| Phase 1 | Structs, interfaces, error handling, packages, modules, `client-go`, CLI flags (cobra), JSON marshaling, goroutines + errgroup, table-driven tests, test fixtures, `testing.T` |
| Phase 2 | Type switches, complex struct hierarchies, K8s API types, YAML parsing (gopkg.in/yaml.v3), sorting (sort.Slice), generics (where applicable), `slog` structured logging, contract testing patterns |
| Phase 3 | File I/O, YAML round-tripping (yaml.v3 Node API), diff algorithms, template generation (`text/template`), fuzzing (`testing.F`), OS environment detection, interactive terminal I/O (TTY detection), `exec.Command` for external tool integration (gh/glab), structured backup/restore patterns |
| Phase 4 | GoReleaser configuration, Makefile enhancements, ldflags injection, Docker multi-stage builds, shell scripting, release engineering |
| Phase 5 | Profiling real workloads, false-positive analysis, severity calibration, user-feedback-driven iteration |
| Phase 6 | CI scripting, SARIF format, golden file testing, property-based testing, baseline diffing |
| Phase 7 | HTTP servers (`net/http`), webhook TLS, Prometheus client library, controller-runtime, admission review types, benchmark testing |
| Phase 8 | Database access (SQLite via modernc), concurrency patterns (channels, select, fan-out/fan-in), context propagation, OPA/Rego integration, mutation testing |
| Phase 9 | Plugin loading (`plugin` package), public API design, backward compatibility, documentation generation (godoc), Helm chart templating |

---

## Appendix B: Competitive Landscape Reference

| Tool | Primary Focus | Key Weakness KubeVigil Exploits |
|------|--------------|-------------------------------|
| Polaris | Config validation | No compliance mapping, no auto-fix, no trend tracking, no SARIF, no Rego |
| kube-bench | CIS benchmarks (node-level) | Node-level only, no workload scanning, no manifest mode, no remediation |
| kubescape | Broad KSPM | Complex, heavy, requires cloud backend for trends, not solo-operator friendly |
| Trivy | Vulnerability + misconfig | Misconfig scanning is secondary to CVE scanning, no auto-fix, no admission webhook |
| Checkov | IaC scanning (Terraform, K8s) | Not K8s-native, no live cluster mode, no admission webhook, no K8s-aware context |
| kube-linter | Manifest linting | No live cluster, no compliance mapping, no reporting beyond text, limited check library |
| Datree | Policy enforcement | **Deprecated/EOL** — community needs a replacement. KubeVigil fills this gap. |
| Terrascan | IaC scanning | Multi-cloud focus dilutes K8s depth, no live cluster, limited K8s checks |
| Falco | Runtime security | Runtime-only (post-deployment), not preventive, doesn't scan manifests |

---

## Appendix C: Full Directory Structure

```
kubevigil/
├── cmd/
│   └── kubevigil/
│       ├── main.go                    # Entry point
│       ├── root.go                    # Root command (cobra)
│       ├── scan.go                    # Scan command
│       ├── fix.go                     # Fix command
│       ├── diff.go                    # Diff command
│       ├── list.go                    # List command
│       ├── explain.go                 # Explain command
│       ├── config.go                  # Config commands
│       ├── watch.go                   # Watch command
│       ├── serve.go                   # Serve command (webhook + metrics)
│       ├── inventory.go               # Inventory command
│       ├── baseline.go                # Baseline commands
│       ├── dev.go                     # Dev commands (new-check scaffold)
│       └── version.go                 # Version command
├── internal/
│   ├── checker/                       # All checker implementations
│   │   ├── checker.go                 # Checker interface definition
│   │   ├── registry.go                # Checker registry
│   │   ├── result.go                  # Finding, Severity types
│   │   ├── category.go                # Check categories
│   │   ├── metadata.go                # Check metadata (frameworks, refs)
│   │   ├── workload/                  # Workload security checks
│   │   │   ├── privileged.go
│   │   │   ├── privileged_test.go
│   │   │   ├── capabilities.go
│   │   │   ├── capabilities_test.go
│   │   │   └── ... (one file per check + test)
│   │   ├── image/                     # Image security checks
│   │   ├── rbac/                      # RBAC checks
│   │   ├── secrets/                   # Secret management checks
│   │   ├── network/                   # Network security checks
│   │   ├── psa/                       # Pod Security Admission checks
│   │   ├── scheduling/                # Scheduling security checks
│   │   ├── storage/                   # Storage security checks
│   │   ├── cluster/                   # Cluster hardening checks
│   │   ├── supply_chain/              # Supply chain checks
│   │   ├── cloud/                     # Cloud provider checks
│   │   └── crd/                       # CRD security checks
│   ├── engine/                        # Scan orchestration
│   │   ├── scanner.go                 # Main scan orchestrator
│   │   ├── scanner_test.go
│   │   ├── resource_cache.go          # K8s resource cache
│   │   ├── resource_cache_test.go
│   │   ├── owner_rollup.go            # Owner reference resolution
│   │   ├── fingerprint.go             # Finding fingerprinting
│   │   ├── version_detect.go          # K8s version detection
│   │   └── manifest_parser.go         # YAML/JSON manifest parsing
│   ├── k8s/                           # Kubernetes client
│   │   ├── client.go                  # Client initialization
│   │   ├── client_test.go
│   │   ├── discovery.go               # API resource discovery
│   │   └── pagination.go              # List pagination helpers
│   ├── report/                        # Report generation
│   │   ├── report.go                  # Reporter interface
│   │   ├── text.go + _test.go
│   │   ├── json.go + _test.go
│   │   ├── yaml.go + _test.go
│   │   ├── markdown.go + _test.go
│   │   ├── html.go + _test.go
│   │   ├── sarif.go + _test.go
│   │   ├── junit.go + _test.go
│   │   ├── csv.go + _test.go
│   │   ├── scoring.go                 # Posture scoring
│   │   └── dedup.go                   # Finding deduplication
│   ├── config/                        # Configuration
│   │   ├── config.go + _test.go
│   │   ├── exemptions.go + _test.go
│   │   ├── discovery.go + _test.go    # Config file discovery
│   │   ├── merge.go + _test.go        # Config merging
│   │   └── validate.go + _test.go
│   ├── fix/                           # Auto-remediation engine
│   │   ├── fixer.go + _test.go        # Fix orchestrator (scan → classify → apply)
│   │   ├── types.go                   # FixHint, FixSafety, FixOp, FixResult types
│   │   ├── registry.go + _test.go     # Fix strategy registry (check → fix mapping)
│   │   ├── yaml_patcher.go + _test.go # YAML round-trip node-level patcher
│   │   ├── safety.go + _test.go       # Safety classification, system NS detection
│   │   ├── known_workloads.go + _test.go # Known system workload detection
│   │   ├── backup.go + _test.go       # Backup creation and restore instructions
│   │   ├── diff.go + _test.go         # Unified diff generation (colored output)
│   │   ├── report.go + _test.go       # Fix report generation (changelog format)
│   │   ├── kubectl_gen.go + _test.go  # kubectl patch command generation
│   │   ├── kustomize_gen.go + _test.go # Kustomize overlay generation
│   │   ├── helm_gen.go + _test.go     # Helm security values generation
│   │   └── gitops.go + _test.go       # GitOps PR generation (gh/glab)
│   ├── frameworks/                    # Compliance framework mappings
│   │   ├── cis.go + _test.go
│   │   ├── mitre.go + _test.go
│   │   ├── nsa.go + _test.go
│   │   └── mapping.go                 # Framework mapping types
│   ├── webhook/                       # Admission webhook
│   │   ├── server.go + _test.go
│   │   ├── handler.go + _test.go
│   │   └── tls.go
│   ├── metrics/                       # Prometheus metrics
│   │   └── metrics.go
│   ├── notify/                        # Notifications
│   │   ├── slack.go + _test.go
│   │   ├── webhook.go + _test.go
│   │   └── email.go + _test.go
│   ├── storage/                       # Scan result storage
│   │   ├── sqlite.go + _test.go
│   │   └── memory.go + _test.go
│   └── version/
│       └── version.go
├── pkg/                               # Public SDK (stable API)
│   ├── scanner/                       # Scanner SDK
│   │   └── scanner.go
│   ├── checker/                       # Checker SDK (for plugins)
│   │   └── types.go
│   └── report/                        # Report SDK
│       └── types.go
├── test/
│   ├── fixtures/                      # YAML fixtures per check
│   ├── golden/                        # Golden file outputs
│   ├── contract/                      # Contract tests
│   ├── integration/                   # Integration tests
│   ├── e2e/                           # E2E tests (build-tagged)
│   ├── helpers/                       # Test utilities
│   └── schemas/                       # Validation schemas
├── configs/
│   └── kubevigil.example.yaml
├── deploy/
│   ├── helm/                          # Helm chart
│   ├── manifests/                     # Raw K8s manifests
│   │   ├── rbac.yaml                  # Minimal RBAC
│   │   ├── cronjob.yaml              # CronJob deployment
│   │   └── webhook.yaml              # Admission webhook
│   └── grafana/
│       └── dashboard.json
├── docs/
│   ├── checks/                        # Per-check documentation
│   ├── architecture.md
│   ├── contributing.md
│   └── faq.md
├── scripts/
│   ├── verify-fixtures.sh             # Check all checks have fixtures
│   └── update-golden.sh              # Regenerate golden files
├── .github/
│   ├── workflows/
│   │   ├── test.yml
│   │   ├── release.yml
│   │   └── benchmark.yml
│   └── ISSUE_TEMPLATE/
├── .golangci.yml                      # Linter config
├── .goreleaser.yml                    # Release config
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── CODE_OF_CONDUCT.md
```

---

*This document is the complete feature and testing specification for KubeVigil v3. It defines the full vision from MVP to ecosystem. Implementation follows the phased roadmap — ship early, test thoroughly, iterate based on community feedback. v3 incorporates the comprehensive auto-remediation engine design with safe-by-default behavior and layered safeguards.*
