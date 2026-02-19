# Cloud Provider Checks

KubeVigil includes 4 checks that detect cloud-provider-specific security misconfigurations on EKS, GKE, and AKS clusters. All cloud provider checks run in Live mode only, since they require access to Node labels, DaemonSets, and NetworkPolicies from the running cluster.

Cloud provider detection is automatic. KubeVigil identifies the provider from node labels (`eks.amazonaws.com/nodegroup` for EKS, `cloud.google.com/gke-nodepool` for GKE, `kubernetes.azure.com/cluster` for AKS) and only runs the provider-specific checks when the corresponding provider is detected.

## Checks

### `eks-imds-access`
**Severity:** High · **Modes:** Live only · **Auto-fix:** No

Detects EKS pods that can access the EC2 Instance Metadata Service (IMDS) at `169.254.169.254` to steal IAM credentials. The check flags two scenarios: pods using `hostNetwork: true` (which share the node's network stack and can always reach IMDS) and pods in namespaces without a NetworkPolicy blocking egress to the IMDS IP. Without blocking, any pod can query the metadata service to obtain the node's IAM role credentials.

> **Note:** This check only runs on clusters detected as AWS EKS.

**Remediation:**
Disable `hostNetwork` unless absolutely required. Deploy a NetworkPolicy in each namespace to block egress to the IMDS IP, enforce IMDSv2 with hop limit 1, and use IRSA (IAM Roles for Service Accounts) for pod-level AWS permissions:

```yaml
# Block IMDS access via NetworkPolicy:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-imds
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [169.254.169.254/32]
```

```bash
# Enforce IMDSv2 with hop limit 1 on EC2 instances:
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

---

### `gke-metadata-concealment`
**Severity:** High · **Modes:** Live only · **Auto-fix:** No

Detects GKE nodes without Workload Identity (GKE Metadata Server) enabled. The check looks for the `iam.gke.io/gke-metadata-server-enabled: "true"` label on nodes. Without Workload Identity, pods can access the GCE metadata server at `169.254.169.254` and retrieve the node's service account token, granting every pod on the node the full IAM permissions of that service account.

> **Note:** This check only runs on clusters detected as Google GKE.

**Remediation:**
Enable GKE Workload Identity on the cluster and node pools, then annotate Kubernetes service accounts to bind them to specific GCP service accounts with least-privilege IAM roles:

```bash
# Enable Workload Identity on the cluster:
gcloud container clusters update CLUSTER \
  --workload-pool=PROJECT_ID.svc.id.goog

# Enable on node pool:
gcloud container node-pools update POOL \
  --cluster CLUSTER \
  --workload-metadata=GKE_METADATA
```

---

### `aks-pod-identity`
**Severity:** Medium · **Modes:** Live only · **Auto-fix:** No

Detects AKS clusters still using the deprecated `aad-pod-identity` instead of Azure Workload Identity. The check looks for DaemonSets whose names or container images contain `aad-pod-identity` or `nmi` (the Node Managed Identity component). `aad-pod-identity` has known security vulnerabilities, including a NMI component that runs as a privileged DaemonSet with host networking, and is no longer receiving security updates.

> **Note:** This check only runs on clusters detected as Azure AKS.

**Remediation:**
Migrate to Azure Workload Identity, which uses federated identity credentials. After migrating all workloads, remove the `aad-pod-identity` DaemonSet components (`nmi` and `mic`) from the cluster:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  annotations:
    azure.workload.identity/client-id: <managed-identity-client-id>
  labels:
    azure.workload.identity/use: "true"
```

---

### `cloud-provider-detection`
**Severity:** Info · **Modes:** Live only · **Auto-fix:** No

Auto-detects the cloud provider from node labels and reports it as an informational finding to confirm which provider-specific security checks are enabled. No action is required unless the detection is incorrect.

Detection is based on node labels:
- **AWS/EKS:** `eks.amazonaws.com/nodegroup`
- **GCP/GKE:** `cloud.google.com/gke-nodepool`
- **Azure/AKS:** `kubernetes.azure.com/cluster`

> **Note:** This check only produces findings in Live mode since it requires access to Node labels.

**Remediation:**
No fix needed. Review the findings from provider-specific checks (`eks-imds-access`, `gke-metadata-concealment`, `aks-pod-identity`) that are enabled based on the detected provider.
