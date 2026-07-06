# Identity & Access (RBAC) Checks

KubeVigil includes 22 checks that inspect service account configuration, token management, role permissions, role bindings, and RBAC-based privilege escalation vectors. These checks examine Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, bare Pods, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, and ServiceAccounts.

All RBAC checks support both **Live** and **Manifest** scan modes.

---

## Service Accounts

### `default-service-account`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads using the default ServiceAccount. The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

**Remediation:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

**Frameworks:** CIS 5.1.5

---

### `automount-token`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects workloads that auto-mount a ServiceAccount token without explicitly disabling it. Most workloads do not call the Kubernetes API. When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

**Remediation:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

**Frameworks:** CIS 5.1.6

---

### `token-projection-config`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads that do not use explicitly configured projected ServiceAccount tokens with expiration and audience restrictions. Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration, reducing blast radius control. The check skips workloads that have `automountServiceAccountToken: false`.

**Remediation:**
```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

---

## Wildcard Permissions

### `rbac-wildcard-verbs`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant wildcard (`*`) verbs, which allows all actions on the specified resources. An attacker who assumes this role can modify or destroy resources, exfiltrate data, or escalate privileges far beyond what the workload actually requires.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]  # Only read access
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "update"]          # Read + update only
```

Enable Kubernetes audit logging and review the audit trail to identify which verbs are actually used before tightening permissions.

**Frameworks:** CIS 5.1.3

---

### `rbac-wildcard-resources`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant access to wildcard (`*`) resources. A wildcard resource grants access to every resource type in the specified API group, including Secrets, ConfigMaps, and any future resource types added to the cluster.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
```

Use `kubectl auth can-i --list --as=system:serviceaccount:ns:sa` to audit the effective permissions of each service account before and after changes.

**Frameworks:** CIS 5.1.3

---

### `rbac-wildcard-apigroups`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant access to wildcard (`*`) API groups. A wildcard API group grants access across every API group in the cluster, including custom resource definitions and any API groups added in the future. An empty string (`""`) in apiGroups means the core API group -- that is NOT a wildcard.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]            # Core API (pods, services, secrets)
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]         # Apps API (deployments, statefulsets)
    resources: ["deployments"]
    verbs: ["get", "list"]
```

Common API groups: `""` (core), `"apps"`, `"batch"`, `"networking.k8s.io"`, `"rbac.authorization.k8s.io"`.

**Frameworks:** CIS 5.1.3

---

## Escalation & Sensitive Access

### `rbac-escalation-verbs`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant escalation-capable verbs (`bind`, `escalate`, `impersonate`). `bind` lets a user assign roles they do not hold, `escalate` lets a user grant permissions beyond their own, and `impersonate` lets a user act as another identity. Any of these can lead to full cluster compromise.

**Remediation:**
```yaml
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["get", "list", "watch"]  # Read-only, no bind/escalate
```

Only cluster administrators and RBAC management controllers should hold these verbs.

**Frameworks:** CIS 5.1.8

---

### `rbac-secret-access`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant read access to Secrets. Roles granting read access to Secrets expose every credential in the namespace, including database passwords, TLS private keys, API tokens, and third-party credentials. A compromised workload with this access can exfiltrate all secrets and pivot to external systems.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["my-app-tls", "my-app-db-creds"]
    verbs: ["get"]
```

For sensitive credentials, consider using an external secrets manager (HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager) with the External Secrets Operator.

**Frameworks:** CIS 5.1.2, MITRE T1552

---

### `rbac-exec-access`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant exec or attach access to pods (`pods/exec`, `pods/attach` with `create` or `*` verbs). Exec/attach access is functionally equivalent to SSH access and allows full control of running containers. An attacker with exec access can read environment variables, access mounted secrets, install tools, and pivot to other systems.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]              # pods only, no sub-resources
    verbs: ["get", "list", "watch"]
  # Do NOT include:
  # resources: ["pods/exec", "pods/attach"]
```

If exec access is required for debugging, restrict it to specific namespaces and enable Kubernetes audit logging to monitor all exec sessions in production.

**Frameworks:** CIS 5.1.3, MITRE T1609

---

### `rbac-log-access`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant access to pod logs (`pods/log`). Applications frequently log sensitive data inadvertently, including authentication tokens, database connection strings, API keys, and personally identifiable information (PII). An attacker with log access can harvest these credentials without needing exec access.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]              # pods only, no sub-resources
    verbs: ["get", "list", "watch"]
  # Grant pods/log only to monitoring-specific roles
```

Configure applications to avoid logging sensitive data. Use structured logging libraries that support field redaction.

**Frameworks:** MITRE T1530

---

### `rbac-node-proxy-access`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant `get`/`create` access to the `nodes/proxy` subresource. The `nodes/proxy` subresource lets a subject send requests directly to a node's kubelet API, which can execute arbitrary commands in any pod on that node, retrieve logs and metrics, and read container filesystem contents -- effectively giving remote code execution across every workload scheduled on the node.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["nodes"]              # nodes only, no proxy subresource
    verbs: ["get", "list"]
  # Do NOT include:
  # resources: ["nodes/proxy"]
```

If node diagnostics are required, use the Kubernetes metrics API or a dedicated monitoring ServiceAccount with tightly scoped, audited access instead of granting nodes/proxy broadly.

**Frameworks:** MITRE T1611, NSA/CISA 3.1

---

### `rbac-csr-approval`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant `update`/`approve` on `certificatesigningrequests/approval` or `signers`. Approving a CertificateSigningRequest mints a signed client certificate for whatever identity the CSR requests -- including `system:masters` or any other cluster identity. A subject that can both submit and approve CSRs (or approve any signer) can escalate to full cluster-admin without ever holding that privilege directly.

**Remediation:**
```yaml
rules:
  - apiGroups: ["certificates.k8s.io"]
    resources: ["certificatesigningrequests"]
    verbs: ["get", "list", "watch"]  # No approval
  # Do NOT include:
  # resources: ["certificatesigningrequests/approval", "signers"]
  #   verbs: ["update", "approve"]
```

Restrict CSR approval to a small, audited set of cluster administrators, and require manual review of every signer-scoped approval grant.

**Frameworks:** MITRE T1078, NSA/CISA 3.1

---

### `rbac-webhook-tampering`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant `update`/`patch`/`delete` access to `ValidatingWebhookConfiguration` or `MutatingWebhookConfiguration` objects. These objects enforce cluster-wide admission control (e.g., OPA Gatekeeper, Kyverno, custom policy engines). A subject that can modify or delete them can silently disable or weaken every security policy they enforce, opening the door to otherwise-blocked malicious workloads.

**Remediation:**
```yaml
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]
    verbs: ["get", "list", "watch"]  # Read-only
```

Only cluster administrators and the controllers that own a given webhook should be able to modify it. Alert on any change to these objects via audit logging.

**Frameworks:** MITRE T1562, NSA/CISA 2.1

---

### `rbac-token-request`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant unrestricted `create` access to `serviceaccounts/token`. The TokenRequest API mints a fresh, valid, bound token for a named ServiceAccount on demand. A subject with unrestricted access to this subresource can impersonate any ServiceAccount in the namespace -- including highly privileged ones -- without ever needing direct access to that ServiceAccount's Secret or RBAC bindings. Distinct from `automount-token`, which governs whether a token is auto-mounted, not who can mint one.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    resourceNames: ["my-app-sa"]     # Pin to one owned ServiceAccount
    verbs: ["create"]
```

Avoid granting this permission cluster-wide or namespace-wide; treat it with the same care as granting direct access to Secrets.

**Frameworks:** MITRE T1078, NSA/CISA 3.1

---

### `rbac-deletecollection-broad`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that grant the `deletecollection` verb on broad resources (`pods`, `secrets`, `*`, or with no `resourceNames` restriction). The `deletecollection` verb deletes every object matching a list call in a single request -- granted broadly, a single API call can destroy every matching object in a namespace or cluster.

**Remediation:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "delete"]  # Single-object delete only
  # Do NOT include:
  # verbs: ["deletecollection"]
```

If bulk cleanup is genuinely required, scope it to a narrow set of `resourceNames` or a dedicated, audited maintenance ServiceAccount.

**Frameworks:** MITRE T1485, NSA/CISA 3.1

---

### `rbac-aggregation-label-injection`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects custom ClusterRoles labeled with a built-in aggregation selector (`rbac.authorization.k8s.io/aggregate-to-{admin,edit,view}: "true"`). The built-in `admin`, `edit`, and `view` ClusterRoles are aggregated: Kubernetes automatically merges the rules of any ClusterRole carrying this label into them. A subject who can only create ClusterRole objects -- not modify `admin`/`edit`/`view` directly -- can still inject arbitrary rules into those aggregated roles simply by applying this label to their own ClusterRole, a documented Kubernetes RBAC privilege-escalation technique.

**Remediation:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-custom-role
  # Remove aggregation labels unless intentional:
  # labels:
  #   rbac.authorization.k8s.io/aggregate-to-admin: "true"
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
```

Restrict `create`/`update` on ClusterRole objects to trusted cluster administrators, and audit any ClusterRole carrying an `aggregate-to-*` label as part of regular RBAC hygiene.

**Frameworks:** MITRE T1068, NSA/CISA 3.1

---

## Bindings

### `rbac-cluster-admin`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects RoleBindings or ClusterRoleBindings that grant the `cluster-admin` ClusterRole. The `cluster-admin` ClusterRole grants unrestricted access to every resource in every namespace, including the ability to create and modify RBAC rules themselves. A compromised identity with cluster-admin privileges has full control of the entire cluster.

**Remediation:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: my-admin
roleRef:
  kind: ClusterRole
  name: my-limited-admin-role    # Scoped permissions
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: User
    name: admin@example.com
    apiGroup: rbac.authorization.k8s.io
```

Conduct periodic access reviews to ensure cluster-admin bindings remain justified and documented.

**Frameworks:** CIS 5.1.1, NSA/CISA

---

### `rbac-group-bindings`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects RoleBindings or ClusterRoleBindings that grant permissions to overly broad system groups (`system:authenticated`, `system:unauthenticated`, `system:anonymous`). `system:authenticated` includes every authenticated identity in the cluster, including all service accounts across all namespaces. `system:unauthenticated` and `system:anonymous` grant access without any authentication.

**Remediation:**
```yaml
subjects:
  - kind: Group
    name: dev-team                    # Specific group
    apiGroup: rbac.authorization.k8s.io
  - kind: ServiceAccount
    name: my-app
    namespace: production             # Specific service account
```

**Frameworks:** CIS 5.1.5, NSA/CISA

---

### `rbac-subject-external`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects bindings that reference external User subjects, which may become stale when users leave the organization or change roles. Individual User subjects in RBAC bindings reference external identities (e.g., from an OIDC provider or client certificates). Unlike groups, user bindings cannot be centrally managed through an identity provider. System users (`system:*`) are excluded from this check.

**Remediation:**
```yaml
subjects:
  - kind: Group
    name: platform-engineers          # Managed by IdP
    apiGroup: rbac.authorization.k8s.io
  # Avoid:
  # - kind: User
  #   name: jane@example.com
```

If individual user bindings are necessary, implement an automated process to reconcile RBAC bindings against your identity provider directory.

**Frameworks:** CIS 5.1

---

### `rbac-crossnamespace-serviceaccount`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects RoleBindings whose `subjects` reference a ServiceAccount in a different namespace than the RoleBinding itself. A RoleBinding's `subjects[].namespace` field silently overrides the binding's own namespace for ServiceAccount subjects -- an unusual cross-namespace trust grant that is frequently accidental (a copy-pasted manifest that forgot to update the subject namespace) but can also be used deliberately to extend trust across a namespace boundary without review. Distinct from `rbac-subject-external` (User subjects) and `rbac-group-bindings` (Group subjects): this specifically targets ServiceAccount subject hygiene.

**Remediation:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: ns-a
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: ns-a    # Matches the binding's own namespace
```

If cross-namespace access is genuinely required, document it explicitly and review it as part of your regular RBAC audit process.

**Frameworks:** NSA/CISA 3.1

---

## Cloud IAM

### `cloud-iam-binding`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects ServiceAccounts with cloud IAM bindings (AWS IRSA, GCP Workload Identity, Azure Workload Identity). Cloud IAM bindings grant pods direct access to cloud provider APIs such as S3, BigQuery, or Key Vault. If the associated cloud IAM role has overly broad permissions, a compromised pod can access, modify, or delete cloud resources far beyond what the workload requires. The check inspects the annotations `eks.amazonaws.com/role-arn`, `iam.gke.io/gcp-service-account`, and `azure.workload.identity/client-id`.

**Remediation:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  annotations:
    # AWS -- use a role scoped to specific resources:
    eks.amazonaws.com/role-arn: arn:aws:iam::123:role/my-app-minimal
    # GCP -- use a service account with only needed permissions:
    iam.gke.io/gcp-service-account: my-app@project.iam.gserviceaccount.com
```

Ensure the cloud IAM role/policy has no wildcard actions or resources. Use condition keys to restrict access by namespace or service account where supported.

---

### `rbac-unused-roles`
**Severity:** Info · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Roles and ClusterRoles that have no matching RoleBinding or ClusterRoleBinding, indicating they may be stale or unnecessary. Unused roles are dormant permissions waiting to be activated. An attacker who can create or modify RoleBindings could bind these unused roles to gain additional privileges. System roles (`system:*`) are excluded from this check.

**Remediation:**
```bash
# Check for any bindings referencing this role
kubectl get rolebindings,clusterrolebindings -A \
  -o json | jq '.items[] | select(.roleRef.name=="unused-role")'

# Remove the unused role
kubectl delete clusterrole unused-role
kubectl delete role unused-role -n my-namespace
```

Implement a regular RBAC hygiene process to review and clean up unused roles quarterly.

**Frameworks:** CIS 5.1
