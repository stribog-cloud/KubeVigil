# Storage Security Checks

KubeVigil includes 9 checks that detect storage-related misconfigurations, covering PVC encryption, reclaim policy risks, CSI driver security, emptyDir volume limits, projected volume permissions, subPath symlink risk, inline/generic ephemeral volumes, and VolumeSnapshotClass encryption.

## Checks

### `pvc-no-encryption`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects PersistentVolumeClaims using StorageClasses that have no encryption configuration. The check examines StorageClass parameters for known encryption keys (`encrypted`, `encryption`, `csi.storage.k8s.io/encrypt`, `disk-encryption-kms-key`). PVCs without encryption store data in plaintext on the underlying disk, making data readable if the storage media is decommissioned, stolen, or accessed by an unauthorized party.

**Remediation:**
Create a StorageClass with encryption enabled and reference it in your PVC. Each cloud provider has its own encryption parameter:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: encrypted-gp3
provisioner: ebs.csi.aws.com
parameters:
  encrypted: "true"
  kmsKeyId: arn:aws:kms:...:key/...   # Optional: customer-managed key
---
apiVersion: v1
kind: PersistentVolumeClaim
spec:
  storageClassName: encrypted-gp3
```

AWS EBS uses `encrypted: "true"`, GCP PD uses CMEK via `disk-encryption-kms-key`, and Azure Disk has SSE enabled by default.

---

### `pvc-reclaim-retain`
**Severity:** Medium · **Modes:** Live only · **Auto-fix:** No

Detects PersistentVolumes with `reclaimPolicy: Retain` that are in `Released` state. These volumes contain data but are no longer bound to any claim, representing potential data exposure. If the volume is re-bound or the underlying storage is reused, the previous data may be accessible.

> **Note:** This check runs only in Live mode because it relies on PV status information (`status.phase`), which is not available in static manifests.

**Remediation:**
Either clean up the released PV after backing up data, or change the reclaim policy for future PVCs:

```yaml
# Option 1: Delete the released PV after backing up data
# kubectl delete pv <pv-name>

# Option 2: Change reclaim policy for future PVCs
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: standard
reclaimPolicy: Delete            # Automatically clean up on PVC deletion
```

For sensitive data, ensure volumes are securely wiped before the PV is deleted or reused.

---

### `csi-driver-security`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CSI drivers installed without `podInfoOnMount` enabled. When `podInfoOnMount` is disabled, the CSI driver receives mount requests without knowing which pod initiated them, preventing per-pod access controls. Any pod that references the volume can mount it without identity verification.

**Remediation:**
Enable `podInfoOnMount` on the CSIDriver resource so the driver receives the pod's name, namespace, UID, and service account on every mount request:

```yaml
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: my-csi-driver
spec:
  podInfoOnMount: true           # Sends pod info to driver
  volumeLifecycleModes:
    - Persistent
```

This field is especially important for secret-store CSI drivers and any driver that needs to enforce pod-level access policies.

---

### `emptydir-size-limit`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects emptyDir volumes without a `sizeLimit`. Without a limit, a compromised or misbehaving container can write unlimited data to the node's filesystem, filling the entire node disk, causing kubelet failures, pod evictions, and node instability affecting all workloads on that node.

**Remediation:**
Set a `sizeLimit` on the emptyDir volume based on expected usage. When the limit is exceeded, the pod will be evicted:

```yaml
spec:
  volumes:
    - name: temp-data
      emptyDir:
        sizeLimit: 1Gi           # Set to expected max usage
        medium: ""               # Or Memory for tmpfs
```

---

### `projected-volume-security`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects projected volumes with an overly permissive `defaultMode`. The Kubernetes default file mode for projected volumes is `0644` (world-readable), meaning any process in the pod can read service account tokens, secrets, and configmaps mounted via projected volumes. The check flags volumes with `defaultMode` greater than `0600` or with no explicit `defaultMode` set.

**Remediation:**
Set a restrictive `defaultMode` on the projected volume. Use `0400` (owner read-only) for tokens, or `0600` (owner read-write) if the application needs to modify the files:

```yaml
spec:
  volumes:
    - name: kube-api-access
      projected:
        defaultMode: 0400         # Owner read-only
        sources:
          - serviceAccountToken:
              path: token
```

---

### `subpath-symlink-risk`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects `volumeMounts[].subPath`/`subPathExpr` usage. Older kubelet versions (fixed in CVE-2021-25741) and some third-party CSI drivers resolve the subPath after the container starts, creating a race window where a malicious container can swap the subPath target for a symlink pointing at the host filesystem, escaping the volume boundary. This is a defense-in-depth flag; most modern, patched clusters are not vulnerable, but the risk surface remains for older kubelets and less-maintained CSI drivers.

**Remediation:**
```yaml
volumeMounts:
  - name: data
    mountPath: /app/conf           # Mount the whole volume
# Instead of:
#  - name: data
#    mountPath: /app/conf/conf.yaml
#    subPath: conf.yaml
```

If subPath is unavoidable, ensure kubelet and the CSI driver are patched against CVE-2021-25741 and restrict which images can be scheduled with subPath mounts via admission control.

**Frameworks:** MITRE T1611

---

### `csi-inline-ephemeral-volume`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Pods using CSI ephemeral inline volumes (`spec.volumes[].csi` set directly on the pod), which bypass PVC/StorageClass admission entirely. Depending on the driver, inline volumes can expose node-level resources or secrets (e.g. the Secrets Store CSI driver) directly to the pod without the review a StorageClass-based PVC would typically receive.

**Remediation:**
```yaml
# Instead of an inline CSI volume:
# volumes:
#   - name: v
#     csi:
#       driver: csi.example.com/secrets-store
volumes:
  - name: v
    persistentVolumeClaim:
      claimName: reviewed-pvc
```

If inline CSI volumes are required, restrict which drivers may be used via an admission policy (OPA Gatekeeper/Kyverno) and track approved drivers explicitly.

**Frameworks:** NSA/CISA 1.3

---

### `generic-ephemeral-volume-no-limits`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Pods using a generic ephemeral volume (`spec.volumes[].ephemeral.volumeClaimTemplate`) whose claim template has no `resources.requests.storage`. Without a declared upper bound, a single pod's ephemeral volume can consume unbounded storage -- the same risk `resource-limits-missing` addresses for CPU/memory, applied to per-pod dynamically-provisioned storage.

**Remediation:**
```yaml
volumes:
  - name: scratch
    ephemeral:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 5Gi           # Set to expected max usage
```

Size conservatively based on expected workload usage and monitor actual consumption to tune the request.

---

### `volumesnapshotclass-no-encryption`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects `VolumeSnapshotClass` resources without an encryption parameter set. Not every CSI driver automatically encrypts a VolumeSnapshot just because the source volume was encrypted -- snapshot data, which contains a full point-in-time copy of the volume's contents, may be stored unencrypted in the underlying snapshot storage. Mirrors the same at-rest encryption rationale already applied to PVCs by `pvc-no-encryption`.

**Remediation:**
```yaml
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: encrypted-snapshots
driver: ebs.csi.aws.com
deletionPolicy: Delete
parameters:
  encrypted: "true"          # Or your CSI driver's equivalent key
```

Each cloud provider's CSI driver has its own parameter name for snapshot encryption -- consult its documentation.
