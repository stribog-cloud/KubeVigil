# Storage Security Checks

KubeVigil includes 5 checks that detect storage-related misconfigurations, covering PVC encryption, reclaim policy risks, CSI driver security, emptyDir volume limits, and projected volume permissions.

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
