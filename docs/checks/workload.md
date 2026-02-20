# Workload Security Checks

KubeVigil includes 25 checks that inspect container and pod security contexts, host isolation boundaries, and resource management. These checks apply to Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and bare Pods.

All workload checks support both **Live** and **Manifest** scan modes.

---

## Container Security Context

### `privileged`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects containers running with `privileged: true`, which grants full access to the host including all devices, filesystems, and kernel interfaces. A compromised privileged container can immediately escape to the host node and pivot across the entire cluster.

**Remediation:**
```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

**Frameworks:** CIS 5.2.1, PSS Baseline

---

### `privilege-escalation`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects containers that do not explicitly set `allowPrivilegeEscalation: false`. By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, enabling a process to gain more permissions than its parent.

**Remediation:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

**Frameworks:** CIS 5.2.5, PSS Restricted

---

### `capabilities-added`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects containers that add dangerous Linux capabilities such as `SYS_ADMIN`, `NET_RAW`, `SYS_PTRACE`, `DAC_OVERRIDE`, `SETUID`, `SETGID`, `NET_ADMIN`, `SYS_RAWIO`, `MKNOD`, `SYS_MODULE`, `DAC_READ_SEARCH`, `FOWNER`, `LINUX_IMMUTABLE`, `SYS_CHROOT`, `SYS_BOOT`, `KILL`, and `NET_BIND_SERVICE`. These capabilities dramatically expand the container's attack surface.

**Remediation:**
```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: []  # Only add specific caps after careful review
```

**Frameworks:** CIS 5.2.7-5.2.9, PSS Restricted

---

### `capabilities-not-dropped`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects containers that do not drop ALL capabilities. Containers inherit default Linux capabilities including KILL, SETUID, SETGID, and NET_RAW, which are rarely needed by application code and increase the blast radius of a compromise.

**Remediation:**
```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

**Frameworks:** CIS 5.2.7, PSS Restricted

---

### `run-as-root`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects containers running as root (UID 0) or missing `runAsNonRoot: true`. The check evaluates both container-level and pod-level securityContext with proper inheritance. Running as root gives processes full privileges inside the container, increasing the blast radius of a container breakout.

**Remediation:**
```yaml
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
  runAsGroup: 1000
```

**Frameworks:** CIS 5.2.6, PSS Restricted

---

### `run-as-high-uid`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers where `runAsUser` is explicitly set to a UID below 10000. Low UIDs overlap with well-known system accounts on most Linux distributions (e.g., daemon, www-data, nobody). If a container escapes to the host, it may inherit the permissions of that system account.

**Remediation:**
```yaml
securityContext:
  runAsUser: 65534       # nobody, or any UID >= 10000
  runAsNonRoot: true
  runAsGroup: 65534
```

---

### `run-as-group`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers that are missing `runAsGroup` or have `runAsGroup` set to GID 0. Without an explicit group, the container process runs as the root group (GID 0), which may grant access to group-owned files and resources on the host.

**Remediation:**
```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

**Frameworks:** CIS 5.2.6

---

### `read-only-rootfs`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects containers without `readOnlyRootFilesystem: true`. A writable root filesystem allows attackers to modify binaries, install tools, or persist malware inside the container.

**Remediation:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

**Frameworks:** CIS 5.2.4

---

### `seccomp-profile`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects containers and pods missing a Seccomp profile. Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. The check accepts both container-level and pod-level profiles.

**Remediation:**
```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

**Frameworks:** CIS 5.7.2, PSS Restricted

---

### `apparmor-profile`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers missing an AppArmor profile. AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Uses the Kubernetes 1.30+ `securityContext.appArmorProfile` field.

**Remediation:**
```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

**Frameworks:** CIS 5.7.5

---

### `selinux-options`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers with dangerous SELinux type configurations (`spc_t` or `unconfined_t`) that disable SELinux confinement. On RHEL/CentOS/Fedora nodes where SELinux is enforcing, this removes a critical security boundary.

**Remediation:**
```yaml
securityContext:
  seLinuxOptions:
    type: ""  # Use default confined context
  # Or remove seLinuxOptions entirely
```

**Frameworks:** CIS 5.7.3

---

### `proc-mount`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects containers with `procMount` set to `Unmasked`. Kubernetes masks certain paths in `/proc` by default to prevent containers from accessing sensitive host information. Unmasking `/proc` exposes these paths and can be used for container escapes.

**Remediation:**
```yaml
securityContext:
  procMount: Default
```

**Frameworks:** PSS Baseline

---

### `unsafe-sysctls`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects pods that configure sysctls outside the kubelet's safe allowlist. Unsafe sysctls modify kernel parameters that are not namespaced and can affect the host system and all other pods on the same node. Safe sysctls include: `kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.tcp_syncookies`, `net.ipv4.ping_group_range`, `net.ipv4.ip_unprivileged_port_start`, and `net.ipv4.ip_local_reserved_ports`.

**Remediation:**
```yaml
spec:
  securityContext:
    sysctls:
      - name: net.ipv4.ip_local_port_range
        value: "1024 65535"
```

**Frameworks:** CIS 5.2.11

---

### `share-process-namespace`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects pods with `shareProcessNamespace` enabled. When enabled, all containers in the pod share the same PID namespace, allowing them to see and signal each other's processes. A compromised container can inspect environment variables, read memory, or kill processes in sibling containers.

**Remediation:**
```yaml
spec:
  shareProcessNamespace: false
```

---

### `runtime-class`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects pods that do not specify a RuntimeClass. Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer.

**Remediation:**
```yaml
spec:
  runtimeClassName: gvisor
```

---

## Host Isolation

### `host-pid`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects pods with `hostPID: true`. When hostPID is enabled, containers share the host's PID namespace and can see every process running on the node, including processes from other pods and system daemons. Attackers can exploit this to inspect environment variables containing secrets or signal critical processes.

**Remediation:**
```yaml
spec:
  hostPID: false
```

**Frameworks:** CIS 5.2.2, PSS Baseline

---

### `host-ipc`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** Yes (Safe)

Detects pods with `hostIPC: true`. When hostIPC is enabled, containers can access the host's shared memory segments, semaphores, and message queues. An attacker can read sensitive data from other processes or inject malicious code into shared memory segments used by host services.

**Remediation:**
```yaml
spec:
  hostIPC: false
```

**Frameworks:** CIS 5.2.3, PSS Baseline

---

### `host-network`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects pods with `hostNetwork: true`. Containers with hostNetwork bypass Kubernetes NetworkPolicies entirely and gain access to all network interfaces on the node, including the node's IP and loopback. An attacker can sniff traffic from other pods or access the kubelet API on port 10250.

**Remediation:**
```yaml
spec:
  hostNetwork: false
```

**Frameworks:** CIS 5.2.4, PSS Baseline

---

### `host-ports`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** Yes (Potentially Breaking)

Detects containers that bind to host ports. Binding to a host port exposes the service directly on the node's network interface, bypassing Kubernetes Service abstractions and NetworkPolicies. It also limits scheduling flexibility since two pods cannot share the same host port.

**Remediation:**
```yaml
ports:
  - containerPort: 8080
    protocol: TCP
    # Remove hostPort entirely
```

**Frameworks:** PSS Baseline

---

### `host-path-volumes`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects pods that mount hostPath volumes. hostPath volumes give containers direct, unrestricted access to the host node's filesystem. The severity varies based on the path: `/`, `/etc`, and container runtime sockets are Critical; `/var/log` is High; all others are Medium.

**Remediation:**
```yaml
volumes:
  - name: data
    emptyDir: {}          # Pod-scoped temporary storage
  - name: persistent
    persistentVolumeClaim:
      claimName: my-pvc  # Managed storage
```

**Frameworks:** CIS 5.2.13, PSS Baseline

---

## Resource Management

### `resource-limits-missing`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Potentially Breaking)

Detects containers missing CPU or memory limits. Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and enabling denial-of-service attacks.

**Remediation:**
```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

---

### `resource-requests-missing`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Potentially Breaking)

Detects containers missing CPU or memory requests. Without resource requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node, leading to overcommitment and unpredictable performance.

**Remediation:**
```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

---

### `resource-limits-ratio`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers where the limits-to-requests ratio exceeds 3x for CPU or memory. High ratios cause node overcommitment and increase the risk of OOM kills when multiple pods burst simultaneously.

**Remediation:**
```yaml
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 500m            # 2.5x ratio
    memory: 512Mi        # 2x ratio
```

---

### `ephemeral-storage-limits`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** Yes (Potentially Breaking)

Detects containers missing ephemeral-storage limits. Without limits, containers can fill up the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across the cluster.

**Remediation:**
```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```
