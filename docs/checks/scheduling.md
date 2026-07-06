# Scheduling & Availability Checks

KubeVigil includes 11 checks that detect scheduling misconfigurations that can compromise cluster stability, availability, and isolation boundaries. These checks examine tolerations, PriorityClasses, PodDisruptionBudgets, topology spread constraints, node affinity, HPA configuration, and Job/CronJob resource hygiene.

## Checks

### `toleration-control-plane`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads that tolerate `node-role.kubernetes.io/control-plane` or `node-role.kubernetes.io/master` taints. Only system components should schedule on control-plane nodes. If a compromised workload runs on a control-plane node, an attacker can access the API server, etcd, and scheduler directly, potentially gaining full cluster control.

**Remediation:**
Remove the control-plane toleration from the workload spec. If the workload genuinely needs to run on control-plane nodes, deploy it in the `kube-system` namespace with minimal privileges.

```yaml
spec:
  tolerations:
    # Remove these entries:
    # - key: node-role.kubernetes.io/control-plane
    #   effect: NoSchedule
    # - key: node-role.kubernetes.io/master
    #   effect: NoSchedule
    - key: dedicated
      operator: Equal
      value: my-team
      effect: NoSchedule
```

---

### `toleration-all`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads with a catch-all toleration (`operator: Exists` with an empty key) that matches all taints, allowing the pod to schedule on any node including control-plane nodes, GPU nodes, and nodes tainted for isolation. This bypasses scheduling boundaries and can place workloads where they should not run.

**Remediation:**
Replace the catch-all toleration with specific tolerations for the taints the workload actually needs. Catch-all tolerations are only appropriate for DaemonSets that must run on every node (e.g., log collectors, node monitors).

```yaml
spec:
  tolerations:
    - key: dedicated
      operator: Equal
      value: monitoring
      effect: NoSchedule
    # Remove this catch-all:
    # - operator: Exists
```

---

### `priority-class-system`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects non-system workloads using `system-cluster-critical` or `system-node-critical` PriorityClasses. These are reserved for essential cluster infrastructure like CoreDNS, kube-proxy, and CNI plugins. When application workloads use these classes, they can preempt real system components, causing DNS failures, networking outages, or cluster instability. Workloads in `kube-system`, `kube-public`, and `kube-node-lease` namespaces are excluded.

**Remediation:**
Create and use a custom PriorityClass with a value below system-critical thresholds (which start at 2000000000):

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-high-priority
value: 1000000
preemptionPolicy: PreemptLowerPriority
globalDefault: false
---
spec:
  priorityClassName: app-high-priority
```

---

### `priority-class-missing`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads without a PriorityClass set. Without priority, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance, leading to unpredictable outages.

**Remediation:**
Define PriorityClasses for your workloads and assign them based on importance. Create a tiered priority scheme (e.g., `app-critical: 500000`, `app-medium: 100000`, `app-low: 10000`):

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
spec:
  priorityClassName: app-medium
```

---

### `priority-class-excessive-value`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects custom PriorityClass resources with a `value` approaching the system-reserved range (`>= 1000000000`, within 1B of `system-cluster-critical`'s 2000000000) created by non-system workloads. PriorityClass values this close to the system-reserved range let an ordinary team's PriorityClass effectively guarantee preemption over the entire cluster -- a priority-abuse / scheduling-DoS pattern where one team can starve every other workload. Distinct from `priority-class-system` (which flags workloads *using* the two built-in system priority classes): this flags newly created custom PriorityClass objects whose value itself is excessive.

**Remediation:**
```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: my-team-critical
value: 100000              # Well below the 1,000,000,000 system-reserved threshold
preemptionPolicy: PreemptLowerPriority
globalDefault: false
```

Establish a tiered priority scheme for application workloads (e.g., critical: 500000, medium: 100000, low: 10000) that stays well clear of system-reserved values.

**Frameworks:** MITRE T1499

---

### `pod-disruption-budget`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Deployments and StatefulSets with `replicas > 1` that have no matching PodDisruptionBudget. Without a PDB, Kubernetes can evict all replicas simultaneously during voluntary disruptions like node drains, cluster upgrades, or autoscaler scale-downs, causing complete service downtime despite having multiple replicas.

**Remediation:**
Create a PodDisruptionBudget with a selector matching your workload's pod labels:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: my-app-pdb
spec:
  minAvailable: 1              # Or use maxUnavailable: 1
  selector:
    matchLabels:
      app: my-app              # Must match Deployment/StatefulSet pod labels
```

---

### `topology-spread`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads without topology spread constraints. Without these constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, the entire service goes down despite having multiple replicas.

**Remediation:**
Add topology spread constraints to distribute replicas across failure domains. Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

---

### `node-affinity-untrusted`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads with `nodeSelector` or `nodeAffinity` targeting nodes with labels containing patterns like "spot", "preemptible", or "ephemeral", which may indicate untrusted or ephemeral nodes. Spot and preemptible nodes can be reclaimed by the cloud provider at any time with minimal notice, risking sudden termination and potential data loss for security-sensitive workloads.

**Remediation:**
Target trusted, dedicated node pools for sensitive workloads. Reserve spot and preemptible nodes for fault-tolerant batch workloads:

```yaml
spec:
  nodeSelector:
    node-pool: trusted-dedicated
    # Avoid labels like:
    # cloud.google.com/gke-spot: "true"
    # kubernetes.azure.com/scalesetpriority: spot
```

---

### `hpa-without-requests`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects HorizontalPodAutoscalers targeting workloads that have no resource requests set on their containers. HPA calculates utilization as a percentage of resource requests (e.g., 80% of requested CPU). Without requests defined, the HPA cannot compute meaningful utilization percentages, leading to erratic scaling behavior, unnecessary scale-ups, or failure to scale entirely.

**Remediation:**
Set resource requests on all containers in the target workload. Size requests based on observed steady-state usage:

```yaml
containers:
  - name: app
    resources:
      requests:
        cpu: 250m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

---

### `job-active-deadline-missing`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects `Job` resources without `spec.activeDeadlineSeconds` set. Without it, a Job that hangs (e.g., waiting on an unreachable dependency) or misbehaves (e.g., an infinite retry loop) has no automatic cutoff -- it can occupy node resources and scheduler capacity indefinitely, degrading the cluster for other workloads.

**Remediation:**
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: batch-processor
spec:
  activeDeadlineSeconds: 3600   # Kill the Job if it runs longer than 1 hour
  template:
    spec:
      containers:
        - name: processor
          image: batch-processor:v1
```

Choose a deadline generously above the expected p99 runtime to avoid killing legitimate long-running work.

---

### `cronjob-concurrency-unbounded`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects `CronJob` resources with `concurrencyPolicy: Allow` (the default, or unset) and no `startingDeadlineSeconds`. A CronJob whose runs take longer than its schedule interval will keep launching new, overlapping Job runs indefinitely under these defaults. Each run consumes scheduler and node capacity, and enough pile-up can starve the cluster's own resources -- an operational denial-of-service against the scheduler.

**Remediation:**
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-report
spec:
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid       # Or: Allow + startingDeadlineSeconds
  startingDeadlineSeconds: 300    # Skip a run if it can't start within 5 minutes
```

Use `Forbid` when overlapping runs would be incorrect (most batch jobs); use `Allow` with a `startingDeadlineSeconds` bound only when overlap is intentional and safe.
