# Supply Chain & Lifecycle Checks

KubeVigil includes 7 checks that detect supply chain security risks and container lifecycle concerns, covering container runtime socket access, health probes, lifecycle hooks, and image freshness.

## Checks

### `container-runtime-socket`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Detects pods mounting container runtime sockets (`/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/var/run/crio/crio.sock`, and variants) via hostPath volumes. Mounting the container runtime socket gives the container full control over every container on the node. An attacker can create privileged containers, access secrets from other pods, or escape to the host entirely. This is one of the most critical container escape vectors.

**Remediation:**
Remove the hostPath volume that mounts the runtime socket. If you need to build container images, use rootless builders like Kaniko or Buildah instead of Docker-in-Docker:

```yaml
spec:
  volumes:
    # Remove this volume entirely:
    # - name: docker-sock
    #   hostPath:
    #     path: /var/run/docker.sock
  containers:
    - name: app
      volumeMounts: []            # Remove the corresponding mount
```

---

### `liveness-readiness-probes`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers missing liveness or readiness probes (init containers are excluded). Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. Without a readiness probe, Kubernetes routes live traffic to containers that may still be initializing or temporarily unable to serve requests.

**Remediation:**
Add both liveness and readiness probes. The readiness endpoint should check downstream dependencies to confirm the container is truly ready:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

---

### `startup-probes`
**Severity:** Info · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers that have a liveness probe but no startup probe. Without a startup probe, the liveness probe starts checking immediately after the container starts. If the application takes longer to initialize than the liveness probe allows, Kubernetes kills and restarts the container, creating an infinite restart loop (CrashLoopBackOff). This is especially common with Java/JVM applications, containers loading large ML models, or services that run database migrations on startup.

**Remediation:**
Add a startup probe that gives the container enough time to initialize. The liveness probe is disabled until the startup probe succeeds:

```yaml
containers:
  - name: app
    startupProbe:
      httpGet:
        path: /healthz
        port: 8080
      failureThreshold: 30     # 30 x 10s = 5 minutes to start
      periodSeconds: 10
```

---

### `lifecycle-hooks`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers with preStop hooks that make external network calls. The check looks for network indicators in exec commands (`curl`, `wget`, `http://`, `https://`, `nc`, `ncat`, `netcat`) and flags any preStop hook using `httpGet`. PreStop hooks making network calls can be exploited for data exfiltration during pod termination -- an attacker who modifies a deployment can add a hook that sends sensitive data to an external server every time a pod is terminated, scaled down, or restarted.

**Remediation:**
Replace network-calling preStop hooks with local-only cleanup operations. If external notification is truly required, use a sidecar or controller pattern with egress network policies restricting the destination:

```yaml
lifecycle:
  preStop:
    exec:
      command:
        - /bin/sh
        - -c
        - "kill -SIGTERM 1 && sleep 5"  # Graceful local shutdown
```

---

### `poststart-hook-network-call`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers with a `postStart` lifecycle hook making a network call (`curl`, `wget`, an HTTP request, `nc`/`ncat`). Unlike `lifecycle-hooks` (which only inspects `preStop`), a postStart hook fires on **every** container start -- including every restart, reschedule, or rolling update -- making it a natural place to establish beacon or callback (C2) behavior that blends into normal cluster churn.

**Remediation:**
```yaml
lifecycle:
  postStart:
    exec:
      command:
        - /bin/sh
        - -c
        - "echo started > /tmp/ready"  # Local-only signal
```

If external notification is genuinely required, use an init container or sidecar pattern with egress network policies restricting the destination.

**Frameworks:** MITRE T1071

---

### `image-age`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects container images older than 180 days (configurable). The check uses the `kubevigil.io/image-created` annotation (RFC 3339 timestamp) on workload resources to determine image age, since registry API access is not available during manifest scanning. Stale images accumulate unpatched CVEs in their base image, OS packages, and application dependencies.

**Remediation:**
Rebuild the container image with an up-to-date base image and set up automated CI/CD pipelines that rebuild images on a regular schedule:

```dockerfile
# Update the base image to a recent, patched version:
FROM nginx:1.27-alpine
# Rebuild and push:
# docker build -t myapp:v2.1 .
# docker push myapp:v2.1
```

Annotate workloads with the image creation timestamp to enable this check:

```yaml
metadata:
  annotations:
    kubevigil.io/image-created: "2025-01-15T10:30:00Z"
```

---

### `ephemeral-container-policy`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects ephemeral containers without adequate security restrictions. Ephemeral containers are added to running pods for debugging via `kubectl debug`. Without security restrictions, they can run as root with full capabilities, effectively creating a privileged backdoor into the pod. The check flags ephemeral containers that are missing `securityContext`, have `privileged: true`, have `allowPrivilegeEscalation` not set to `false`, or have `runAsNonRoot` not set to `true`.

**Remediation:**
Apply the same security context standards to ephemeral containers as regular containers. Enforce these standards cluster-wide using Pod Security Admission policies:

```yaml
ephemeralContainers:
  - name: debug
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```
