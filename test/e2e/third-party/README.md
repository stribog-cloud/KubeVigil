# KubeVigil E2E -- Third-Party Vulnerable Workloads

This directory contains instructions for deploying and scanning third-party
projects and popular Helm charts to validate KubeVigil against real-world
Kubernetes manifests.

These tests complement the purpose-built scenarios in `test/e2e/scenarios/` by
exercising KubeVigil against workloads it was not specifically designed for.
Findings from third-party scans help identify false positives, false negatives,
and edge cases in checker logic.

---

## Prerequisites

- A running Kubernetes cluster (Kind recommended for isolation):
  ```bash
  kind create cluster --config ../clusters/kind-single-node.yaml
  ```
- `kubectl` configured to point at the cluster
- `kubevigil` binary built and available on PATH:
  ```bash
  cd /path/to/KubeVigil
  make build
  export PATH="$PWD/bin:$PATH"
  ```
- `helm` (v3+) for Helm chart rendering
- `git` for cloning third-party repositories

---

## 1. Kubernetes Goat

[Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) is a
deliberately vulnerable Kubernetes environment designed to teach security
concepts. It deploys workloads with a wide range of misconfigurations.

### Deploy

```bash
# Clone the repository
git clone https://github.com/madhuakula/kubernetes-goat.git /tmp/kubernetes-goat
cd /tmp/kubernetes-goat

# Deploy to the cluster (uses a setup script)
bash setup-kubernetes-goat.sh
```

### Scan -- Live Mode

```bash
# Scan the entire cluster
kubevigil scan -o json > /tmp/kubevigil-k8s-goat-live.json

# Scan a specific namespace deployed by Kubernetes Goat
kubevigil scan --namespace default -o json > /tmp/kubevigil-k8s-goat-default.json
```

### Scan -- Manifest Mode

```bash
# Scan the raw manifests without deploying
kubevigil scan --file /tmp/kubernetes-goat/platforms/kind-setup/ -o json > /tmp/kubevigil-k8s-goat-manifests.json
```

### Expected Findings

Kubernetes Goat intentionally includes many misconfigurations. Expect a high
volume of findings across multiple categories:

- **Workload security:** privileged containers, host namespaces (hostPID,
  hostNetwork), dangerous capabilities, host-path volume mounts, containers
  running as root
- **Image security:** images using `:latest` tags, missing digest pinning
- **RBAC:** overly permissive roles, cluster-admin bindings, default
  ServiceAccount usage
- **Network:** missing NetworkPolicies, exposed services
- **Secrets:** secrets passed via environment variables

A healthy scan should produce **50+ findings** across at least 5 categories.

### Cleanup

```bash
bash teardown-kubernetes-goat.sh
# Or delete the entire cluster:
kind delete cluster --name kubevigil-e2e-single
```

---

## 2. Google Online Boutique (Microservices Demo)

[Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) is
Google's reference microservices application. It represents a well-maintained but
not perfectly hardened production deployment.

### Deploy

```bash
# Clone the repository
git clone https://github.com/GoogleCloudPlatform/microservices-demo.git /tmp/microservices-demo

# Deploy using the release manifest
kubectl apply -f /tmp/microservices-demo/release/kubernetes-manifests.yaml
```

### Scan -- Live Mode

```bash
kubevigil scan --namespace default -o json > /tmp/kubevigil-boutique-live.json
```

### Scan -- Manifest Mode

```bash
kubevigil scan --file /tmp/microservices-demo/release/kubernetes-manifests.yaml -o json > /tmp/kubevigil-boutique-manifests.json
```

### Expected Findings

The Online Boutique is well-structured but still triggers several checks:

- **Image security:** images pinned by tag but missing digest (image-no-digest)
- **Workload security:** some containers may lack seccomp profiles,
  readOnlyRootFilesystem, or dropped capabilities
- **Resource management:** some containers may have relaxed limits-to-requests
  ratios
- **Network:** likely missing NetworkPolicies (network-policy-missing)

Expect **15-30 findings**, mostly Medium and Low severity. This is a useful
benchmark for what a "reasonably well-configured" application looks like through
KubeVigil's lens.

### Cleanup

```bash
kubectl delete -f /tmp/microservices-demo/release/kubernetes-manifests.yaml
```

---

## 3. Popular Helm Charts

Helm chart rendering produces static YAML that can be scanned in manifest mode
without deploying anything. This is the safest and fastest way to validate
KubeVigil against production infrastructure components.

### General Pattern

```bash
# Add the Helm repository
helm repo add <repo-name> <repo-url>
helm repo update

# Render the chart to YAML (no cluster required)
helm template <release-name> <repo-name>/<chart-name> \
  --values <optional-values-file> \
  > /tmp/<chart-name>-rendered.yaml

# Scan the rendered YAML
kubevigil scan --file /tmp/<chart-name>-rendered.yaml -o json > /tmp/kubevigil-<chart-name>.json

# Generate an HTML report for detailed review
kubevigil scan --file /tmp/<chart-name>-rendered.yaml -o html > /tmp/kubevigil-<chart-name>.html
```

### 3a. Bitnami WordPress

A full application stack with PHP, Apache, and MariaDB. Heavy use of
PersistentVolumeClaims and Secrets.

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

helm template wordpress bitnami/wordpress > /tmp/wordpress-rendered.yaml
kubevigil scan --file /tmp/wordpress-rendered.yaml -o json > /tmp/kubevigil-wordpress.json
```

**Expected findings:** secrets-in-env (database credentials often injected as
env vars), resource management findings, image-no-digest, run-as-root (MariaDB
defaults to root), missing seccomp/apparmor profiles.

### 3b. Prometheus / kube-prometheus-stack

The de facto monitoring stack. Includes Prometheus, Alertmanager, Grafana, and
many RBAC resources.

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm template monitoring prometheus-community/kube-prometheus-stack > /tmp/kube-prometheus-rendered.yaml
kubevigil scan --file /tmp/kube-prometheus-rendered.yaml -o json > /tmp/kubevigil-kube-prometheus.json
```

**Expected findings:** RBAC findings are the primary interest here.
Prometheus requires broad read access (get/list/watch on many resource types),
which may trigger rbac-secret-access and broad-role warnings. Expect
image-no-digest across all components. Grafana may trigger secrets-in-env for
admin credentials.

### 3c. ingress-nginx

The most widely deployed Kubernetes ingress controller. Uses hostNetwork or
hostPort in some configurations.

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

helm template ingress ingress-nginx/ingress-nginx > /tmp/ingress-nginx-rendered.yaml
kubevigil scan --file /tmp/ingress-nginx-rendered.yaml -o json > /tmp/kubevigil-ingress-nginx.json
```

**Expected findings:** host-network or host-ports findings (ingress controllers
legitimately bind host ports), capabilities-added (NET_BIND_SERVICE for port 80/443),
privilege-escalation, run-as-root (some nginx configurations require root).
These are interesting because many are legitimate for an ingress controller --
useful for testing exemption workflows.

### 3d. cert-manager

Automated TLS certificate management with RBAC-heavy configuration.

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update

helm template cert-manager jetstack/cert-manager \
  --set crds.enabled=true > /tmp/cert-manager-rendered.yaml
kubevigil scan --file /tmp/cert-manager-rendered.yaml -o json > /tmp/kubevigil-cert-manager.json
```

**Expected findings:** RBAC findings (cert-manager needs broad Secret access for
certificate storage), image-no-digest, resource management findings. CRD
validation checks may fire on the CustomResourceDefinition manifests.

### 3e. Argo CD

GitOps continuous delivery tool with extensive RBAC and multi-component
architecture.

```bash
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update

helm template argocd argo/argo-cd > /tmp/argocd-rendered.yaml
kubevigil scan --file /tmp/argocd-rendered.yaml -o json > /tmp/kubevigil-argocd.json
```

**Expected findings:** RBAC findings (Argo CD manages cluster resources and
needs broad permissions), secrets-in-env, image-no-digest, service-type-nodeport
or service-type-loadbalancer depending on default values.

---

## Cross-Validation with Other Tools

For added confidence, compare KubeVigil findings against other KSPM tools. This
helps identify both false positives (findings other tools do not flag) and false
negatives (findings KubeVigil misses).

### Trivy (Aqua Security)

```bash
# Scan a rendered Helm chart
trivy config /tmp/wordpress-rendered.yaml --format json > /tmp/trivy-wordpress.json

# Scan a live cluster namespace
trivy k8s --namespace default --report summary
```

### Kubescape (ARMO)

```bash
# Scan a manifest file
kubescape scan /tmp/wordpress-rendered.yaml --format json --output /tmp/kubescape-wordpress.json

# Scan a live cluster
kubescape scan --format json --output /tmp/kubescape-cluster.json
```

### Polaris (Fairwinds)

```bash
# Scan a manifest file
polaris audit --audit-path /tmp/wordpress-rendered.yaml --format json > /tmp/polaris-wordpress.json

# Scan a live cluster
polaris audit --format json > /tmp/polaris-cluster.json
```

### Comparison Tips

- Focus on findings that appear in KubeVigil but not in other tools (potential
  false positives) and vice versa (potential false negatives).
- KubeVigil's RBAC checks are more comprehensive than most tools -- expect
  unique findings there.
- Other tools may flag CIS Benchmark items that KubeVigil maps differently.
  Cross-reference using KubeVigil's `--framework cis-1.8` flag.

---

## Storing Results

When running third-party scans, save the output for regression tracking:

```bash
# Create a timestamped results directory
RESULTS_DIR="../results/third-party/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Run scans and save output
kubevigil scan --file /tmp/wordpress-rendered.yaml -o json > "$RESULTS_DIR/wordpress.json"
kubevigil scan --file /tmp/kube-prometheus-rendered.yaml -o json > "$RESULTS_DIR/kube-prometheus.json"
# ... etc.
```

Compare results across KubeVigil versions to catch regressions in check logic.

---

## Notes

1. **Network access.** Helm chart rendering (`helm template`) does not require
   a cluster and does not make network requests (beyond the initial `helm repo
   update`). It is safe to run in CI environments.

2. **Chart versions.** Helm charts evolve rapidly. Pin chart versions in CI to
   get reproducible results:
   ```bash
   helm template wordpress bitnami/wordpress --version 24.1.1 > /tmp/wordpress-rendered.yaml
   ```

3. **False positives are expected.** Infrastructure components (ingress
   controllers, monitoring, cert-manager) legitimately need elevated
   permissions. Use these scans to refine KubeVigil's exemption system, not to
   chase zero findings.

4. **Do not commit third-party manifests.** Rendered Helm charts and cloned
   repositories should go in `/tmp/` or `test/e2e/results/` (which is
   gitignored). Do not commit them to the KubeVigil repository.
