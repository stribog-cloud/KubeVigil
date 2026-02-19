# Network Security Checks

KubeVigil includes 12 checks that inspect NetworkPolicies, Ingress resources, Service exposure, DNS configuration, and service mesh settings. These checks examine Namespaces, NetworkPolicies, Ingresses, Services, ConfigMaps (CoreDNS), and Istio PeerAuthentication resources.

All network checks support both **Live** and **Manifest** scan modes.

---

## NetworkPolicies

### `network-policy-missing`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects namespaces that have no NetworkPolicy defined, leaving all pods in the namespace without any network-level access controls. Without NetworkPolicies, every pod can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers. System namespaces are excluded from this check.

**Remediation:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Frameworks:** CIS 5.3.2

---

### `network-policy-default-deny`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects namespaces that have NetworkPolicies but are missing a default-deny ingress or egress policy. A default-deny policy has an empty `podSelector` (selects all pods) and declares the policy type but defines no allow rules. Without default-deny, all traffic is allowed even when other policies exist. System namespaces are excluded, and namespaces with zero policies are skipped (handled by `network-policy-missing`).

**Remediation (ingress):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

**Remediation (egress):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Default-deny is a zero-trust network best practice recommended by the NSA/CISA Kubernetes Hardening Guide.

**Frameworks:** CIS 5.3.2, NSA/CISA

---

### `network-policy-overly-permissive`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects NetworkPolicies that allow all traffic, effectively providing no network segmentation. The check flags ingress rules with an empty `from` list (allows from everywhere) or `ipBlock` with CIDR `0.0.0.0/0` without `except`, and egress rules with an empty `to` list or `0.0.0.0/0` CIDR.

**Remediation:**
```yaml
spec:
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - namespaceSelector:
            matchLabels:
              env: production
      ports:
        - port: 8080
          protocol: TCP
```

For external sources, use `ipBlock` with specific CIDRs and `except` ranges to narrow allowed IP ranges.

**Frameworks:** CIS 5.3.2

---

### `network-policy-egress-unrestricted`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects namespaces without any egress NetworkPolicy restrictions. Without egress policies, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., `169.254.169.254`), or establish reverse shells to attacker-controlled servers. System namespaces are excluded.

**Remediation:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

**Frameworks:** CIS 5.3.2, NSA/CISA

---

## Ingress

### `ingress-no-tls`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Ingress resources without TLS configured, meaning traffic is served over unencrypted HTTP. All traffic between clients and this Ingress is transmitted in plaintext, allowing attackers on the network path to intercept credentials, session tokens, API keys, and other sensitive data through man-in-the-middle attacks.

**Remediation:**
```yaml
spec:
  tls:
    - hosts:
        - app.example.com
      secretName: app-tls-cert
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

Use cert-manager to automate certificate provisioning and renewal via Let's Encrypt or your internal CA.

**Frameworks:** CIS 5.4.1

---

### `ingress-wildcard-host`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Ingress resources with wildcard or empty host rules that match all incoming requests regardless of hostname. This can expose backend services to unintended traffic, enable host header injection attacks, and make it difficult to enforce per-domain security policies like TLS and authentication. Hosts that are empty, `*`, or start with `*.` are flagged.

**Remediation:**
```yaml
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

If multiple domains are needed, create separate rules with explicit hosts for each.

---

### `ingress-class-missing`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Ingress resources without an `ingressClassName` or the deprecated `kubernetes.io/ingress.class` annotation. Without an explicit IngressClass, the Ingress relies on the cluster's default ingress controller. If no default is configured, the Ingress may be silently ignored. If multiple controllers exist, the wrong one may claim it, leading to misrouted traffic or missing security configurations.

**Remediation:**
```yaml
spec:
  ingressClassName: nginx
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

List available IngressClasses with `kubectl get ingressclass` to find the correct class name.

---

## Service Exposure

### `service-type-loadbalancer`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Services exposed as LoadBalancer, which create cloud load balancers that may be publicly accessible without proper access controls. This exposes the service directly to the internet without centralized security controls such as TLS termination, authentication, WAF rules, and rate limiting that an Ingress controller provides.

**Remediation:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: my-app
```

If a LoadBalancer is required, use cloud-specific annotations to restrict access (e.g., `service.beta.kubernetes.io/aws-load-balancer-internal: "true"`) and configure security groups.

**Frameworks:** CIS 5.4

---

### `service-type-nodeport`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Services exposed as NodePort, which open a port (30000-32767) on every node in the cluster, bypassing Ingress controllers and their centralized security controls. Any network client that can reach a cluster node's IP address can access the service, significantly widening the attack surface.

**Remediation:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: my-app
```

Ingress controllers centralize TLS termination, authentication, rate limiting, and access logging in a single entry point. If NodePort is unavoidable, restrict access using firewall rules to limit which source IPs can reach the node ports.

**Frameworks:** CIS 5.4

---

### `external-ips`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Services with `externalIPs` configured, which poses a man-in-the-middle risk documented in CVE-2020-8554. The `externalIPs` field allows a Service to claim arbitrary IP addresses. An attacker with permission to create or update Services can redirect traffic destined for those IPs through their own pods.

**Remediation:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: LoadBalancer
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: my-app
  # externalIPs: []  # Remove this field entirely
```

Enable the `DenyServiceExternalIPs` admission controller to prevent `externalIPs` usage cluster-wide.

**Frameworks:** CVE-2020-8554

---

## DNS & Service Mesh

### `service-mesh-mtls`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Istio PeerAuthentication resources where mTLS is not set to STRICT mode. When mTLS is PERMISSIVE or DISABLE, traffic between services may be unencrypted, allowing eavesdropping and spoofing. The check identifies mesh-wide, namespace-wide, and workload-scoped policies.

**Remediation:**
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: my-namespace
spec:
  mtls:
    mode: STRICT
```

For mesh-wide enforcement, apply the policy in the `istio-system` namespace with no selector. Verify all workloads have Envoy sidecars injected before switching from PERMISSIVE to STRICT.

**Frameworks:** NSA/CISA

---

### `dns-security`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CoreDNS configuration security issues in the `coredns` ConfigMap in `kube-system`. The check identifies three issues:

1. **Insecure forward resolvers** -- DNS queries forwarded without TLS are transmitted in plaintext, allowing network attackers to intercept, log, or spoof DNS responses.
2. **Debug plugin enabled** -- The debug plugin produces verbose output that may expose sensitive DNS query patterns and internal service names.
3. **Missing cache plugin** -- Without DNS caching, every pod DNS query is forwarded to upstream resolvers, increasing latency and vulnerability to DNS attacks.

**Remediation (TLS forwarding):**
```
forward . tls://1.1.1.1 tls://8.8.8.8 {
  tls_servername cloudflare-dns.com
  health_check 5s
}
```

**Remediation (cache):**
```
.:53 {
  errors
  health
  ready
  kubernetes cluster.local
  cache 30
  forward . /etc/resolv.conf
  # debug  # Remove in production
}
```

**Frameworks:** NSA/CISA
