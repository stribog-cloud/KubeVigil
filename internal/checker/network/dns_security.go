package network

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ConfigMapGVR is the GroupVersionResource for ConfigMap.
var ConfigMapGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}

// DNSSecurityChecker detects security issues in CoreDNS configuration, including
// insecure upstream resolvers, debug plugin in production, and missing cache configuration.
type DNSSecurityChecker struct{}

// Name returns the kebab-case check ID.
func (c *DNSSecurityChecker) Name() string { return "dns-security" }

// Description returns a human-readable description.
func (c *DNSSecurityChecker) Description() string {
	return "Detects CoreDNS configuration security issues including insecure resolvers, debug mode, and missing cache."
}

// Categories returns the check categories.
func (c *DNSSecurityChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *DNSSecurityChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *DNSSecurityChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ConfigMapGVR}
}

// Run executes the dns-security check against ConfigMaps in the cache.
func (c *DNSSecurityChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns-security check: %w", err)
	}

	configMaps := resources.List(ConfigMapGVR)
	var findings []checker.Finding

	for i := range configMaps {
		cm := &configMaps[i]

		// Only check ConfigMaps named "coredns" in "kube-system".
		if cm.GetName() != "coredns" {
			continue
		}
		if cm.GetNamespace() != "kube-system" {
			continue
		}

		corefile := extractCorefile(cm)
		if corefile == "" {
			continue
		}

		findings = append(findings, analyzeCorefile(corefile)...)
	}

	return findings, nil
}

// extractCorefile retrieves the Corefile content from a ConfigMap.
func extractCorefile(cm *unstructured.Unstructured) string {
	data, found, err := unstructured.NestedStringMap(cm.Object, "data")
	if err != nil || !found {
		return ""
	}
	corefile, ok := data["Corefile"]
	if !ok {
		return ""
	}
	return corefile
}

// analyzeCorefile parses a Corefile string and returns findings for security issues.
func analyzeCorefile(corefile string) []checker.Finding {
	var findings []checker.Finding

	if f := checkInsecureForward(corefile); f != nil {
		findings = append(findings, *f)
	}
	if f := checkDebugPlugin(corefile); f != nil {
		findings = append(findings, *f)
	}
	if f := checkMissingCache(corefile); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// checkInsecureForward checks if forward directives point to non-TLS resolvers.
func checkInsecureForward(corefile string) *checker.Finding {
	lines := strings.Split(corefile, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "forward") {
			continue
		}

		// Parse the forward directive arguments.
		parts := strings.Fields(trimmed)
		if len(parts) < 3 {
			continue
		}

		// Check each upstream resolver (skip "forward" and the zone).
		for _, resolver := range parts[2:] {
			// Skip block markers and options.
			if resolver == "{" || resolver == "}" {
				break
			}
			if !strings.HasPrefix(resolver, "tls://") {
				return &checker.Finding{
					Checker:   "dns-security",
					Severity:  checker.SeverityMedium,
					Resource:  "coredns",
					Namespace: "kube-system",
					Kind:      "ConfigMap",
					Message:   fmt.Sprintf("CoreDNS forwards DNS queries to insecure (non-TLS) resolver %q. DNS queries may be intercepted.", resolver),
					Remediation: "## Why This Matters\n\n" +
						"DNS queries forwarded without TLS are transmitted in plaintext, allowing network attackers to intercept, log, or spoof DNS responses. " +
						"DNS spoofing can redirect pod traffic to attacker-controlled endpoints, enabling credential theft and data exfiltration.\n\n" +
						"## How to Fix\n\n" +
						"Configure CoreDNS to use DNS-over-TLS (DoT) for upstream forwarding in the Corefile ConfigMap:\n\n" +
						"```yaml\nforward . tls://1.1.1.1 tls://8.8.8.8 {\n  tls_servername cloudflare-dns.com\n  health_check 5s\n}\n```\n\n" +
						"Ensure the upstream DNS provider supports TLS (e.g., Cloudflare 1.1.1.1, Google 8.8.8.8). " +
						"Alternatively, deploy a local DNSSEC-validating resolver.\n\n" +
						"## Learn More\n\n" +
						"Refer to the CoreDNS forward plugin documentation for TLS configuration options. " +
						"DNS-over-TLS is recommended by the NSA/CISA Kubernetes Hardening Guide to protect DNS queries in transit.",
					FieldPath: ".data.Corefile",
				}
			}
		}
	}
	return nil
}

// checkDebugPlugin checks if the debug plugin is enabled.
func checkDebugPlugin(corefile string) *checker.Finding {
	lines := strings.Split(corefile, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "debug" || strings.HasPrefix(trimmed, "debug ") {
			return &checker.Finding{
				Checker:   "dns-security",
				Severity:  checker.SeverityMedium,
				Resource:  "coredns",
				Namespace: "kube-system",
				Kind:      "ConfigMap",
				Message:   "CoreDNS has the debug plugin enabled, which provides verbose logging that may expose sensitive information in production.",
				Remediation: "## Why This Matters\n\n" +
					"The CoreDNS debug plugin produces verbose output including full query and response details. " +
					"In production, this can expose sensitive DNS query patterns, internal service names, and network topology to anyone with log access, and may degrade DNS performance under load.\n\n" +
					"## How to Fix\n\n" +
					"Remove or comment out the `debug` directive from the Corefile ConfigMap:\n\n" +
					"```yaml\n.:53 {\n  errors\n  health\n  ready\n  kubernetes cluster.local\n  cache 30\n  forward . /etc/resolv.conf\n  # debug  # Remove in production\n}\n```\n\n" +
					"Use the `errors` plugin for error logging and the `log` plugin with appropriate filtering for production-grade observability.\n\n" +
					"## Learn More\n\n" +
					"Refer to the CoreDNS plugin documentation for debug, errors, and log plugins. " +
					"Production CoreDNS configurations should minimize verbose output while retaining error visibility.",
				FieldPath: ".data.Corefile",
			}
		}
	}
	return nil
}

// checkMissingCache checks if the cache plugin is not configured.
func checkMissingCache(corefile string) *checker.Finding {
	lines := strings.Split(corefile, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "cache" || strings.HasPrefix(trimmed, "cache ") {
			return nil
		}
	}
	return &checker.Finding{
		Checker:   "dns-security",
		Severity:  checker.SeverityMedium,
		Resource:  "coredns",
		Namespace: "kube-system",
		Kind:      "ConfigMap",
		Message:   "CoreDNS has no cache plugin configured. Without caching, DNS performance is degraded and the cluster is more susceptible to DNS-based attacks.",
		Remediation: "## Why This Matters\n\n" +
			"Without DNS caching, every pod DNS query is forwarded to upstream resolvers, increasing latency and external traffic volume. " +
			"This also makes the cluster more vulnerable to DNS cache poisoning attacks since there is no local cache to serve validated responses.\n\n" +
			"## How to Fix\n\n" +
			"Add the `cache` plugin to the CoreDNS Corefile ConfigMap with an appropriate TTL:\n\n" +
			"```yaml\n.:53 {\n  errors\n  health\n  ready\n  kubernetes cluster.local\n  cache 30\n  forward . /etc/resolv.conf\n}\n```\n\n" +
			"The TTL value (30 seconds in this example) should be tuned based on your DNS update frequency. " +
			"Lower values ensure faster propagation of changes; higher values reduce upstream load.\n\n" +
			"## Learn More\n\n" +
			"Refer to the CoreDNS cache plugin documentation for advanced options including cache size limits and prefetching. " +
			"DNS caching is a standard best practice for both performance and security in Kubernetes clusters.",
		FieldPath: ".data.Corefile",
	}
}
