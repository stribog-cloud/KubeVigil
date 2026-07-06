package workload

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// protectedHostnames are well-known internal or control-plane hostnames that
// should never be overridden via hostAliases. Overriding them can silently
// redirect a workload's calls to the Kubernetes API (or another trusted
// internal service) to an attacker-controlled IP.
var protectedHostnames = []string{
	// Kubernetes control-plane service.
	"kubernetes.default",
	"kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local",
	// Cloud instance-metadata endpoints reachable by hostname. Redirecting these
	// via hostAliases is the same credential-theft/AitM vector as overriding the
	// API service (AWS/Azure IMDS is an IP, but GCP resolves by name).
	"metadata.google.internal",
	"metadata",
}

// HostAliasesInjectionChecker detects pods whose hostAliases override
// well-known internal or control-plane hostnames.
type HostAliasesInjectionChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostAliasesInjectionChecker) Name() string { return "hostaliases-injection" }

// Description returns a human-readable description.
func (c *HostAliasesInjectionChecker) Description() string {
	return "Detects pods with hostAliases entries overriding well-known internal or control-plane hostnames."
}

// Categories returns the check categories.
func (c *HostAliasesInjectionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostAliasesInjectionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostAliasesInjectionChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the hostaliases-injection check against all workload resources in the cache.
func (c *HostAliasesInjectionChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hostaliases-injection check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		for aliasIdx := range info.Spec.HostAliases {
			alias := &info.Spec.HostAliases[aliasIdx]

			matched := matchedProtectedHostname(alias.Hostnames)
			if matched == "" {
				continue
			}

			findings = append(findings, checker.Finding{
				Checker:   "hostaliases-injection",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message: fmt.Sprintf(
					"%s %q overrides %q via hostAliases, redirecting it to %q.",
					info.Kind, info.ResourceName, matched, alias.IP,
				),
				Remediation: "## Why This Matters\n\n" +
					"hostAliases entries are injected verbatim into the pod's /etc/hosts file, taking precedence over normal " +
					"cluster DNS resolution. An entry that overrides `kubernetes.default`, `kubernetes.default.svc`, or any " +
					"`*.cluster.local` hostname can silently redirect the workload's calls to the Kubernetes API server — or " +
					"another trusted in-cluster service — to an attacker-controlled IP, enabling credential theft or response " +
					"tampering without any visible change to the application code.\n\n" +
					"## How to Fix\n\n" +
					"Remove the hostAliases entry overriding the protected hostname:\n\n" +
					"```yaml\nspec:\n  hostAliases: []  # remove entries targeting kubernetes.default or *.cluster.local\n```\n\n" +
					"If local DNS overrides are genuinely needed for testing, scope them to hostnames that are not part of the " +
					"cluster's trusted internal namespace.\n\n" +
					"## Learn More\n\n" +
					"This check aligns with MITRE ATT&CK T1557 (Adversary-in-the-Middle): overriding a trusted cluster " +
					"hostname redirects the workload's traffic through an attacker-controlled endpoint. See the Kubernetes " +
					"documentation on adding entries to Pod /etc/hosts with HostAliases.",
				FieldPath: fmt.Sprintf(".spec.hostAliases[%d]", aliasIdx),
			})
		}
	}

	return findings, nil
}

// matchedProtectedHostname returns the first protected hostname found in the
// given list, or an empty string if none match. A hostname matches if it is
// exactly one of the well-known protected names, or if it ends in
// ".cluster.local".
func matchedProtectedHostname(hostnames []string) string {
	for _, h := range hostnames {
		// DNS names are case-insensitive, so compare case-folded — otherwise
		// `Kubernetes.Default` would bypass the check.
		lower := strings.ToLower(strings.TrimSpace(h))
		for _, protected := range protectedHostnames {
			if lower == protected {
				return h
			}
		}
		if strings.HasSuffix(lower, ".cluster.local") {
			return h
		}
	}
	return ""
}
