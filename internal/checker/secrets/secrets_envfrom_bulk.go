package secrets

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// EnvFromBulkChecker detects containers that use envFrom[].secretRef to
// bulk-inject every key of a Secret as environment variables. This is
// strictly worse than a single per-key env[].valueFrom.secretKeyRef reference
// (already covered by [InEnvChecker]): a single misconfiguration here exposes
// the Secret's entire contents to process listings, crash dumps, and
// child-process inheritance, not just one key.
type EnvFromBulkChecker struct{}

// Name returns the kebab-case check ID.
func (c *EnvFromBulkChecker) Name() string { return "secrets-envfrom-bulk" }

// Description returns a human-readable description.
func (c *EnvFromBulkChecker) Description() string {
	return "Detects containers using envFrom[].secretRef to bulk-inject every key of a Secret as environment variables."
}

// Categories returns the check categories.
func (c *EnvFromBulkChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *EnvFromBulkChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EnvFromBulkChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the secrets-envfrom-bulk check against all workload resources in the cache.
func (c *EnvFromBulkChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-envfrom-bulk check: %w", err)
	}

	specs := workload.ExtractPodSpecs(cache)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			for efIdx, envFrom := range container.EnvFrom {
				if envFrom.SecretRef == nil {
					continue
				}

				secretName := envFrom.SecretRef.Name
				fieldPath := containerFieldPath(ct, idx, fmt.Sprintf("envFrom[%d].secretRef", efIdx))

				findings = append(findings, checker.Finding{
					Checker:   "secrets-envfrom-bulk",
					Severity:  checker.SeverityHigh,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message: fmt.Sprintf(
						"container %q bulk-injects every key of secret %q as environment variables via envFrom",
						container.Name, secretName,
					),
					Remediation: "## Why This Matters\n\n" +
						"`envFrom[].secretRef` injects **every** key in the referenced Secret as an environment " +
						"variable, without the workload declaring which keys it actually needs. A single " +
						"misconfiguration exposes the Secret's entire contents to process listings " +
						"(`/proc/*/environ`), crash dumps, log output, and any child process the container " +
						"spawns — far worse than a targeted `env[].valueFrom.secretKeyRef` reference to one key.\n\n" +
						"## How to Fix\n\n" +
						"Mount the Secret as a file instead, or reference only the specific keys the workload needs:\n\n" +
						"```yaml\nvolumeMounts:\n  - name: secret-vol\n    mountPath: /etc/secrets\n    readOnly: true\nvolumes:\n  - name: secret-vol\n    secret:\n      secretName: db-credentials\n```\n\n" +
						"If environment variables are required, reference individual keys explicitly:\n\n" +
						"```yaml\nenv:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password\n```\n\n" +
						"## Learn More\n\n" +
						"CIS Kubernetes Benchmark 5.4.1 and the NSA/CISA Kubernetes Hardening Guide recommend " +
						"avoiding secrets in environment variables, and scoping any exposure to the minimum " +
						"necessary keys. See the Kubernetes Secrets documentation for `envFrom` semantics.",
					FieldPath: fieldPath,
				})
			}
		})
	}

	return findings, nil
}
