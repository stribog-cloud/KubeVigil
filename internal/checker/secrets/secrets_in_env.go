package secrets

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// InEnvChecker detects containers that pass secrets via environment variables
// instead of volume mounts. Environment variables are visible in process listings,
// may appear in logs or crash dumps, and do not support automatic rotation.
type InEnvChecker struct{}

// Name returns the kebab-case check ID.
func (c *InEnvChecker) Name() string { return "secrets-in-env" }

// Description returns a human-readable description.
func (c *InEnvChecker) Description() string {
	return "Detects containers that use env[].valueFrom.secretKeyRef to pass secrets as environment variables instead of using volume mounts."
}

// Categories returns the check categories.
func (c *InEnvChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *InEnvChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *InEnvChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the secrets-in-env check against all workload resources in the cache.
func (c *InEnvChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-in-env check: %w", err)
	}

	specs := workload.ExtractPodSpecs(cache)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			for envIdx, envVar := range container.Env {
				if envVar.ValueFrom == nil || envVar.ValueFrom.SecretKeyRef == nil {
					continue
				}

				secretName := envVar.ValueFrom.SecretKeyRef.LocalObjectReference.Name
				secretKey := envVar.ValueFrom.SecretKeyRef.Key
				fieldPath := containerFieldPath(ct, idx, fmt.Sprintf("env[%d].valueFrom.secretKeyRef", envIdx))

				findings = append(findings, checker.Finding{
					Checker:   "secrets-in-env",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message: fmt.Sprintf(
						"container %q passes secret %q key %q via environment variable",
						container.Name, secretName, secretKey,
					),
					Remediation: "## Why This Matters\n\n" +
						"Environment variables are visible in pod specs, process listings (`/proc/*/environ`), " +
						"crash dumps, and log output. They are also inherited by child processes. If a " +
						"secret leaks through any of these channels, an attacker gains immediate access " +
						"to the credential.\n\n" +
						"## How to Fix\n\n" +
						"Mount secrets as files using a volume instead of environment variables:\n\n" +
						"```yaml\nvolumeMounts:\n  - name: secret-vol\n    mountPath: /etc/secrets\n    readOnly: true\nvolumes:\n  - name: secret-vol\n    secret:\n      secretName: my-secret\n```\n\n" +
						"File-mounted secrets are stored on tmpfs, are not exposed in logs or process " +
						"listings, and support automatic rotation via the kubelet.\n\n" +
						"## Learn More\n\n" +
						"CIS Kubernetes Benchmark 5.4.1 and NSA/CISA Kubernetes Hardening Guide " +
						"recommend avoiding secrets in environment variables. See the Kubernetes " +
						"Secrets documentation for volume mount examples.",
					FieldPath: fieldPath,
				})
			}
		})
	}

	return findings, nil
}

// containerFieldPath returns the JSON field path for a container field.
func containerFieldPath(ct workload.ContainerType, idx int, field string) string {
	switch ct {
	case workload.ContainerTypeInit, workload.ContainerTypeSidecar:
		return fmt.Sprintf(".spec.initContainers[%d].%s", idx, field)
	default:
		return fmt.Sprintf(".spec.containers[%d].%s", idx, field)
	}
}
