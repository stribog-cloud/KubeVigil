# Glossary

Key terms used throughout KubeVigil documentation and output.

## Auto-fix

The ability of KubeVigil to automatically patch Kubernetes manifest files to resolve security findings. Performed by the `kubevigil fix` command. Only a subset of checks (20 of 150) support auto-fixing. See also: FixHint, Safety Classification.

## Category

A grouping of related security checks. KubeVigil organizes its 150 checks into 12 categories: workload, image, RBAC, secrets, network, PSA (Pod Security Admission), scheduling, storage, cluster configuration, supply chain, cloud provider, and CRD security.

## Check

A single security rule that evaluates Kubernetes resources for a specific misconfiguration. Each check has a unique kebab-case ID (e.g., `privileged`, `host-network`, `rbac-wildcard-verbs`), a severity level, a description, and one or more supported scan modes. Checks produce Findings when they detect issues.

## Dry-run

The default mode for the `kubevigil fix` command. In dry-run mode, KubeVigil shows what changes would be made (as a unified diff) but does not modify any files. Use `--apply` to switch from dry-run to actual file modification.

## Exemption

A rule that suppresses specific findings from scan results. Exemptions can be configured in `.kubevigil.yaml` (config-based) or via the `kubevigil.io/skip` annotation on resources (annotation-based). Exemptions support filtering by namespace, resource name, kind, check ID, and expiry date.

## Field Path

A dot-notation path identifying the location of a problematic field within a Kubernetes resource. For example, `spec.containers[0].securityContext.privileged` points to the privileged field of the first container. Field paths appear in findings and are used by the fix engine to locate the YAML nodes to patch.

## Finding

A single security issue detected by a Check during a scan. Each finding includes the check ID, severity, affected resource (name, namespace, kind), a human-readable message, remediation guidance, and optional compliance framework references. Findings are the primary output of a scan.

## FixHint

Structured metadata attached to a Finding that tells the fix engine how to auto-remediate the issue. A FixHint includes the safety classification, a description of the fix, the potential impact, and the type of YAML operation (set, add, remove, merge). Only findings from checks registered in the fix registry include FixHints.

## Framework Mapping

The association between a KubeVigil check and one or more compliance framework controls. KubeVigil maps 137 of its 150 checks to three frameworks: CIS Kubernetes Benchmark v1.8, MITRE ATT&CK for Containers v14, and NSA/CISA Kubernetes Hardening Guide v1.2. The remaining 13 checks cover surfaces newer than the current published framework revisions (e.g. the Gateway API and ValidatingAdmissionPolicy) and carry no framework reference rather than a fabricated control ID. Framework references appear in JSON/YAML output under `findings[].frameworks`.

## Posture Score

A numerical score (0-100) representing the overall security posture of a scanned cluster or set of manifests. Calculated from the number and severity of findings relative to the total number of resources scanned. Displayed in the HTML report dashboard.

## Remediation

Guidance on how to fix a security finding. Every finding includes a remediation string with specific instructions. For auto-fixable checks, the remediation is implemented programmatically by the fix engine. For manual-only checks, the remediation provides step-by-step human guidance.

## Risk Level

A CLI parameter (`--risk-level`) for the fix command that controls which Safety Classifications are eligible for auto-fixing. Three levels are available:

- **safe** (default) -- only safe fixes are applied
- **moderate** -- safe and likely safe fixes are applied
- **aggressive** -- safe, likely safe, and potentially breaking fixes are applied

Risk levels are additive: each higher level includes all lower levels.

## Safety Classification

A label assigned to each auto-fixable check that describes the risk of applying the fix. Four classifications exist:

- **Safe** -- zero risk of breaking functionality (e.g., setting `privileged: false`)
- **Likely Safe** -- very low risk, could theoretically break edge cases (e.g., `drop: ["ALL"]` capabilities)
- **Potentially Breaking** -- could impact functionality (e.g., adding default resource limits)
- **Manual Only** -- cannot be automated, requires human intervention (e.g., RBAC restructuring)

## Scan Mode

The method used to evaluate Kubernetes resources. KubeVigil supports two scan modes:

- **Live** -- connects to a running Kubernetes cluster via the API server and evaluates resources in real time
- **Manifest** -- reads YAML/JSON files from disk and evaluates them without a cluster connection

Some checks support only one mode (e.g., checks that query cluster state require Live mode), while most support both.

## Severity

The impact level assigned to a finding. Five levels are defined, from lowest to highest:

- **Info** -- informational observation with no direct security impact
- **Low** -- best practice deviation with minimal direct risk
- **Medium** -- defense-in-depth gap
- **High** -- significant security weakness
- **Critical** -- direct path to cluster compromise

Severities can be overridden per-check in the configuration file.
