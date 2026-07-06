# Compliance Framework Mappings

KubeVigil maps 137 of its 150 security checks to three industry-standard compliance frameworks. This allows you to filter scan results by framework, generate framework-specific reports, and demonstrate compliance coverage during audits. The 13 unmapped checks cover surfaces newer than the current published framework revisions (for example the Gateway API and ValidatingAdmissionPolicy); rather than cite a fabricated control ID, those checks carry no framework reference until the frameworks catch up.

## Supported Frameworks

| Framework | Version | Controls Mapped | Description |
|-----------|---------|-----------------|-------------|
| [CIS Kubernetes Benchmark](cis.md) | v1.8 | 35 | Industry-standard hardening guide from the Center for Internet Security |
| [MITRE ATT&CK for Containers](mitre.md) | v14 | 34 | Adversarial tactics and techniques for container environments |
| [NSA/CISA Kubernetes Hardening Guide](nsa.md) | v1.2 | 15 | US government hardening guidance for Kubernetes deployments |

## Filtering by Framework

Use the `--framework` flag to filter scan results to only checks that map to a specific compliance framework.

### CIS Benchmark

```bash
kubevigil scan --framework cis
```

### MITRE ATT&CK

```bash
kubevigil scan --framework mitre
```

### NSA/CISA Hardening Guide

```bash
kubevigil scan --framework nsa
```

## Framework References in Output

Framework mappings appear in the JSON and YAML output under the `frameworks` field of each finding. Each entry includes the framework name, version, control ID, and control title.

Example JSON output:

```json
{
  "checker": "privileged",
  "severity": "Critical",
  "resource": "my-deployment",
  "namespace": "default",
  "kind": "Deployment",
  "message": "Container 'app' runs in privileged mode",
  "frameworks": [
    {
      "framework": "cis",
      "version": "1.8",
      "control_id": "5.2.2",
      "title": "Minimize the admission of privileged containers"
    },
    {
      "framework": "mitre",
      "version": "v14",
      "control_id": "T1611",
      "title": "Escape to Host"
    },
    {
      "framework": "nsa",
      "version": "1.2",
      "control_id": "1.1",
      "title": "Non-root containers"
    }
  ]
}
```

## Combining with Other Flags

Framework filtering can be combined with other scan flags:

```bash
# CIS findings at high severity or above, in JSON format
kubevigil scan --framework cis --severity high -o json

# MITRE ATT&CK findings for a specific namespace
kubevigil scan --framework mitre -n production

# NSA/CISA findings from manifest files
kubevigil scan --framework nsa -f manifests/
```

## How Mappings Work

Each KubeVigil check can map to one or more controls across multiple frameworks. For example, the `privileged` check maps to:

- CIS 5.2.2 (Pod Security Standards)
- MITRE T1611 (Escape to Host)
- NSA/CISA 1.1 (Non-root containers) and 2.1 (Pod security enforcement)

This means a single finding can satisfy compliance requirements across all three frameworks simultaneously. The mapping data is maintained in `internal/frameworks/` and is attached to findings automatically during scanning.
