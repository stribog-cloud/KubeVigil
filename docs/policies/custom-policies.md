# Custom Policies

KubeVigil's 110 built-in checks cover common security misconfigurations, but every organization has rules that are specific to it -- a required label, an approved image registry, a minimum replica count. Custom policies let you express those rules as [CEL](https://cel.dev) (Common Expression Language) expressions, without writing Go code or forking KubeVigil.

A custom policy compiles into the same `checker.Checker` interface as a built-in check. Once compiled, it is indistinguishable from a built-in check to the rest of the pipeline: it runs alongside built-in checks, its findings respect severity overrides and exemptions, and its output appears in every report format.

## How It Works

1. You author one or more policies in YAML -- either inline in `.kubevigil.yaml` under `customPolicies:`, or in a standalone file/directory passed to `--policy-file`.
2. At scan startup, KubeVigil loads, structurally validates, and CEL-compiles every policy into an executable program.
3. Each compiled policy is registered into the same checker registry as the 110 built-in checks, under its `id`.
4. During the scan, the policy's expression is evaluated once per matching resource, with `object` bound to that resource. A `true` result means the resource **violates** the policy, and a finding is emitted.

If any policy fails to load or compile, the scan does not run -- KubeVigil prints a `Policy error:` message and exits with code `3` (configuration error), the same as a malformed `.kubevigil.yaml`.

## The Policy Schema

A policy document (whether inline in config or a standalone file) is a versioned set of policies:

```yaml
version: "v1"
policies:
  - id: ...
    name: ...
    # ... one entry per policy
```

Each policy (`Spec`) supports these fields:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | -- | Kebab-case unique identifier (`a-z`, `0-9`, `-`; cannot start or end with `-`). Becomes the finding's checker name -- the same value you'd pass to `--checks`, `checks.disabled`, or an exemption's `checks` list. |
| `name` | No | -- | Short human-readable title. Used as the finding `message` when `message` is not set. |
| `description` | No | -- | Longer explanation of what the policy detects. Shown by `kubevigil policy list` tooling and intended for policy-authoring documentation, not the finding output. |
| `severity` | No | `medium` | One of `critical`, `high`, `medium`, `low`, `info` (case-insensitive). An unrecognized value fails validation. |
| `category` | No | `custom` | Groups the policy for reporting. Either a built-in category (see [Severity and Category](#severity-and-category) below) or any other string, which is treated as a custom label. |
| `message` | No | falls back to `name` | The finding's human-readable message. |
| `remediation` | No | -- | Guidance shown in reports and the `get_remediation` MCP tool. |
| `expression` | Yes | -- | A CEL expression that must evaluate to a boolean. `true` = violation. See [The CEL Environment](#the-cel-environment). |
| `match.kinds` | No | any kind | Restrict to these Kubernetes kinds (e.g. `Deployment`, `Pod`). Empty means every resource kind KubeVigil recognizes. |
| `match.apiGroups` | No | any group | Further restrict to these API groups (e.g. `apps`, or `""` for the core group). |
| `match.namespaces` | No | any namespace | Restrict evaluation to resources in these namespaces. Empty means all namespaces. |

## The CEL Environment

Every policy expression is compiled against a single-variable CEL environment:

- **`object`** -- the resource as a dynamic map, equivalent to the resource's raw JSON/YAML structure (`object.metadata.name`, `object.spec.replicas`, `object.spec.template.spec.containers`, and so on).

The expression **must** type-check to a boolean. `kubevigil policy validate` catches this at compile time:

```console
$ kubevigil policy validate bad.yaml
Policy error: policy "bad-expr": expression must evaluate to bool, got dyn
```

(That error came from an expression that only accessed a field, e.g. `object.metadata.labels.team`, without a comparison -- CEL doesn't guess a boolean intent for you.)

### `has()` guards

Kubernetes resources are optional-field-heavy: a Deployment may or may not have `labels`, `annotations`, or `volumes`. CEL raises a runtime evaluation error if you index into a map key that doesn't exist. Guard optional fields with `has()`:

```cel
!has(object.metadata.labels) || !('team' in object.metadata.labels)
```

CEL's `||` and `&&` are *commutative* error-absorbing operators: if either side determines the result, any error from the other side is absorbed. When `has(...)` is false, the `||` is already determined, so a would-be error in the other operand never surfaces — which is what makes this pattern safe for resources with no labels at all.

### What happens on an evaluation error

If an expression *does* raise a runtime error against a particular resource (for example, a missing `has()` guard, or `match.kinds` matching a kind whose shape doesn't have the field you assumed), KubeVigil does **not** fail the scan and does **not** count it as a violation. The error is logged at debug level (`--verbose` to see it) and that one resource is skipped; every other matching resource is still evaluated normally. In practice this means a policy bug tends to show up as **missing findings you expected**, not a crash -- always test a new policy against a real manifest, not just `policy validate` (which only checks that the expression compiles, not that it behaves as intended against real data).

### Common examples

**Missing a required label:**

```cel
!has(object.metadata.labels) || !('team' in object.metadata.labels)
```

**Disallowed image registry** (flags any container not from the approved registry):

```cel
object.spec.template.spec.containers.exists(c, !c.image.startsWith('registry.example.com/'))
```

**hostPath volume usage:**

```cel
has(object.spec.template.spec.volumes) && object.spec.template.spec.volumes.exists(v, has(v.hostPath))
```

**Replica minimums:**

```cel
has(object.spec.replicas) && object.spec.replicas < 2
```

Note that the container and volume examples assume a `Deployment`-shaped `spec.template.spec` -- restrict `match.kinds` accordingly (see below), since a `Pod`'s containers live at `spec.containers` directly, not `spec.template.spec.containers`.

### Evaluation cost limit

Every evaluation runs under a fixed CEL **cost limit** (1,000,000 cost units per
resource) so a pathological expression — deeply nested comprehensions over
large objects, for example — cannot stall a scan. Typical field checks cost a
few dozen units; you will only ever hit the limit with unusually heavy
`.exists()` / `.all()` chains over big lists. If an evaluation exceeds the
limit it is treated like any other per-resource evaluation error: the resource
is skipped for that policy (never reported as a violation) and the scan
continues.

## Match Semantics

`match` controls which resources a policy is evaluated against, at two points:

1. **Resource-type resolution** (before the scan runs): `match.kinds` is resolved to the concrete `GroupVersionResource`s KubeVigil knows about for that kind name, further narrowed by `match.apiGroups` if set. With no `kinds`, the policy resolves to *every* resource type KubeVigil scans by default -- broad, but means an expression written for one resource shape (like the Deployment examples above) will raise (harmless, silently-skipped) evaluation errors against every other kind it doesn't apply to. Prefer narrowing `match.kinds` both for correctness and for scan performance.
2. **Namespace filtering** (during evaluation): `match.namespaces`, if set, is checked per-resource; only resources in a listed namespace are evaluated.

An unrecognized kind name in `match.kinds` (a typo, or a kind KubeVigil doesn't know) is **not** a validation error -- `kubevigil policy validate` will report success. It simply resolves to zero resource types, so the policy silently matches nothing. If a policy you expect to fire never produces findings, check for a kind-name typo before suspecting the expression.

## Severity and Category

`severity` uses the same five levels as built-in checks:

| Severity | Meaning |
|----------|---------|
| **Critical** | Direct path to cluster compromise. |
| **High** | Significant security weakness. |
| **Medium** | Defense-in-depth gap (the default when `severity` is omitted). |
| **Low** | Best practice deviation. |
| **Info** | Informational observation. |

`category` groups the policy's findings for reporting (the check-coverage table, HTML dashboard tiers, etc.). It accepts, case-insensitively, one of the 12 built-in category identifiers, or defaults to `custom` for anything else:

`workload`, `lifecycle`, `image`, `rbac`, `secrets`, `network`, `podsecuritystandards`, `storage`, `scheduling`, `clusterconfig`, `supplychain`, `crd`, `cloudprovider` -- or `custom` (the default, and the fallback for any unrecognized value).

Opting into a built-in category (e.g. `category: storage` for a hostPath policy) makes the finding aggregate visually alongside built-in checks of that category; leaving it unset keeps your organization-specific rules visually separated under "Custom Policies."

## How Findings Flow Through the Pipeline

A custom policy's findings are ordinary `checker.Finding` values, so they participate in every downstream mechanism identically to built-in checks:

- **Severity overrides** (`checks.overrides` in config) apply by ID, including custom policy IDs.
- **`checks.disabled`** can disable a custom policy by its `id`, the same as a built-in check name.
- **Exemptions** (`exemptions:` in config, or resource annotations) match on `checks: [<policy-id>]` exactly like built-in checks.
- **All 8 output formats** (text, JSON, YAML, Markdown, HTML, SARIF, JUnit, CSV) include custom policy findings with no special-casing.
- **Baselines** (`--baseline`, `--save-baseline`, `--fail-on-new`) fingerprint custom policy findings the same way as built-in ones -- see [Baseline & Drift Detection](baseline-drift.md).

One exception: **compliance framework mappings do not apply.** Built-in checks carry static references into CIS/MITRE/NSA control tables; custom policies have no such mapping, since there's no way to know in advance which control an arbitrary organization-specific rule maps to. This means custom policy findings are excluded when you filter with `--framework cis` (or `mitre`/`nsa`) -- they simply have no framework references to match against. They still appear in an unfiltered scan.

A custom policy `id` must be unique across built-in checks *and* every other custom policy (from both config and `--policy-file`, if both are used). A collision -- including one with a built-in check name -- is a registration error:

```console
$ kubevigil scan -f manifests/ --policy-file collision.yaml
Policy error: registering custom policy "privileged": checker "privileged" already registered
```

(exit code `3`)

## The `policy` Commands

### `kubevigil policy validate <file|dir>`

Loads, structurally validates, and CEL-compiles every policy in the given file or directory, without running a scan. Exits `0` if every policy is valid, `3` otherwise.

```console
$ kubevigil policy validate configs/example-policies.yaml
OK: 4 policies valid in configs/example-policies.yaml
```

Use this in CI to catch a broken policy file before it reaches `kubevigil scan`.

### `kubevigil policy list <file|dir>`

Lists every policy defined in a file or directory, with its resolved severity and category:

```console
$ kubevigil policy list configs/example-policies.yaml
ID                           SEVERITY   CATEGORY       NAME
require-team-label           Low        custom         Workload missing team label
disallow-latest-tag          Medium     image          Container uses floating :latest tag
disallow-hostpath-volumes    High       storage        Workload mounts a hostPath volume
min-replica-count            Low        custom         Deployment has fewer than 2 replicas

Total: 4 policies
```

## Config vs. `--policy-file`

There are two ways to bring custom policies into a scan, and they can be combined:

- **`customPolicies:` in `.kubevigil.yaml`** -- policies live inline in your committed config, alongside `checks.disabled`, `exemptions`, and everything else. They are active on every scan that loads that config, with no extra flag.
- **`--policy-file <file|dir>`** -- policies live in a separate file or directory, passed explicitly at scan time. Useful for policy sets that are shared across repos, versioned independently of `.kubevigil.yaml`, or swapped per environment/pipeline stage.

```bash
# Inline in config -- always active
kubevigil scan -f manifests/

# Standalone file
kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml

# Standalone directory: every *.yaml/*.yml file is loaded in lexical
# (sorted-by-filename) order and merged into one policy set
kubevigil scan -f manifests/ --policy-file policies/
```

If both are used in the same scan, `customPolicies` and the `--policy-file` policies are merged into a single set before compilation. The same uniqueness rule applies: a policy `id` cannot appear twice across the merged set (whether the duplicate came from config, from two files in the directory, or from the same `id` as a built-in check).

`.kubevigil.yaml`:

```yaml
version: "1"
customPolicies:
  - id: require-team-label
    name: "Workload missing team label"
    severity: low
    expression: "!has(object.metadata.labels) || !('team' in object.metadata.labels)"
    match:
      kinds: ["Deployment"]
```

## Cookbook

Six ready-to-use policies. All are CEL-compile-verified against the current KubeVigil release; the first four ship together in [`configs/example-policies.yaml`](../../configs/example-policies.yaml) and are runnable as-is with `--policy-file`.

### 1. Missing required label

```yaml
- id: require-team-label
  name: "Workload missing team label"
  severity: low
  message: "Workload has no 'team' label."
  remediation: "Add a 'team: <team-name>' label under metadata.labels."
  expression: "!has(object.metadata.labels) || !('team' in object.metadata.labels)"
  match:
    kinds: ["Deployment", "StatefulSet", "DaemonSet"]
```

### 2. Floating `:latest` image tag

```yaml
- id: disallow-latest-tag
  name: "Container uses floating :latest tag"
  severity: medium
  category: image
  message: "One or more containers reference an untagged or :latest image."
  remediation: "Pin images to an immutable tag or digest, e.g. app:1.4.2 or app@sha256:...."
  expression: "object.spec.template.spec.containers.exists(c, !c.image.contains(':') || c.image.endsWith(':latest'))"
  match:
    kinds: ["Deployment"]
```

### 3. Disallowed image registry

```yaml
- id: disallow-image-registry
  name: "Image from untrusted registry"
  severity: high
  category: image
  message: "Container image is not from an approved registry."
  remediation: "Re-tag and push the image to registry.example.com, or add the registry to the allowlist."
  expression: "object.spec.template.spec.containers.exists(c, !c.image.startsWith('registry.example.com/'))"
  match:
    kinds: ["Deployment"]
```

### 4. hostPath volume usage

```yaml
- id: disallow-hostpath-volumes
  name: "Workload mounts a hostPath volume"
  severity: high
  category: storage
  message: "Workload defines a hostPath volume."
  remediation: "Replace the hostPath volume with a PersistentVolumeClaim, ConfigMap, or Secret; use CSI drivers for node-local storage needs."
  expression: "has(object.spec.template.spec.volumes) && object.spec.template.spec.volumes.exists(v, has(v.hostPath))"
  match:
    kinds: ["Deployment", "DaemonSet"]
```

### 5. Replica minimum, scoped to a namespace

`match.namespaces` restricts evaluation to a subset of namespaces -- here, only `production`:

```yaml
- id: min-replica-count
  name: "Deployment has fewer than 2 replicas"
  severity: low
  message: "Deployment runs with fewer than 2 replicas."
  remediation: "Set spec.replicas to 2 or more, or document why a single replica is acceptable (e.g. a singleton batch job)."
  expression: "has(object.spec.replicas) && object.spec.replicas < 2"
  match:
    kinds: ["Deployment"]
    namespaces: ["production"]
```

### 6. Missing owner annotation

```yaml
- id: require-owner-annotation
  name: "Missing owner annotation"
  severity: info
  expression: "!has(object.metadata.annotations) || !('owner' in object.metadata.annotations)"
  match:
    kinds: ["Deployment"]
```

## See Also

- [Baseline & Drift Detection](baseline-drift.md) -- gate CI on new findings only, including from custom policies
- [Configuration File](../configuration/config-file.md) -- full `.kubevigil.yaml` reference
- [Exemptions](../configuration/exemptions.md) -- suppressing findings (built-in or custom) for reviewed resources
- [CLI Reference](../reference/cli-reference.md) -- `scan` and `policy` flags
