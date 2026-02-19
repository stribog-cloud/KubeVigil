# Image Security Checks

KubeVigil includes 9 checks that inspect container image references for tagging practices, digest pinning, registry policies, and supply chain integrity. These checks apply to all containers in Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and bare Pods.

All image checks support both **Live** and **Manifest** scan modes.

---

## Image Tagging

### `image-tag-latest`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers using the `:latest` tag or images with no tag (which defaults to `:latest`). The `:latest` tag is mutable and can resolve to a different image at any time. Deployments become non-reproducible, rollbacks break silently, and attackers can poison the tag to inject malicious code without changing your manifests.

**Remediation:**
```yaml
containers:
  - name: app
    image: nginx:1.25.3          # Pinned version tag
    # Or pin by digest for maximum immutability:
    # image: nginx@sha256:a8281ce42034
```

**Frameworks:** CIS 5.4.1

---

### `image-tag-missing`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers where the image has no tag and no digest. An image reference with no version identifier at all (e.g., `nginx`) is completely non-deterministic -- the resolved image can change between pulls, implicitly resolving to `:latest`.

**Remediation:**
```yaml
containers:
  - name: app
    image: nginx:1.25.3              # Explicit version tag
    # Or for critical workloads, pin by digest:
    # image: nginx@sha256:a8281ce42034
```

**Frameworks:** CIS 5.4.1

---

### `image-no-digest`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers whose image is not pinned by digest. Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

**Remediation:**
```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

**Frameworks:** SLSA Level 1+, NIST SP 800-190

---

### `image-pull-policy`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects containers with a mutable image tag and a pull policy that does not enforce pulling the latest version. Without `imagePullPolicy: Always`, a node may use a cached (potentially stale or compromised) version of a mutable tag. The check skips digest-pinned images since their content is immutable.

**Remediation:**
```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

**Frameworks:** CIS 5.4.2

---

## Registry Policies

### `image-registry-allowlist`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Flags containers using images from registries not in the configured allowed registries list. Pulling images from unapproved registries bypasses your organization's security scanning, vulnerability management, and supply chain controls. This check is a NO-OP when no allowed registries policy is configured in `.kubevigil.yaml`.

**Remediation:**
```yaml
containers:
  - name: app
    image: registry.company.com/app:v1.0   # Approved registry
```

Define your approved registries in `.kubevigil.yaml`:

```yaml
policies:
  images:
    allowedRegistries:
      - registry.company.com
      - gcr.io/my-project
```

**Frameworks:** CIS 5.4.1

---

### `image-registry-blocklist`
**Severity:** Critical · **Modes:** Live, Manifest · **Auto-fix:** No

Flags containers using images from explicitly blocked registries. Your organization has prohibited these registries because they are known to be insecure, unmaintained, or non-compliant. This check is a NO-OP when no blocked registries policy is configured in `.kubevigil.yaml`.

**Remediation:**
```yaml
containers:
  - name: app
    image: registry.company.com/app:v1.0   # Approved alternative
```

Mirror needed images into your internal registry using `crane copy` or `skopeo copy`, then update manifests to reference the mirrored location.

---

## Supply Chain

### `image-signature-verification`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Flags container images not pinned by digest when signature verification is required. Digest pinning is a prerequisite for verifying image signatures because the tag can be mutated after signing, breaking the trust chain. This check is a NO-OP when `policies.images.requireSignatures` is false in `.kubevigil.yaml`.

**Remediation:**
```yaml
containers:
  - name: app
    image: myapp@sha256:abcdef1234567890
```

Sign images in CI with cosign: `cosign sign --key cosign.key myapp@sha256:...`
Verify at admission time: `cosign verify --key cosign.pub myapp@sha256:...`

**Frameworks:** SLSA Level 2+

---

### `image-sbom-attestation`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Flags container images not pinned by digest when SBOM attestation is required. Without digest pinning, SBOM attestations cannot be matched to a specific image build, so you lose visibility into which libraries and CVEs are present at runtime. This check is a NO-OP when `policies.images.requireSBOM` is false in `.kubevigil.yaml`.

**Remediation:**
```yaml
containers:
  - name: app
    image: myapp@sha256:abcdef1234567890
```

Generate and attach SBOMs in CI:
`syft myapp@sha256:... -o spdx-json > sbom.json`
`cosign attest --predicate sbom.json --type spdxjson myapp@sha256:...`

**Frameworks:** NIST Executive Order 14028

---

### `image-provenance`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Flags container images not pinned by digest when provenance verification is required. Build provenance records where, when, and how a container image was built. Without digest pinning, provenance attestations cannot be tied to a specific image, so you cannot verify that the image came from your trusted CI/CD pipeline. This check is a NO-OP when `policies.images.requireProvenance` is false in `.kubevigil.yaml`.

**Remediation:**
```yaml
containers:
  - name: app
    image: myapp@sha256:abcdef1234567890
```

Generate provenance in CI (e.g., GitHub Actions SLSA generator) and verify:
`cosign verify-attestation --type slsaprovenance myapp@sha256:...`

**Frameworks:** SLSA Level 1+
