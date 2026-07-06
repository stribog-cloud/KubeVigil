#!/usr/bin/env bash
# Regenerate deploy/krew/kubevigil.yaml for a released version.
# Usage: scripts/update-krew-manifest.sh v1.0.0
# Downloads the release checksums file and rewrites the krew manifest with
# fresh URIs and sha256 values. Run after every release, commit the result.
set -euo pipefail

TAG="${1:?usage: $0 vX.Y.Z}"
VER="${TAG#v}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/deploy/krew/kubevigil.yaml"
BASE="https://github.com/stribog-cloud/KubeVigil/releases/download/${TAG}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sSfL -o "$TMP/checksums.txt" "${BASE}/kubevigil_checksums.txt"

sha_for() {
  local asset="$1"
  awk -v a="$asset" '$2 == a { print $1 }' "$TMP/checksums.txt"
}

declare -a PLATFORMS=(
  "linux amd64 tar.gz kubevigil"
  "linux arm64 tar.gz kubevigil"
  "darwin amd64 tar.gz kubevigil"
  "darwin arm64 tar.gz kubevigil"
  "windows amd64 zip kubevigil.exe"
)

{
  cat <<HEADER
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: vigil
spec:
  version: ${TAG}
  homepage: https://github.com/stribog-cloud/KubeVigil
  shortDescription: Kubernetes Security Posture Management — scan clusters for misconfigurations
  description: |
    KubeVigil scans Kubernetes clusters and YAML manifests for security
    misconfigurations. It runs 110 security checks across 12 categories,
    maps findings to compliance frameworks (CIS, MITRE ATT&CK, NSA/CISA),
    and outputs reports in 8 formats. Includes auto-remediation with a
    five-ring safety model.
  caveats: |
    This plugin provides the 'kubectl vigil' command.
    Usage:
      kubectl vigil scan                  # Scan live cluster
      kubectl vigil scan -f ./manifests/  # Scan manifests
      kubectl vigil fix ./manifests/      # Preview auto-fixes
  platforms:
HEADER
  for p in "${PLATFORMS[@]}"; do
    read -r os arch ext bin <<<"$p"
    asset="kubevigil_${VER}_${os}_${arch}.${ext}"
    sha="$(sha_for "$asset")"
    if [[ -z "$sha" ]]; then
      echo "ERROR: no checksum for ${asset} in ${BASE}/kubevigil_checksums.txt" >&2
      exit 1
    fi
    cat <<PLATFORM
    - selector:
        matchLabels:
          os: ${os}
          arch: ${arch}
      uri: ${BASE}/${asset}
      sha256: ${sha}
      bin: ${bin}
PLATFORM
  done
} > "$MANIFEST"

echo "updated ${MANIFEST} for ${TAG}"
