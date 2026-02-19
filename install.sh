#!/usr/bin/env bash
# KubeVigil installer — downloads the latest release binary for your platform.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/stribog-cloud/KubeVigil/master/install.sh | bash
#
# Environment variables:
#   KUBEVIGIL_INSTALL_DIR  — Override install directory (default: /usr/local/bin or ~/.local/bin)
#   KUBEVIGIL_VERSION      — Install a specific version (default: latest)

set -euo pipefail

REPO="stribog-cloud/KubeVigil"
BINARY="kubevigil"

# --- helpers ----------------------------------------------------------------

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
error() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" > /dev/null 2>&1 || error "Required command not found: $1"
}

# --- detect OS and architecture ---------------------------------------------

detect_os() {
  local os
  os="$(uname -s)"
  case "$os" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) error "Unsupported operating system: $os" ;;
  esac
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) error "Unsupported architecture: $arch" ;;
  esac
}

# --- download helper (curl or wget) -----------------------------------------

download() {
  local url="$1" dest="$2"
  if command -v curl > /dev/null 2>&1; then
    curl -fsSL -o "$dest" "$url"
  elif command -v wget > /dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    error "Neither curl nor wget found. Install one and try again."
  fi
}

# --- resolve version --------------------------------------------------------

resolve_version() {
  if [ -n "${KUBEVIGIL_VERSION:-}" ]; then
    echo "$KUBEVIGIL_VERSION"
    return
  fi
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  local version
  if command -v curl > /dev/null 2>&1; then
    version="$(curl -fsSL "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
  elif command -v wget > /dev/null 2>&1; then
    version="$(wget -qO- "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
  else
    error "Neither curl nor wget found."
  fi
  [ -n "$version" ] || error "Could not determine latest version. Set KUBEVIGIL_VERSION to install manually."
  echo "$version"
}

# --- choose install directory -----------------------------------------------

choose_install_dir() {
  if [ -n "${KUBEVIGIL_INSTALL_DIR:-}" ]; then
    echo "$KUBEVIGIL_INSTALL_DIR"
    return
  fi
  if [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
  else
    local dir="${HOME}/.local/bin"
    mkdir -p "$dir"
    echo "$dir"
  fi
}

# --- main -------------------------------------------------------------------

main() {
  local os arch version install_dir
  os="$(detect_os)"
  arch="$(detect_arch)"

  # Windows arm64 is not supported
  if [ "$os" = "windows" ] && [ "$arch" = "arm64" ]; then
    error "Windows arm64 is not supported. Use amd64 (x86_64) instead."
  fi

  info "Detected platform: ${os}/${arch}"

  version="$(resolve_version)"
  info "Installing KubeVigil ${version}"

  install_dir="$(choose_install_dir)"
  info "Install directory: ${install_dir}"

  # Build archive name and URL
  local ver_no_v="${version#v}"
  local ext="tar.gz"
  [ "$os" = "windows" ] && ext="zip"
  local archive="${BINARY}_${ver_no_v}_${os}_${arch}.${ext}"
  local base_url="https://github.com/${REPO}/releases/download/${version}"
  local archive_url="${base_url}/${archive}"
  local checksums_url="${base_url}/${BINARY}_checksums.txt"

  # Download archive and checksums to a temp directory
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  info "Downloading ${archive}..."
  download "$archive_url" "${tmpdir}/${archive}"

  info "Downloading checksums..."
  download "$checksums_url" "${tmpdir}/checksums.txt"

  # Verify checksum
  info "Verifying SHA256 checksum..."
  local expected
  expected="$(grep " ${archive}\$" "${tmpdir}/checksums.txt" | awk '{print $1}')"
  [ -n "$expected" ] || error "Checksum not found for ${archive} in checksums file."

  local actual
  if command -v sha256sum > /dev/null 2>&1; then
    actual="$(sha256sum "${tmpdir}/${archive}" | awk '{print $1}')"
  elif command -v shasum > /dev/null 2>&1; then
    actual="$(shasum -a 256 "${tmpdir}/${archive}" | awk '{print $1}')"
  else
    error "Neither sha256sum nor shasum found. Cannot verify checksum."
  fi

  if [ "$expected" != "$actual" ]; then
    error "Checksum mismatch!\n  Expected: ${expected}\n  Got:      ${actual}"
  fi
  info "Checksum verified."

  # Extract binary
  info "Extracting..."
  if [ "$ext" = "tar.gz" ]; then
    tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
  else
    need_cmd unzip
    unzip -qo "${tmpdir}/${archive}" -d "$tmpdir"
  fi

  # Install
  local binary_name="$BINARY"
  [ "$os" = "windows" ] && binary_name="${BINARY}.exe"

  if [ -w "$install_dir" ]; then
    cp "${tmpdir}/${binary_name}" "${install_dir}/${binary_name}"
    chmod +x "${install_dir}/${binary_name}"
  else
    info "Elevated permissions required to install to ${install_dir}"
    sudo cp "${tmpdir}/${binary_name}" "${install_dir}/${binary_name}"
    sudo chmod +x "${install_dir}/${binary_name}"
  fi

  # Verify installation
  info "Installed successfully!"
  "${install_dir}/${binary_name}" version

  # Check if install_dir is in PATH
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *) printf '\n\033[1;33mNote:\033[0m %s is not in your PATH.\n' "$install_dir"
       printf '  Add it with: export PATH="%s:$PATH"\n' "$install_dir" ;;
  esac
}

main "$@"
