# Installation

## Requirements

- **kubectl** configured with a valid kubeconfig (for live cluster scanning only)

## Homebrew (macOS / Linux)

```bash
brew install stribog-cloud/tap/kubevigil
```

## Krew (kubectl plugin)

```bash
kubectl krew install vigil
```

## Install Script

```bash
curl -sSL https://raw.githubusercontent.com/stribog-cloud/KubeVigil/master/install.sh | bash
```

The script auto-detects your OS and architecture, downloads the latest release,
verifies the SHA256 checksum, and installs to `/usr/local/bin` (or
`~/.local/bin` if not writable). Set `KUBEVIGIL_VERSION` or
`KUBEVIGIL_INSTALL_DIR` to customize.

## Download from GitHub Releases

Pre-built binaries for Linux, macOS, and Windows are available on the
[Releases page](https://github.com/stribog-cloud/KubeVigil/releases).

Download the archive for your platform, extract it, and move `kubevigil` to a
directory on your `$PATH`.

## Docker

```bash
# Scan manifests
docker run --rm -v $(pwd):/manifests ghcr.io/stribog-cloud/kubevigil scan -f /manifests/

# Scan a live cluster
docker run --rm -v ~/.kube/config:/root/.kube/config ghcr.io/stribog-cloud/kubevigil scan
```

## From Source

Requires **Go 1.25** or later.

```bash
go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest
```

Or clone and build with version injection:

```bash
git clone https://github.com/stribog-cloud/kubevigil.git
cd kubevigil
make build
```

The binary is written to `./bin/kubevigil`.

## Verify Installation

```bash
kubevigil version
```

Expected output:

```
KubeVigil v0.5.0
  Commit: abc1234
  Built:  2026-02-20T12:00:00Z
```

If you see `KubeVigil dev`, you built without the Makefile. This is fine for
local use.

## Shell Completion

KubeVigil supports tab completion for Bash, Zsh, Fish, and PowerShell.

**Bash:**

```bash
kubevigil completion bash > /etc/bash_completion.d/kubevigil
# Or for the current session:
source <(kubevigil completion bash)
```

**Zsh:**

```bash
kubevigil completion zsh > "${fpath[1]}/_kubevigil"
# Or for the current session:
source <(kubevigil completion zsh)
```

**Fish:**

```bash
kubevigil completion fish | source
# Or persist it:
kubevigil completion fish > ~/.config/fish/completions/kubevigil.fish
```

**PowerShell:**

```bash
kubevigil completion powershell | Out-String | Invoke-Expression
```

## Next Steps

- [Quickstart](quickstart.md) -- run your first scan in 30 seconds
- [Key Concepts](concepts.md) -- understand checks, findings, and scan modes
