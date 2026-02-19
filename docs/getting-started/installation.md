# Installation

## Requirements

- **Go 1.25** or later (for `go install` or building from source)
- **kubectl** configured with a valid kubeconfig (for live cluster scanning only)

## Install with `go install`

```bash
go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest
```

This places the `kubevigil` binary in your `$GOPATH/bin` (or `$HOME/go/bin` if `$GOPATH` is unset). Make sure that directory is in your `$PATH`.

## Build from Source

```bash
git clone https://github.com/stribog-cloud/kubevigil.git
cd kubevigil
make build
```

The binary is written to `./bin/kubevigil`. You can move it to a location on your `$PATH`:

```bash
sudo mv ./bin/kubevigil /usr/local/bin/
```

The `make build` target embeds version, commit, and build date into the binary via linker flags. If you use `go build` directly, those fields default to `dev` / `unknown`.

## Verify Installation

```bash
kubevigil version
```

Expected output:

```
KubeVigil v0.1.0
  Commit: abc1234
  Built:  2025-01-15T12:00:00Z
```

If you see `KubeVigil dev`, you built without the Makefile. This is fine for local use.

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
