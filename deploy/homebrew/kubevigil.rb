# Homebrew formula for KubeVigil — reference template.
# This formula is a standalone reference. The actual tap is managed by
# GoReleaser (see .goreleaser.yaml brews section, currently commented out
# until the repository is made public).
#
# To test locally with a GoReleaser snapshot:
#   brew install --formula deploy/homebrew/kubevigil.rb

class Kubevigil < Formula
  desc "Kubernetes Security Posture Management CLI — know your clusters before attackers do"
  homepage "https://github.com/stribog-cloud/KubeVigil"
  license "Apache-2.0"

  # Update version, URL, and checksum when cutting a release.
  version "0.3.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_darwin_arm64.tar.gz"
      sha256 "PLACEHOLDER_DARWIN_ARM64"
    else
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_darwin_amd64.tar.gz"
      sha256 "PLACEHOLDER_DARWIN_AMD64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_linux_arm64.tar.gz"
      sha256 "PLACEHOLDER_LINUX_ARM64"
    else
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_linux_amd64.tar.gz"
      sha256 "PLACEHOLDER_LINUX_AMD64"
    end
  end

  def install
    bin.install "kubevigil"
  end

  test do
    system "#{bin}/kubevigil", "version"
  end
end
