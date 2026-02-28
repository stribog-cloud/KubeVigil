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
  # GoReleaser auto-publishes to stribog-cloud/homebrew-tap on release.
  # This file is a standalone reference template.
  version "0.5.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_darwin_arm64.tar.gz"
      sha256 "ea3027df448e62f4734a8f8b73a4b031ea3841f0344d611dc23eedd7ce7f85bb"
    else
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_darwin_amd64.tar.gz"
      sha256 "f4486b27a94a0002960fd5dcfa6c88912cf8dea5a539b0635f641064d469755d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_linux_arm64.tar.gz"
      sha256 "2d6bc7dbc9ca8d692546f9515a98cf18030cf8908e27f133e77946c36f08d537"
    else
      url "https://github.com/stribog-cloud/KubeVigil/releases/download/v#{version}/kubevigil_#{version}_linux_amd64.tar.gz"
      sha256 "e704fa6e82637c0d02fd57d32791b242567b7219f1f6db10657763924d97a55e"
    end
  end

  def install
    bin.install "kubevigil"
  end

  test do
    system "#{bin}/kubevigil", "version"
  end
end
