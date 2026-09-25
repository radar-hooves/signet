# Canonical Homebrew formula for signet, the Portcullis machine-identity attest
# client. This is the source of truth; copy it into the Homebrew tap repo
# (radar-hooves/homebrew-tap, as `Formula/signet.rb`) so users can
# `brew install radar-hooves/tap/signet`. Bump `version` and the sha256s when a new
# signet release is cut (the .sha256 files are published alongside each release
# tarball).
class Signet < Formula
  desc "Single Go binary machine-identity attest client for Portcullis"
  homepage "https://github.com/radar-hooves/signet"
  version "2026.9.6"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/radar-hooves/signet/releases/download/v#{version}/signet-#{version}-darwin-arm64.tar.gz"
      sha256 "217dcb65cfe54493bfb2c15d88af6bbbcee16060bc40b4a04b93a45caabd12b4"
    end

    on_intel do
      # darwin/amd64 is not yet built; add when the matrix runner is added to the release workflow.
      odie "signet: no release artifact for macOS Intel (darwin/amd64) yet."
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/radar-hooves/signet/releases/download/v#{version}/signet-#{version}-linux-amd64.tar.gz"
      sha256 "192e649124b1c70ac00f34b15c368ba77e344aee7ebe4902bba2829af0f9bd48"
    end

    on_arm do
      # linux/arm64 is not yet built; add when the matrix runner is added to the release workflow.
      odie "signet: no release artifact for Linux ARM64 (linux/arm64) yet."
    end
  end

  def install
    bin.install "signet"
  end

  test do
    # With no arguments the CLI prints its help block to stdout and exits 0;
    # an unknown subcommand exits 1 naming the failure.
    assert_match "Usage", shell_output("#{bin}/signet")
    assert_match "unknown subcommand", shell_output("#{bin}/signet nonsense 2>&1", 1)
  end
end
