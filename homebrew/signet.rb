# Canonical Homebrew formula for signet, the cross-platform Go binary for
# hardware-rooted machine identity. This is the source of truth; copy it into the
# Homebrew tap repo (radar-hooves/homebrew-tap, as `Formula/signet.rb`) so users can
# `brew install radar-hooves/tap/signet`. Bump `version` and the sha256s when a new
# signet release is cut (the .sha256 files are published alongside each release
# tarball).
#
# SECURE ENCLAVE: the SE backend works on the pre-built release binary (unsigned/ad-hoc).
# It uses CryptoKit's self-stored-key-blob model — the Enclave's opaque hardware-wrapped
# blob is stored in a file (~/.signet/), the keychain is never
# touched, and no code-signing entitlement is required. All three backends work unsigned.
class Signet < Formula
  desc "Single Go binary for hardware-rooted machine identity; TPM, PIV, and Secure Enclave all work on the unsigned release binary"
  homepage "https://github.com/radar-hooves/signet"
  version "2026.9.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/radar-hooves/signet/releases/download/v#{version}/signet-#{version}-darwin-arm64.tar.gz"
      sha256 "122e3f4990d3e826832efe8bd71496b5a566f139a6eb41512bcbf11b68df62f7"
    end

    on_intel do
      # darwin/amd64 is not yet built; add when the matrix runner is added to the release workflow.
      odie "signet: no release artifact for macOS Intel (darwin/amd64) yet."
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/radar-hooves/signet/releases/download/v#{version}/signet-#{version}-linux-amd64.tar.gz"
      sha256 "2acf9bd76247c4e75277a4cd7d0a64d8982df9ba45710a799703ec453e9588b4"
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
