# Reference nix-darwin / home-manager derivation for the signet release binary.
#
# signet is a single self-contained cross-platform Go binary with three hardware
# backends compiled in: Secure Enclave (macOS, cgo), TPM 2.0 (go-tpm), and
# YubiKey/PIV (go-piv). It is built and published as per-platform native binaries
# by this repo's release workflow. This derivation installs the pre-built binary
# via fetchurl + SRI — the Go source is never built here. Copy it into your nix
# config and add it to home.packages:
#
#   home.packages = [ (pkgs.callPackage ./signet.nix { }) ];
#
# Bump `version` and the hash for your system in `hashes` when a new signet release
# is cut. `nix store prefetch-file <url>` (or the hash-mismatch build error) yields
# the SRI hash.
#
# SECURE ENCLAVE: the SE backend works on the pre-built release binary (unsigned/ad-hoc).
# It uses CryptoKit's self-stored-key-blob model — the Enclave's opaque hardware-wrapped
# blob is stored in a file, the keychain is never touched, and no code-signing entitlement
# is required. All three backends (TPM 2.0 / YubiKey PIV / Secure Enclave) work on the
# downloaded artifact.
{
  lib,
  stdenv,
  fetchurl,
}:
let
  version = "2026.9.1";

  # Per-platform artifact selection. cgo forces native per-platform builds, so each
  # system gets its own tarball. Platforms not yet built throw at evaluation time —
  # add a row + hash when the matrix runner is added to the workflow.
  platformMap = {
    "aarch64-darwin" = "darwin-arm64";
    "x86_64-linux" = "linux-amd64";
  };

  artifactSuffix =
    platformMap.${stdenv.hostPlatform.system}
      or (throw "signet: no release artifact for ${stdenv.hostPlatform.system}; add a matrix entry to the release workflow");

  # SRI hashes for the published release tarballs (nix store prefetch-file <url>).
  hashes = {
    "darwin-arm64" = "sha256-IX3LZc/lRJO/ssFdiK9ru87hYGC8QLSgS5OkXKq9ErQ=";
    "linux-amd64" = "sha256-GS5kkSSxxwrADzSxXDaLp340Su5+vkkCu6KCmvD5vUg=";
  };

  src = fetchurl {
    url = "https://github.com/radar-hooves/signet/releases/download/v${version}/signet-${version}-${artifactSuffix}.tar.gz";
    hash = hashes.${artifactSuffix};
  };
in
stdenv.mkDerivation {
  pname = "signet";
  inherit version src;

  # The tarball is a single native binary for the target platform; nothing to build.
  sourceRoot = ".";
  dontBuild = true;
  dontConfigure = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 signet "$out/bin/signet"
    runHook postInstall
  '';

  meta = {
    description = "Single Go binary for hardware-rooted machine identity; TPM, PIV, and Secure Enclave backends all work on the unsigned release binary";
    homepage = "https://github.com/radar-hooves/signet";
    license = lib.licenses.mit;
    platforms = [
      "aarch64-darwin"
      "x86_64-linux"
    ];
    mainProgram = "signet";
  };
}
