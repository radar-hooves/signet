# Reference nix-darwin / home-manager derivation for the signet release binary.
#
# signet is a single self-contained cross-platform Go binary: a machine-identity
# attest client for Portcullis, holding a P-256 key in a PKCS8 PEM file. It is
# built and published as per-platform native binaries by this repo's release
# workflow. This derivation installs the pre-built binary via fetchurl + SRI —
# the Go source is never built here. Copy it into your nix config and add it to
# home.packages:
#
#   home.packages = [ (pkgs.callPackage ./signet.nix { }) ];
#
# Bump `version` and the hash for your system in `hashes` when a new signet
# release is cut. `nix store prefetch-file <url>` (or the hash-mismatch build
# error) yields the SRI hash.
{
  lib,
  stdenv,
  fetchurl,
}:
let
  version = "2026.9.6";

  platformMap = {
    "aarch64-darwin" = "darwin-arm64";
    "x86_64-linux" = "linux-amd64";
  };

  artifactSuffix =
    platformMap.${stdenv.hostPlatform.system}
      or (throw "signet: no release artifact for ${stdenv.hostPlatform.system}; add a matrix entry to the release workflow");

  # SRI hashes for the published release tarballs (nix store prefetch-file <url>).
  hashes = {
    "darwin-arm64" = "sha256-KzM4an3c6Hn8EJ+KPAqbR9GONYluyuEZYUkuNfbKPBM=";
    "linux-amd64" = "sha256-B9WHsBUttKiQGF2c7Ksp0AIeBT3Iju4qjAeRbkXdftg=";
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
    description = "Single Go binary machine-identity attest client for Portcullis";
    homepage = "https://github.com/radar-hooves/signet";
    license = lib.licenses.mit;
    platforms = [
      "aarch64-darwin"
      "x86_64-linux"
    ];
    mainProgram = "signet";
  };
}
