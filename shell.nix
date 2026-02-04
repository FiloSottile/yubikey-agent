# Development shell. Prefer `nix develop` (flake) when available.
# Run `nix-shell` for a shell with Go and build dependencies.
# Uses pcsclite so the built binary matches system pcscd (avoids protocol mismatch).
# If your system pcscd is pcsclite-with-polkit, use that same package in your system config.
let
  pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz") {};
  pcsclite = pkgs.pcsclite;
in
pkgs.mkShell {
  packages = [
    pkgs.go
    pkgs.pkg-config
    pcsclite
  ];
  PKG_CONFIG_PATH = "${pcsclite.dev}/lib/pkgconfig";
  # Same lib at runtime so yubikey-agent and pcscd use the same protocol version (no 4.4 vs 4.5 mismatch)
  LD_LIBRARY_PATH = "${pcsclite}/lib";
  shellHook = ''
    echo "yubikey-agent dev shell — go $(go version)"
    echo "pcsclite in LD_LIBRARY_PATH so builds and runs match system pcscd"
  '';
}
