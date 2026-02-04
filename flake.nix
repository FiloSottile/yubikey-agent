{
  description = "yubikey-agent - a seamless ssh-agent for YubiKeys";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.buildGoModule {
        pname = "yubikey-agent";
        version = "0.0.0";
        src = ./.;

        vendorHash = "sha256-+IRPs3wm3EvIgfQRpzcVpo2JBaFQlyY/RI1G7XfVS84=";

        buildInputs = [ pkgs.pcsclite ];
        nativeBuildInputs = [ pkgs.pkg-config ];

        meta = with pkgs.lib; {
          description = "A seamless ssh-agent for YubiKeys";
          homepage = "https://github.com/FiloSottile/yubikey-agent";
          license = licenses.bsd3;
          mainProgram = "yubikey-agent";
        };
      };
    });

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        packages = [ pkgs.go pkgs.pkg-config pkgs.pcsclite ];
        PKG_CONFIG_PATH = "${pkgs.pcsclite.dev}/lib/pkgconfig";
        shellHook = ''
          echo "yubikey-agent dev shell — go $(go version)"
        '';
      };
    });
  };
}
