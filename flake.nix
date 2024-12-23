{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      buildInputs =
        pkgs: with pkgs; [
          openssl
          tpm2-tss
        ];
      nativeBuildInputs =
        pkgs: with pkgs; [
          llvmPackages.libclang
          llvmPackages.clang
          llvmPackages.libcxxClang
          clang
          pkg-config
          rustPlatform.bindgenHook
        ];
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) stdenv lib;
      in
      rec {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = cargoToml.package.name;
          version = cargoToml.package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;

          doCheck = false;

          buildInputs = buildInputs pkgs;
          nativeBuildInputs = nativeBuildInputs pkgs;
          # LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };

        devShells.default = pkgs.mkShell {
          # shellHook = "${packages.default.preBuild}";
          buildInputs = buildInputs pkgs;
          nativeBuildInputs = nativeBuildInputs pkgs;
        };
      }
    )
    // {
      nixosModules = rec {
        default =
          {
            config,
            lib,
            pkgs,
            ...
          }:
          with lib;
          let
            cfg = config.services.gnome-autounlock-keyring;
          in
          {
            options.services.gnome-autounlock-keyring = {
              enable = mkEnableOption "gnome-autounlock.keyring";

              target = mkOption {
                type = types.str;
                default = "graphical-session.target";
                example = "hyprland-session.target";
              };
            };

            config = mkIf cfg.enable {
              systemd.user.services.gnome-autounlock-keyring = {
                description = "Automatically unlock gnome keyring using TPM";
                wantedBy = [ cfg.target ];
                script = ''
                  ${self.packages.${pkgs.system}.default}/bin/gnome-autounlock-keyring unlock
                '';
                serviceConfig.Type = "oneshot";
              };
            };
          };
        gnome-autounlock-keyring = default;
      };
    };
}
