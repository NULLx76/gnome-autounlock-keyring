{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        cargoToml = (builtins.fromTOML (builtins.readFile ./Cargo.toml));
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) stdenv lib;
      in rec {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = cargoToml.package.name;
          version = cargoToml.package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;

          doCheck = false;

          buildInputs = with pkgs; [ openssl tpm2-tss ];
          nativeBuildInputs = with pkgs; [
            llvmPackages.libclang
            llvmPackages.libcxxClang
            clang
            pkg-config
          ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          preBuild = ''
            export BINDGEN_EXTRA_CLANG_ARGS="$(< ${stdenv.cc}/nix-support/libc-crt1-cflags) \
               $(< ${stdenv.cc}/nix-support/libc-cflags) \
               $(< ${stdenv.cc}/nix-support/cc-cflags) \
               $(< ${stdenv.cc}/nix-support/libcxx-cxxflags) \
               ${
                 lib.optionalString stdenv.cc.isClang
                 "-idirafter ${stdenv.cc.cc}/lib/clang/${
                   lib.getVersion stdenv.cc.cc
                 }/include"
               } \
               ${
                 lib.optionalString stdenv.cc.isGNU
                 "-isystem ${stdenv.cc.cc}/include/c++/${
                   lib.getVersion stdenv.cc.cc
                 } -isystem ${stdenv.cc.cc}/include/c++/${
                   lib.getVersion stdenv.cc.cc
                 }/${stdenv.hostPlatform.config} -idirafter ${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${
                   lib.getVersion stdenv.cc.cc
                 }/include"
               } \
             "
          '';
        };

        devShells.default = pkgs.mkShell {
          shellHook = "${packages.default.preBuild}";
          inherit (packages.default)
            nativeBuildInputs buildInputs LIBCLANG_PATH;
        };
      }) // {
        nixosModules = rec {
          default = { config, lib, pkgs, ... }:
            with lib;
            let cfg = config.services.gnome-autounlock-keyring;
            in {
              options.services.gnome-autounlock-keyring = {
                enable = mkEnableOption "gnome-autounlock.keyring";
              };

              config = mkIf cfg.enable {
                systemd.user.services.gnome-autounlock-keyring = {
                  description = "Automatically unlock gnome keyring using TPM";
                  wantedBy = [ "gnome-session.target" ];
                  script = ''
                    ${self.packages.${pkgs.system}.default}/bin/gnome-autounlock-keyring unlock
                  '';
                  serviceConfig = { Type = "oneshot"; };
                };
              };
            };
          gnome-autounlock-keyring = default;
        };
      };
}
