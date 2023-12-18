{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) stdenv lib;
      in {
        devShell = pkgs.mkShell {
          shellHook = ''
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
          nativeBuildInputs = with pkgs; [
            llvmPackages.libclang
            llvmPackages.libcxxClang
            clang
          ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          buildInputs = with pkgs; [ libclang pkg-config openssl tpm2-tss ];
        };
      });
}
