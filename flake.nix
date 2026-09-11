{
  description = "a nix flake for developing pulsar";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux"] (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };
        lib = pkgs.lib;
        llvm = pkgs.llvmPackages_21;

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # cilium/little-vm-helper: boots the prebuilt kernels the `lvh`
        # integration job tests against. Not in nixpkgs, and upstream ships no
        # nix packaging, so build it here. Dependencies are vendored in-tree,
        # hence vendorHash = null.
        lvh = pkgs.buildGoModule rec {
          pname = "lvh";
          version = "0.0.23";
          src = pkgs.fetchFromGitHub {
            owner = "cilium";
            repo = "little-vm-helper";
            rev = "v${version}";
            hash = "sha256-qP5GNalVyiNLHdkwDWPEtIWtwQ9jsVcN6ZPnArwgMpo=";
          };
          vendorHash = null;
          subPackages = ["cmd/lvh"];
        };

        # Every target in the CI matrix. Adding one is a line here plus the
        # triple in rust-toolchain.toml.
        targets = {
          "x86_64-unknown-linux-musl" = pkgs.pkgsCross.musl64;
          "aarch64-unknown-linux-gnu" = pkgs.pkgsCross.aarch64-multiplatform;
          "aarch64-unknown-linux-musl" = pkgs.pkgsCross.aarch64-multiplatform-musl;
          "riscv64gc-unknown-linux-gnu" = pkgs.pkgsCross.riscv64;
          "riscv64gc-unknown-linux-musl" = pkgs.pkgsCross.riscv64-musl;
        };

        qemuFor = triple:
          if lib.hasPrefix "aarch64" triple
          then "qemu-aarch64"
          else if lib.hasPrefix "riscv64" triple
          then "qemu-riscv64"
          else "qemu-x86_64";

        # nixpkgs' pkg-config wrapper resolves against a salted variable and
        # ignores PKG_CONFIG_PATH, so it always answers with host libraries.
        # Give each cross target its own unwrapped pkg-config instead.
        crossPkgConfig = triple: cross:
          pkgs.writeShellScriptBin "${triple}-pkg-config" ''
            export PKG_CONFIG_PATH=${cross.openssl.dev}/lib/pkgconfig:${cross.sqlite.dev}/lib/pkgconfig
            exec ${pkgs.pkg-config-unwrapped}/bin/pkg-config "$@"
          '';

        targetEnv = triple: cross: let
          cc = cross.stdenv.cc;
          bin = p: "${cc}/bin/${cc.targetPrefix}${p}";
          upper = lib.replaceStrings ["-"] ["_"] (lib.toUpper triple);
          lower = lib.replaceStrings ["-"] ["_"] triple;
          isMusl = lib.hasSuffix "musl" triple;
          # qemu-user needs a sysroot to find the dynamic loader; musl builds are static.
          runner =
            "${pkgs.qemu-user}/bin/${qemuFor triple}"
            + lib.optionalString (!isMusl) " -L ${cc.libc}/";
          # rustc's link line does not reach the ld-wrapper's rpath logic, so
          # dynamically linked targets need their library paths spelled out.
          rustflags =
            lib.optionals (!isMusl) [
              "-C link-arg=-Wl,-rpath,${cross.openssl.out}/lib"
              "-C link-arg=-Wl,-rpath,${cross.sqlite.out}/lib"
            ]
            # rustc does not default musl riscv64 to a static crt the way it does the others.
            ++ lib.optional (triple == "riscv64gc-unknown-linux-musl")
            "-C target-feature=+crt-static";
        in
          [
            "export CARGO_TARGET_${upper}_LINKER=${bin "cc"}"
            "export CARGO_TARGET_${upper}_RUNNER='${runner}'"
            "export CC_${lower}=${bin "cc"}"
            "export AR_${lower}=${bin "ar"}"
          ]
          # musl builds use `all-vendored`, so they need no target openssl/sqlite.
          ++ lib.optional (!isMusl)
          "export PKG_CONFIG_${lower}=${crossPkgConfig triple cross}/bin/${triple}-pkg-config"
          ++ lib.optional (rustflags != [])
          "export CARGO_TARGET_${upper}_RUSTFLAGS='${lib.concatStringsSep " " rustflags}'";

        buildInputs = with pkgs; [
          rustToolchain

          # `linker=clang` + `-fuse-ld=lld` for the host build; llvm.bintools
          # supplies a *wrapped* ld.lld, without which binaries lose their RPATH.
          llvm.clang
          llvm.bintools
          llvm.llvm

          pkg-config
          openssl
          sqlite

          git
          coreutils
          clang-tools
          just
          rsync
          patchelf
          cargo-audit
          lychee

          # integration tests: qemu-user runs the cross-built unit tests,
          # qemu (system) boots the architest VMs.
          qemu-user
          qemu
          openssh
          e2fsprogs
          lvh
          zstd
        ]
        ++ map (cross: cross.stdenv.cc) (lib.attrValues targets);
      in {
        devShells.default = pkgs.mkShell {
          inherit buildInputs;

          shellHook = ''
            # The nix cc-wrapper injects host flags that break `-target bpf`
            # under -Werror; bpf-builder honours $CLANG.
            export CLANG="${llvm.clang-unwrapped}/bin/clang"
            export PKG_CONFIG_ALLOW_CROSS=1

            # Host target: rustc only gets a usable RPATH out of the nix
            # ld-wrapper when it links through clang with the wrapped ld.lld.
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C linker=clang -C link-arg=-fuse-ld=lld'

            ${lib.concatStringsSep "\n" (
              lib.flatten (lib.mapAttrsToList targetEnv targets)
            )}
          '';
        };
      }
    );
}
