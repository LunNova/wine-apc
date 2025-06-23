# SPDX-FileCopyrightText: 2025 LunNova
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    args:
    args.flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = (import args.nixpkgs) {
          inherit system;
        };

        # Minimal runtime dependencies for wine-apc
        runtimeDeps = [
          # none, yet
        ];

        LD_LIBRARY_PATH = "/run/opengl-driver/lib/:${pkgs.lib.makeLibraryPath runtimeDeps}";

        # Development shell packages
        devShellPkgs = [
          pkgs.python3 # For parse_strace.py
          pkgs.cargo-deny
          pkgs.cargo-bloat
          pkgs.cargo-flamegraph
          pkgs.cargo-udeps
          pkgs.cargo-modules
          pkgs.rustfmt
          pkgs.reuse
          pkgs.pkg-config
          pkgs.just
          pkgs.cmake
          pkgs.binutils
          pkgs.xxd
          pkgs.strace # For tracing Wine communication
        ] ++ runtimeDeps;

        # Teaches Cargo to use Wine to run X86_64_PC_WINDOWS_GNU tests and binaries
        # (https://doc.rust-lang.org/cargo/reference/config.html#targettriplerunner)
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER = pkgs.writeShellScript "wine-wrapper" ''
          echo "Launching $@ with $(command -v wine64)"
          if [ -z "''${WINEPREFIX+x}" ]; then
            export WINEPREFIX="''${XDG_CACHE_HOME:-$HOME/.cache}/wine-cargo-test-prefix/"
          fi

          exec wine $@
        '';

        fenix = args.fenix.packages.${system};

        toolchain =
          with fenix;
          combine [
            complete.rustc
            complete.cargo
            targets.x86_64-pc-windows-gnu.latest.rust-std
          ];

        naersk = args.naersk.lib.${system}.override {
          cargo = toolchain;
          rustc = toolchain;
        };
        self = {
          devShells.default = self.devShells.rustup-dev;

          devShells.rustup-dev = pkgs.stdenv.mkDerivation {
            inherit CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER LD_LIBRARY_PATH;
            name = "rustup-dev-shell";

            # Unset CC and CFLAGS_COMPILE to fix mingw targets
            shellHook = ''
              export CC=
              export NIX_CFLAGS_COMPILE=
              export NIX_CFLAGS_COMPILE_FOR_TARGET=
            '';

            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "x86_64-w64-mingw32-gcc";
            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L ${pkgs.pkgsCross.mingwW64.windows.pthreads}/lib";

            depsBuildBuild = with pkgs; [
              pkg-config
            ];

            nativeBuildInputs = with pkgs; [
              mold
              lld
            ];

            GLIBC_PATH = "${pkgs.glibc_multi}/lib";

            buildInputs =
              with pkgs;
              [
                glibc_multi
                rustup
                libunwind
                pkgsCross.mingwW64.stdenv.cc
              ]
              ++ devShellPkgs;
          };

          packages.default = naersk.buildPackage {
            src = ./wine-apc;
            strictDeps = true;
            doCheck = true;
          };

          # FIXME: this should be for the win example
          packages.x86_64-pc-windows-gnu = naersk.buildPackage {
            inherit CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER;
            src = ./wine-apc;
            strictDeps = true;

            depsBuildBuild = with pkgs; [
              pkgsCross.mingwW64.stdenv.cc
              pkgsCross.mingwW64.windows.pthreads
            ];

            nativeBuildInputs = with pkgs; [
              # We need Wine to run tests:
              wineWowPackages.staging
            ];

            doCheck = true;

            # Tells Cargo that we're building for Windows.
            # (https://doc.rust-lang.org/cargo/reference/config.html#buildtarget)
            CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
          };
        };
      in
      self
    );
}
