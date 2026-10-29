{
  description = "tx: a remote terminal built on libghostty-vt";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    # Zig 0.17, which Ghostty main requires. nixpkgs only has 0.16.
    zig = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    zig,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.default = pkgs.mkShell {
        packages =
          [
            zig.packages.${system}."0.17.0"
            pkgs.clang-tools # clang-format for src/**/*.{c,h}
          ]
          # wl-copy and wl-paste, which the clipboard server's tests run.
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [pkgs.wl-clipboard];
      };
    });
}
