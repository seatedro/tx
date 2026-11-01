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

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      zig,
      ...
    }:
    let
      # build.zig.zon's version, then the commit, as `0.0.0-dev+965921b`.
      zonVersion = builtins.head (
        builtins.match ''.*[.]version = "([^"]+)".*'' (builtins.readFile ./build.zig.zon)
      );
      version = "${zonVersion}-dev+${self.shortRev or self.dirtyShortRev or "unknown"}";
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig' = zig.packages.${system}."0.17.0";
      in
      {
        packages.default = pkgs.callPackage ./nix/package.nix {
          zig = zig';
          inherit version;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            zig'
            pkgs.clang-tools # clang-format for src/**/*.{c,h}
          ]
          # wl-copy and wl-paste, which the clipboard server's tests run.
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.wl-clipboard ];
        };
      }
    )
    // {
      overlays.default = final: _: { tx = self.packages.${final.stdenv.hostPlatform.system}.default; };

      # services.txd; see nix/home-module.nix.
      homeModules.default = import ./nix/home-module.nix self;
    };
}
