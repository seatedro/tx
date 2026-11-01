{
  description = "tx: a remote terminal built on libghostty-vt";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

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
            pkgs.clang-tools
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.wl-clipboard ];
        };
      }
    )
    // {
      overlays.default = final: _: { tx = self.packages.${final.stdenv.hostPlatform.system}.default; };

      homeModules.default = import ./nix/home-module.nix self;
    };
}
