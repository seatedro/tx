# tx and txd, built as a release is: ReleaseSafe, and static on Linux.
{
  lib,
  stdenvNoCC,
  zig,
  version,
}:
let
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../build.zig
      ../build.zig.zon
      ../src
      ../LICENSE
      ../README.md
    ];
  };

  # Zig's name for the platform's target. A target named outright, rather
  # than the native one, builds for the baseline CPU, and on macOS needs no
  # SDK.
  target =
    {
      aarch64-linux = "aarch64-linux-musl";
      x86_64-linux = "x86_64-linux-musl";
      aarch64-darwin = "aarch64-macos";
      x86_64-darwin = "x86_64-macos";
    }
    .${stdenvNoCC.hostPlatform.system};

  # The packages build.zig.zon names, and the lazy ones Ghostty's build asks
  # for, as zig-pkg holds them. `zig build --fetch` leaves the lazy ones
  # out; configuring the build, which `zig build -l` does, fetches them.
  #
  # When build.zig.zon's dependencies change, so does the hash: set it to
  # "", build, and copy the hash Nix prints.
  deps = stdenvNoCC.mkDerivation {
    name = "tx-zig-pkg";
    inherit src;
    nativeBuildInputs = [ zig ];

    buildPhase = ''
      export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
      zig build -l >/dev/null
    '';
    installPhase = "mv zig-pkg $out";
    dontFixup = true;

    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-TLF3KnrzQ6kppf7o+kTDKjGn0llpLvZYjToG1/uzIVQ=";
  };
in
stdenvNoCC.mkDerivation {
  pname = "tx";
  inherit version src;
  nativeBuildInputs = [ zig ];

  buildPhase = ''
    export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
    # A copy, not a link: build steps run in a package's directory, with
    # paths relative to it that lead back to .zig-cache.
    cp -r ${deps} zig-pkg
    zig build install -j$NIX_BUILD_CORES --prefix $out \
      -Dtarget=${target} -Doptimize=ReleaseSafe -Dstrip -Dversion=${version}
  '';
  dontInstall = true;
  # There is nothing to fix up: the binaries are static on Linux, and Zig
  # strips them. Stripping again on macOS would undo their signatures.
  dontFixup = true;

  passthru = { inherit deps; };

  meta = {
    description = "A remote terminal on QUIC and libghostty-vt, meant to replace ssh and mosh";
    homepage = "https://github.com/seatedro/tx";
    license = lib.licenses.mit;
    mainProgram = "tx";
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
      "aarch64-darwin"
      "x86_64-darwin"
    ];
  };
}
