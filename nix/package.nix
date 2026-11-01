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

  target =
    {
      aarch64-linux = "aarch64-linux-musl";
      x86_64-linux = "x86_64-linux-musl";
      aarch64-darwin = "aarch64-macos";
      x86_64-darwin = "x86_64-macos";
    }
    .${stdenvNoCC.hostPlatform.system};

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
    cp -r ${deps} zig-pkg
    zig build install -j$NIX_BUILD_CORES --prefix $out \
      -Dtarget=${target} -Doptimize=ReleaseSafe -Dstrip -Dversion=${version}
  '';
  dontInstall = true;
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
