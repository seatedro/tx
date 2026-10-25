//! Builds picotls (h2o/picotls) from its upstream sources.
//!
//! picotls is a TLS 1.3 state machine with pluggable cryptography. tx links
//! only the core and supplies the cryptography itself (src/crypto). The
//! minicrypto backend is built separately so tests can check tx's backend
//! against an independent implementation.
const std = @import("std");

const flags = &[_][]const u8{ "-std=gnu99", "-fno-sanitize=undefined" };

/// The TLS 1.3 core, with no cryptography.
pub fn core(
    b: *std.Build,
    dep: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "picotls",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.root_module.addIncludePath(dep.path("include"));
    lib.root_module.addCSourceFiles(.{
        .root = dep.path("lib"),
        .files = &.{ "picotls.c", "hpke.c", "pembase64.c" },
        .flags = flags,
    });
    lib.installHeadersDirectory(dep.path("include"), "", .{});
    return lib;
}

/// The bundled minicrypto backend (cifra and micro-ecc). Used by tests only.
pub fn minicrypto(
    b: *std.Build,
    dep: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "picotls-minicrypto",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    for ([_][]const u8{ "include", "deps/cifra/src", "deps/cifra/src/ext", "deps/micro-ecc" }) |dir| {
        lib.root_module.addIncludePath(dep.path(dir));
    }
    lib.root_module.addCSourceFiles(.{
        .root = dep.path(""),
        .files = &.{
            "deps/micro-ecc/uECC.c",
            "deps/cifra/src/aes.c",
            "deps/cifra/src/blockwise.c",
            "deps/cifra/src/chacha20.c",
            "deps/cifra/src/chash.c",
            "deps/cifra/src/curve25519.c",
            "deps/cifra/src/drbg.c",
            "deps/cifra/src/hmac.c",
            "deps/cifra/src/gcm.c",
            "deps/cifra/src/gf128.c",
            "deps/cifra/src/modes.c",
            "deps/cifra/src/poly1305.c",
            "deps/cifra/src/sha256.c",
            "deps/cifra/src/sha512.c",
            "lib/cifra.c",
            "lib/cifra/x25519.c",
            "lib/cifra/chacha20.c",
            "lib/cifra/aes128.c",
            "lib/cifra/aes256.c",
            "lib/cifra/random.c",
            "lib/minicrypto-pem.c",
            "lib/uecc.c",
            "lib/asn1.c",
            "lib/ffx.c",
        },
        .flags = flags,
    });
    return lib;
}
