const std = @import("std");
const ngtcp2_build = @import("src/build/ngtcp2.zig");
const picotls_build = @import("src/build/picotls.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libghostty-vt, pinned in build.zig.zon.
    const ghostty = b.dependency("ghostty", .{
        .target = target,
        .optimize = optimize,
    });
    const ghostty_vt = ghostty.module("ghostty-vt");

    // QUIC (ngtcp2) and TLS 1.3 (picotls), built from upstream sources.
    const ngtcp2_dep = b.dependency("ngtcp2", .{});
    const picotls_dep = b.dependency("picotls", .{});
    const ngtcp2 = ngtcp2_build.core(b, ngtcp2_dep, target, optimize);
    const picotls = picotls_build.core(b, picotls_dep, target, optimize);
    const ngtcp2_crypto = ngtcp2_build.cryptoPicotls(b, ngtcp2_dep, target, optimize, .{
        .picotls_include = picotls_dep.path("include"),
        .backend_include = b.path("src/crypto/include"),
    });
    b.getInstallStep().dependOn(&ngtcp2_crypto.step);

    const transport_libs: TransportLibs = .{
        .ngtcp2 = ngtcp2,
        .ngtcp2_crypto = ngtcp2_crypto,
        .picotls = picotls,
    };

    const test_step = b.step("test", "Run unit tests");
    const test_network_step = b.step("test-network", "Run unit tests, including ones that need the internet");

    const crypto_tests = b.addTest(.{
        .name = "crypto-test",
        .root_module = cryptoModule(b, target, optimize, picotls),
    });
    crypto_tests.root_module.addCSourceFile(.{
        .file = b.path("src/crypto/picotls_backend_test.c"),
        .flags = c_flags,
    });
    crypto_tests.root_module.linkLibrary(picotls_build.minicrypto(b, picotls_dep, target, optimize));
    addTestRuns(b, crypto_tests, test_step, test_network_step);

    const transport_tests = b.addTest(.{
        .name = "transport-test",
        .root_module = transportModule(b, target, optimize, transport_libs),
    });
    addTestRuns(b, transport_tests, test_step, test_network_step);

    const term_tests = b.addTest(.{
        .name = "term-test",
        .root_module = termModule(b, target, optimize, ghostty_vt),
    });
    addTestRuns(b, term_tests, test_step, test_network_step);
}

fn termModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    ghostty_vt: *std.Build.Module,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/term/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("ghostty-vt", ghostty_vt);
    return mod;
}

const c_flags = &[_][]const u8{"-std=gnu11"};

fn cryptoModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    picotls: *std.Build.Step.Compile,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/crypto/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addIncludePath(b.path("src/crypto/include"));
    mod.addCSourceFile(.{ .file = b.path("src/crypto/picotls_backend.c"), .flags = c_flags });
    mod.linkLibrary(picotls);
    return mod;
}

/// `zig build test` runs `tests` offline; `zig build test-network` also runs
/// the tests that need the internet.
fn addTestRuns(
    b: *std.Build,
    tests: *std.Build.Step.Compile,
    test_step: *std.Build.Step,
    test_network_step: *std.Build.Step,
) void {
    test_step.dependOn(&b.addRunArtifact(tests).step);
    const network = b.addRunArtifact(tests);
    network.setEnvironmentVariable("TX_TEST_NETWORK", "1");
    test_network_step.dependOn(&network.step);
}

const TransportLibs = struct {
    ngtcp2: *std.Build.Step.Compile,
    ngtcp2_crypto: *std.Build.Step.Compile,
    picotls: *std.Build.Step.Compile,
};

fn transportModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libs: TransportLibs,
) *std.Build.Module {
    // ngtcp2's API and tls.h, translated for quic.zig. picotls's headers
    // stay out: its structs use bitfields, so only tls.c touches them.
    const c = b.addTranslateC(.{
        .root_source_file = b.path("src/transport/c.h"),
        .target = target,
        .optimize = optimize,
    });
    c.addIncludePath(b.path("src/transport/include"));
    c.addIncludePath(libs.ngtcp2.getEmittedIncludeTree());
    c.addIncludePath(libs.ngtcp2_crypto.getEmittedIncludeTree());
    c.defineCMacro("NGTCP2_STATICLIB", "1");

    const mod = b.createModule(.{
        .root_source_file = b.path("src/transport/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("c", c.createModule());
    mod.addImport("crypto", cryptoModule(b, target, optimize, libs.picotls));
    mod.addIncludePath(b.path("src/transport/include"));
    mod.addIncludePath(b.path("src/crypto/include"));
    mod.addCMacro("NGTCP2_STATICLIB", "1");
    mod.addCSourceFile(.{ .file = b.path("src/transport/tls.c"), .flags = c_flags });
    mod.linkLibrary(libs.ngtcp2_crypto);
    mod.linkLibrary(libs.ngtcp2);
    mod.linkLibrary(libs.picotls);
    return mod;
}
