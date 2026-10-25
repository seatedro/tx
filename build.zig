const std = @import("std");
const ngtcp2_build = @import("src/build/ngtcp2.zig");
const picotls_build = @import("src/build/picotls.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libghostty-vt, pinned in build.zig.zon. Code in src/ will import it.
    const ghostty = b.dependency("ghostty", .{
        .target = target,
        .optimize = optimize,
    });
    _ = ghostty.module("ghostty-vt");

    // QUIC (ngtcp2) and TLS 1.3 (picotls), built from upstream sources.
    const ngtcp2_dep = b.dependency("ngtcp2", .{});
    const picotls_dep = b.dependency("picotls", .{});
    const ngtcp2 = ngtcp2_build.core(b, ngtcp2_dep, target, optimize);
    const picotls = picotls_build.core(b, picotls_dep, target, optimize);
    b.getInstallStep().dependOn(&ngtcp2.step);

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
