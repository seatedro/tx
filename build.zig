const std = @import("std");
const ngtcp2_build = @import("src/build/ngtcp2.zig");
const picotls_build = @import("src/build/picotls.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ghostty = b.dependency("ghostty", .{
        .target = target,
        .optimize = optimize,
    });
    const ghostty_vt = ghostty.module("ghostty-vt");

    const ngtcp2_dep = b.dependency("ngtcp2", .{});
    const picotls_dep = b.dependency("picotls", .{});
    const ngtcp2 = ngtcp2_build.core(b, ngtcp2_dep, target, optimize);
    const picotls = picotls_build.core(b, picotls_dep, target, optimize);
    const ngtcp2_crypto = ngtcp2_build.cryptoPicotls(b, ngtcp2_dep, target, optimize, .{
        .picotls_include = picotls_dep.path("include"),
        .backend_include = b.path("src/crypto/include"),
    });
    b.getInstallStep().dependOn(&ngtcp2_crypto.step);

    const xev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    }).module("xev");

    const transport_libs: TransportLibs = .{
        .xev = xev,
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

    // The wake pipe, shared by the client's threads and the session host.
    const wake = b.createModule(.{
        .root_source_file = b.path("src/wake.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const session_tests = b.addTest(.{
        .name = "session-test",
        .root_module = sessionModule(b, target, optimize, termModule(b, target, optimize, ghostty_vt), wake),
    });
    addTestRuns(b, session_tests, test_step, test_network_step);

    const proto_tests = b.addTest(.{
        .name = "proto-test",
        .root_module = protoModule(b, target, optimize),
    });
    addTestRuns(b, proto_tests, test_step, test_network_step);

    // One instance of each module for the executables and the end-to-end
    // test, so that they share their dependencies' code and globals.
    const term = termModule(b, target, optimize, ghostty_vt);
    const transport = transportModule(b, target, optimize, transport_libs);
    const proto = protoModule(b, target, optimize);
    const session = sessionModule(b, target, optimize, term, wake);
    const client = clientModule(b, target, optimize, .{ .xev = xev, .transport = transport, .proto = proto, .wake = wake });
    const server = serverModule(b, target, optimize, .{
        .xev = xev,
        .transport = transport,
        .proto = proto,
        .session = session,
        .term = term,
    });

    const client_tests = b.addTest(.{
        .name = "client-test",
        .root_module = clientModule(b, target, optimize, .{ .xev = xev, .transport = transport, .proto = proto, .wake = wake }),
    });
    addTestRuns(b, client_tests, test_step, test_network_step);

    // The end-to-end tests run a server and clients in one process.
    const e2e = b.createModule(.{
        .root_source_file = b.path("src/e2e_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    e2e.addImport("xev", xev);
    e2e.addImport("transport", transport);
    e2e.addImport("server", server);
    e2e.addImport("client", client);
    e2e.addImport("term", term);
    e2e.addImport("proto", proto);
    addTestRuns(b, b.addTest(.{ .name = "e2e-test", .root_module = e2e }), test_step, test_network_step);

    const tx = b.createModule(.{
        .root_source_file = b.path("src/cli/tx.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tx.addImport("client", client);
    b.installArtifact(b.addExecutable(.{ .name = "tx", .root_module = tx }));

    const tx_session = b.createModule(.{
        .root_source_file = b.path("src/cli/tx_session.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tx_session.addImport("xev", xev);
    tx_session.addImport("server", server);
    tx_session.addImport("transport", transport);
    b.installArtifact(b.addExecutable(.{ .name = "tx-session", .root_module = tx_session }));
}

const ServerDeps = struct {
    xev: *std.Build.Module,
    transport: *std.Build.Module,
    proto: *std.Build.Module,
    session: *std.Build.Module,
    term: *std.Build.Module,
};

fn serverModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: ServerDeps,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/server/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("xev", deps.xev);
    mod.addImport("transport", deps.transport);
    mod.addImport("proto", deps.proto);
    mod.addImport("session", deps.session);
    mod.addImport("term", deps.term);
    return mod;
}

const ClientDeps = struct {
    xev: *std.Build.Module,
    transport: *std.Build.Module,
    proto: *std.Build.Module,
    wake: *std.Build.Module,
};

fn protoModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/proto/root.zig"),
        .target = target,
        .optimize = optimize,
    });
}

fn clientModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: ClientDeps,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/client/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("xev", deps.xev);
    mod.addImport("transport", deps.transport);
    mod.addImport("proto", deps.proto);
    mod.addImport("wake", deps.wake);
    return mod;
}

fn sessionModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    term: *std.Build.Module,
    wake: *std.Build.Module,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/session/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("term", term);
    mod.addImport("wake", wake);
    return mod;
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

/// `test_network_step` sets `TX_TEST_NETWORK`, which enables the tests that
/// need the internet.
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
    xev: *std.Build.Module,
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
    // picotls's headers are left out because its structs use bitfields,
    // which translate-c can't express. Only tls.c includes them.
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
    mod.addImport("xev", libs.xev);
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
