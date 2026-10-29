const std = @import("std");
const ngtcp2_build = @import("src/build/ngtcp2.zig");
const picotls_build = @import("src/build/picotls.zig");

/// The version in build.zig.zon. Builds other than `zig build release`
/// add `-dev`.
const version = @import("build.zig.zon").version;

/// The platforms `zig build release` builds for. `os` and `arch` are the
/// names of `std.Target.Os.Tag` and `std.Target.Cpu.Arch`. Linux builds are
/// static, so that they run on any distribution.
const release_targets = [_]struct { query: std.Target.Query, os: []const u8, arch: []const u8 }{
    .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl }, .os = "linux", .arch = "x86_64" },
    .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl }, .os = "linux", .arch = "aarch64" },
    .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .macos }, .os = "macos", .arch = "x86_64" },
    .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .macos }, .os = "macos", .arch = "aarch64" },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libs = libraries(b, target, optimize);
    const ghostty_vt = libs.ghostty_vt;
    const xev = libs.transport.xev;
    const transport_libs = libs.transport;
    const wake = libs.wake;
    b.getInstallStep().dependOn(&transport_libs.ngtcp2_crypto.step);
    const picotls_dep = b.dependency("picotls", .{});

    const test_step = b.step("test", "Run unit tests");
    const test_network_step = b.step("test-network", "Run unit tests, including ones that need the internet");

    // For the fuzz tests. One module, since a test build may reach it
    // through more than one of its modules.
    const fuzz = b.createModule(.{ .root_source_file = b.path("src/fuzz.zig") });

    const crypto_tests = b.addTest(.{
        .name = "crypto-test",
        .root_module = cryptoModule(b, target, optimize, transport_libs.picotls),
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
    transport_tests.root_module.addImport("fuzz", fuzz);
    addTestRuns(b, transport_tests, test_step, test_network_step);

    const term_tests = b.addTest(.{
        .name = "term-test",
        .root_module = termModule(b, target, optimize, ghostty_vt),
    });
    addTestRuns(b, term_tests, test_step, test_network_step);

    const session_tests = b.addTest(.{
        .name = "session-test",
        .root_module = sessionModule(b, target, optimize, .{
            .term = termModule(b, target, optimize, ghostty_vt),
            .wake = wake,
            .xev = xev,
            .proto = protoModule(b, target, optimize),
            .auth = authModule(b, target, optimize),
        }),
    });
    addTestRuns(b, session_tests, test_step, test_network_step);

    const proto_tests = b.addTest(.{
        .name = "proto-test",
        .root_module = protoModule(b, target, optimize),
    });
    proto_tests.root_module.addImport("fuzz", fuzz);
    addTestRuns(b, proto_tests, test_step, test_network_step);

    const auth_tests = b.addTest(.{
        .name = "auth-test",
        .root_module = authModule(b, target, optimize),
    });
    auth_tests.root_module.addImport("fuzz", fuzz);
    addTestRuns(b, auth_tests, test_step, test_network_step);

    const wayland_tests = b.addTest(.{
        .name = "wayland-test",
        .root_module = waylandModule(b, target, optimize, xev),
    });
    wayland_tests.root_module.addImport("fuzz", fuzz);
    addTestRuns(b, wayland_tests, test_step, test_network_step);

    // The tests with fuzz tests that `--fuzz` can build. Under it, C code
    // doesn't link and ghostty-vt's build makes a Unicode table that
    // doesn't compile. So the SPA guard's tests build alone, and the
    // end-to-end tests are left out. They build with LLVM, which adds the
    // fuzzer's instrumentation; the x86_64 backend Debug builds use
    // doesn't.
    const fuzz_step = b.step("fuzz", "Run the fuzz tests of what a client reaches before login and of the Wayland wire format; with --fuzz, fuzz them");
    for ([_]struct { []const u8, *std.Build.Module }{
        .{ "proto-fuzz", protoModule(b, target, optimize) },
        .{ "auth-fuzz", authModule(b, target, optimize) },
        .{ "wayland-fuzz", waylandModule(b, target, optimize, xev) },
        .{ "spa-fuzz", b.createModule(.{
            .root_source_file = b.path("src/transport/spa.zig"),
            .target = target,
            .optimize = optimize,
        }) },
    }) |entry| {
        const name, const module = entry;
        module.addImport("fuzz", fuzz);
        const tests = b.addTest(.{ .name = name, .root_module = module, .use_llvm = true });
        fuzz_step.dependOn(&b.addRunArtifact(tests).step);
    }

    const app = appModules(b, target, optimize, libs);
    const term = app.term;
    const transport = app.transport;
    const proto = app.proto;
    const auth = app.auth;
    const session = app.session;
    const client = app.client;
    const server = app.server;

    const server_tests = b.addTest(.{
        .name = "server-test",
        .root_module = serverModule(b, target, optimize, .{
            .xev = xev,
            .transport = transport,
            .proto = proto,
            .auth = auth,
            .session = session,
            .term = term,
            .wayland = app.wayland,
        }),
    });
    addTestRuns(b, server_tests, test_step, test_network_step);

    const client_tests = b.addTest(.{
        .name = "client-test",
        .root_module = clientModule(b, target, optimize, .{ .xev = xev, .transport = transport, .proto = proto, .auth = auth, .wake = wake }),
    });
    addTestRuns(b, client_tests, test_step, test_network_step);

    // Writes the list of txd builds that tx carries.
    const txd_builds_tool = b.addExecutable(.{
        .name = "txd_builds",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/build/txd_builds.zig"),
            .target = b.graph.host,
        }),
    });

    // A development build lists no txd builds.
    const dev_info = buildInfo(b, version ++ "-dev");
    const dev_builds = b.addRunArtifact(txd_builds_tool);
    const dev_builds_module = b.createModule(.{ .root_source_file = dev_builds.addOutputFileArg("txd_builds.zig") });

    const tx = txModule(b, target, optimize, app, dev_info, dev_builds_module);
    const tx_bin = b.addExecutable(.{ .name = "tx", .root_module = tx });
    b.installArtifact(tx_bin);
    addTestRuns(b, b.addTest(.{ .name = "cli-test", .root_module = tx }), test_step, test_network_step);

    const txd = txdModule(b, target, optimize, app, dev_info);
    const txd_bin = b.addExecutable(.{ .name = "txd", .root_module = txd });
    b.installArtifact(txd_bin);
    addTestRuns(b, b.addTest(.{ .name = "txd-test", .root_module = txd }), test_step, test_network_step);

    // The end-to-end tests run a server and clients in one process. The
    // sessions run in txd processes.
    const e2e = b.createModule(.{
        .root_source_file = b.path("src/e2e_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    e2e.addImport("xev", xev);
    e2e.addImport("transport", transport);
    e2e.addImport("server", server);
    e2e.addImport("session", session);
    e2e.addImport("client", client);
    e2e.addImport("term", term);
    e2e.addImport("proto", proto);
    e2e.addImport("auth", auth);
    e2e.addImport("fuzz", fuzz);
    const e2e_options = b.addOptions();
    e2e_options.addOptionPath("txd_exe", txd_bin.getEmittedBin());
    e2e_options.addOptionPath("tx_exe", tx_bin.getEmittedBin());
    e2e.addImport("build_options", e2e_options.createModule());
    addTestRuns(b, b.addTest(.{ .name = "e2e-test", .root_module = e2e }), test_step, test_network_step);

    // `zig build release` makes `tx-VERSION-OS-ARCH.tar.gz` in
    // zig-out/release for each release platform, with tx, txd, the license
    // and the README in a directory of the same name. Each tx carries the
    // SHA-256 of every txd.
    const release_step = b.step("release", "Build tx and txd for every release platform");
    const release_info = buildInfo(b, version);
    const release_builds = b.addRunArtifact(txd_builds_tool);
    const release_builds_module = b.createModule(.{ .root_source_file = release_builds.addOutputFileArg("txd_builds.zig") });
    const tarball_tool = b.addExecutable(.{
        .name = "tarball",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/build/tarball.zig"),
            .target = b.graph.host,
        }),
    });
    var release_apps: [release_targets.len]AppModules = undefined;
    var txds: [release_targets.len]*std.Build.Step.Compile = undefined;
    for (release_targets, &release_apps, &txds) |rt, *rt_app, *txd_exe| {
        const rt_target = b.resolveTargetQuery(rt.query);
        rt_app.* = appModules(b, rt_target, .ReleaseSafe, libraries(b, rt_target, .ReleaseSafe));
        txd_exe.* = b.addExecutable(.{ .name = "txd", .root_module = txdModule(b, rt_target, .ReleaseSafe, rt_app.*, release_info) });
        txd_exe.*.root_module.strip = true;
        release_builds.addArgs(&.{ rt.os, rt.arch });
        release_builds.addFileArg(txd_exe.*.getEmittedBin());
    }
    for (release_targets, release_apps, txds) |rt, rt_app, txd_exe| {
        const rt_target = b.resolveTargetQuery(rt.query);
        const tx_exe = b.addExecutable(.{ .name = "tx", .root_module = txModule(b, rt_target, .ReleaseSafe, rt_app, release_info, release_builds_module) });
        tx_exe.root_module.strip = true;

        const name = b.fmt("tx-{s}-{s}-{s}", .{ version, rt.os, rt.arch });
        const tarball = b.addRunArtifact(tarball_tool);
        const out = tarball.addOutputFileArg(b.fmt("{s}.tar.gz", .{name}));
        tarball.addArg(name);
        tarball.addArgs(&.{ "tx", "755" });
        tarball.addFileArg(tx_exe.getEmittedBin());
        tarball.addArgs(&.{ "txd", "755" });
        tarball.addFileArg(txd_exe.getEmittedBin());
        tarball.addArgs(&.{ "LICENSE", "644" });
        tarball.addFileArg(b.path("LICENSE"));
        tarball.addArgs(&.{ "README.md", "644" });
        tarball.addFileArg(b.path("README.md"));
        release_step.dependOn(&b.addInstallFile(out, b.fmt("release/{s}.tar.gz", .{name})).step);
    }
}

/// `build_options`, with the version.
fn buildInfo(b: *std.Build, version_text: []const u8) *std.Build.Module {
    const options = b.addOptions();
    options.addOption([]const u8, "version", version_text);
    return options.createModule();
}

const Libraries = struct {
    ghostty_vt: *std.Build.Module,
    transport: TransportLibs,
    /// The wake pipe, shared by the client's threads and the session host.
    wake: *std.Build.Module,
};

fn libraries(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) Libraries {
    const ghostty = b.dependency("ghostty", .{
        .target = target,
        .optimize = optimize,
    });

    const ngtcp2_dep = b.dependency("ngtcp2", .{});
    const picotls_dep = b.dependency("picotls", .{});
    const ngtcp2 = ngtcp2_build.core(b, ngtcp2_dep, target, optimize);
    const picotls = picotls_build.core(b, picotls_dep, target, optimize);
    const ngtcp2_crypto = ngtcp2_build.cryptoPicotls(b, ngtcp2_dep, target, optimize, .{
        .picotls_include = picotls_dep.path("include"),
        .backend_include = b.path("src/crypto/include"),
    });

    const xev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    }).module("xev");

    return .{
        .ghostty_vt = ghostty.module("ghostty-vt"),
        .transport = .{
            .xev = xev,
            .ngtcp2 = ngtcp2,
            .ngtcp2_crypto = ngtcp2_crypto,
            .picotls = picotls,
        },
        .wake = b.createModule(.{
            .root_source_file = b.path("src/wake.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    };
}

/// One instance of each module for the executables and the end-to-end
/// test, so that they share their dependencies' code and globals.
const AppModules = struct {
    xev: *std.Build.Module,
    term: *std.Build.Module,
    transport: *std.Build.Module,
    proto: *std.Build.Module,
    auth: *std.Build.Module,
    session: *std.Build.Module,
    client: *std.Build.Module,
    server: *std.Build.Module,
    wayland: *std.Build.Module,
};

fn appModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, libs: Libraries) AppModules {
    const xev = libs.transport.xev;
    const term = termModule(b, target, optimize, libs.ghostty_vt);
    const transport = transportModule(b, target, optimize, libs.transport);
    const proto = protoModule(b, target, optimize);
    const auth = authModule(b, target, optimize);
    const session = sessionModule(b, target, optimize, .{ .term = term, .wake = libs.wake, .xev = xev, .proto = proto, .auth = auth });
    const wayland = waylandModule(b, target, optimize, xev);
    return .{
        .xev = xev,
        .term = term,
        .transport = transport,
        .proto = proto,
        .auth = auth,
        .session = session,
        .client = clientModule(b, target, optimize, .{ .xev = xev, .transport = transport, .proto = proto, .auth = auth, .wake = libs.wake }),
        .server = serverModule(b, target, optimize, .{
            .xev = xev,
            .transport = transport,
            .proto = proto,
            .auth = auth,
            .session = session,
            .term = term,
            .wayland = wayland,
        }),
        .wayland = wayland,
    };
}

fn txModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    app: AppModules,
    info: *std.Build.Module,
    txd_builds: *std.Build.Module,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/cli/tx.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("client", app.client);
    mod.addImport("transport", app.transport);
    mod.addImport("auth", app.auth);
    mod.addImport("proto", app.proto);
    mod.addImport("build_options", info);
    mod.addImport("txd_builds", txd_builds);
    return mod;
}

fn txdModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    app: AppModules,
    info: *std.Build.Module,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/cli/txd.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("xev", app.xev);
    mod.addImport("server", app.server);
    mod.addImport("session", app.session);
    mod.addImport("transport", app.transport);
    mod.addImport("auth", app.auth);
    mod.addImport("proto", app.proto);
    mod.addImport("build_options", info);
    return mod;
}

const ServerDeps = struct {
    xev: *std.Build.Module,
    transport: *std.Build.Module,
    proto: *std.Build.Module,
    auth: *std.Build.Module,
    session: *std.Build.Module,
    term: *std.Build.Module,
    wayland: *std.Build.Module,
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
    mod.addImport("auth", deps.auth);
    mod.addImport("session", deps.session);
    mod.addImport("term", deps.term);
    mod.addImport("wayland", deps.wayland);
    return mod;
}

const ClientDeps = struct {
    xev: *std.Build.Module,
    transport: *std.Build.Module,
    proto: *std.Build.Module,
    auth: *std.Build.Module,
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

fn authModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/auth/root.zig"),
        .target = target,
        .optimize = optimize,
    });
}

fn waylandModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    xev: *std.Build.Module,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/wayland/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("xev", xev);
    return mod;
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
    mod.addImport("auth", deps.auth);
    mod.addImport("wake", deps.wake);
    return mod;
}

const SessionDeps = struct {
    term: *std.Build.Module,
    wake: *std.Build.Module,
    xev: *std.Build.Module,
    proto: *std.Build.Module,
    auth: *std.Build.Module,
};

fn sessionModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: SessionDeps,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/session/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("term", deps.term);
    mod.addImport("wake", deps.wake);
    mod.addImport("xev", deps.xev);
    mod.addImport("proto", deps.proto);
    mod.addImport("auth", deps.auth);
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
