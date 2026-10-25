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
    b.getInstallStep().dependOn(&picotls.step);
}
