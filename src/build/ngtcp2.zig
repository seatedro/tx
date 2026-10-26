//! Builds ngtcp2 (QUIC) from its upstream sources, replacing the CMake
//! configure step with Zig config headers.
const std = @import("std");

const version = "1.25.0";
const version_num = 0x011900;

const flags = &[_][]const u8{ "-std=gnu11", "-fno-sanitize=undefined" };

pub fn core(
    b: *std.Build,
    dep: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "ngtcp2",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const mod = lib.root_module;
    mod.addConfigHeader(configHeader(b, target));
    const version_h = versionHeader(b, dep);
    mod.addConfigHeader(version_h);
    mod.addIncludePath(dep.path("lib"));
    mod.addIncludePath(dep.path("lib/includes"));
    mod.addCMacro("HAVE_CONFIG_H", "1");
    mod.addCMacro("BUILDING_NGTCP2", "1");
    mod.addCMacro("NGTCP2_STATICLIB", "1");
    mod.addCSourceFiles(.{ .root = dep.path("lib"), .files = &lib_files, .flags = flags });
    lib.installHeadersDirectory(dep.path("lib/includes"), "", .{});
    lib.installConfigHeader(version_h);
    return lib;
}

pub const CryptoOptions = struct {
    /// picotls's public headers.
    picotls_include: std.Build.LazyPath,
    /// Directory containing tx's `picotls/openssl.h`, which maps the OpenSSL
    /// backend names used by ngtcp2's picotls adapter onto tx's backend.
    /// Searched before `picotls_include`.
    backend_include: std.Build.LazyPath,
};

/// ngtcp2's picotls adapter (`crypto/picotls/picotls.c`) and the crypto
/// helpers it shares with the other adapters.
pub fn cryptoPicotls(
    b: *std.Build,
    dep: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: CryptoOptions,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "ngtcp2_crypto_picotls",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const mod = lib.root_module;
    mod.addIncludePath(options.backend_include);
    mod.addIncludePath(options.picotls_include);
    mod.addConfigHeader(configHeader(b, target));
    mod.addConfigHeader(versionHeader(b, dep));
    for ([_][]const u8{ "crypto", "crypto/includes", "lib", "lib/includes" }) |dir| {
        mod.addIncludePath(dep.path(dir));
    }
    mod.addCMacro("HAVE_CONFIG_H", "1");
    mod.addCMacro("BUILDING_NGTCP2", "1");
    mod.addCMacro("NGTCP2_STATICLIB", "1");
    mod.addCSourceFiles(.{
        .root = dep.path("crypto"),
        .files = &.{ "shared.c", "picotls/picotls.c" },
        .flags = flags,
    });
    lib.installHeadersDirectory(dep.path("crypto/includes"), "", .{});
    return lib;
}

/// Replaces CMake's `config.h`.
fn configHeader(b: *std.Build, target: std.Build.ResolvedTarget) *std.Build.Step.ConfigHeader {
    const options: std.Build.Step.ConfigHeader.Options = .{ .style = .blank, .include_path = "config.h" };
    if (target.result.os.tag.isDarwin()) return b.addConfigHeader(options, .{
        .HAVE_ARPA_INET_H = 1,
        .HAVE_NETINET_IN_H = 1,
        .HAVE_NETINET_IP_H = 1,
        .HAVE_UNISTD_H = 1,
        .HAVE_DECL_BE64TOH = 0,
        .HAVE_DECL_BSWAP_64 = 0,
        .HAVE_MEMSET_S = 1,
    });
    return b.addConfigHeader(options, .{
        .HAVE_ARPA_INET_H = 1,
        .HAVE_NETINET_IN_H = 1,
        .HAVE_NETINET_IP_H = 1,
        .HAVE_UNISTD_H = 1,
        .HAVE_ENDIAN_H = 1,
        .HAVE_BYTESWAP_H = 1,
        .HAVE_DECL_BE64TOH = 1,
        .HAVE_DECL_BSWAP_64 = 1,
        .HAVE_EXPLICIT_BZERO = 1,
    });
}

fn versionHeader(b: *std.Build, dep: *std.Build.Dependency) *std.Build.Step.ConfigHeader {
    return b.addConfigHeader(.{
        .style = .{ .cmake = dep.path("lib/includes/ngtcp2/version.h.in") },
        .include_path = "ngtcp2/version.h",
    }, .{
        .PACKAGE_VERSION = version,
        .PACKAGE_VERSION_NUM = version_num,
    });
}

const lib_files = [_][]const u8{
    "ngtcp2_acktr.c",       "ngtcp2_addr.c",     "ngtcp2_balloc.c",
    "ngtcp2_bbr.c",         "ngtcp2_buf.c",      "ngtcp2_callbacks.c",
    "ngtcp2_cc.c",          "ngtcp2_cid.c",      "ngtcp2_conn.c",
    "ngtcp2_conn_info.c",   "ngtcp2_conv.c",     "ngtcp2_crypto.c",
    "ngtcp2_dcidtr.c",      "ngtcp2_err.c",      "ngtcp2_fmt.c",
    "ngtcp2_frame_chain.c", "ngtcp2_gaptr.c",    "ngtcp2_idtr.c",
    "ngtcp2_ksl.c",         "ngtcp2_log.c",      "ngtcp2_map.c",
    "ngtcp2_mem.c",         "ngtcp2_objalloc.c", "ngtcp2_opl.c",
    "ngtcp2_path.c",        "ngtcp2_pcg.c",      "ngtcp2_pkt.c",
    "ngtcp2_pmtud.c",       "ngtcp2_ppe.c",      "ngtcp2_pq.c",
    "ngtcp2_pv.c",          "ngtcp2_qlog.c",     "ngtcp2_range.c",
    "ngtcp2_ratelim.c",     "ngtcp2_ringbuf.c",  "ngtcp2_rob.c",
    "ngtcp2_rst.c",         "ngtcp2_rtb.c",      "ngtcp2_settings.c",
    "ngtcp2_str.c",         "ngtcp2_strm.c",     "ngtcp2_transport_params.c",
    "ngtcp2_unreachable.c", "ngtcp2_vec.c",      "ngtcp2_version.c",
    "ngtcp2_wf.c",
};
