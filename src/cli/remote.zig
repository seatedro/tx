//! Running txd in the remote account over ssh, and copying it there when
//! the host has none.
//!
//! tx looks for txd on the host in `~/.local/share/tx/DIR`, where DIR is
//! tx's version, then in PATH. With neither, the host reports its
//! `uname -s` and `uname -m`, and a txd for that platform goes into DIR.
//!
//! A release build tries these in order, and each txd must have the
//! SHA-256 the release lists for its platform:
//!
//! 1. The host downloads `BASE/tx/VERSION/txd-OS-ARCH` with curl or wget.
//!    BASE is `TX_DOWNLOAD_URL`, or `https://tarball.seated.ro`.
//! 2. tx sends the `txd-OS-ARCH` from its own directory through ssh's
//!    stdin.
//! 3. tx downloads it into `~/.cache/tx/VERSION/`, and sends that.
//!
//! A development build has no release to download. It sends the `txd`
//! next to it, if the host's platform is its own. Development builds share
//! a version, so DIR adds the first 12 hex digits of that txd's SHA-256,
//! and a rebuilt txd is sent again.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const build_options = @import("build_options");
const txd_builds = @import("txd_builds");
const paths = @import("paths.zig");

/// Where releases are downloaded from, unless `TX_DOWNLOAD_URL` is set.
const default_download_url = "https://tarball.seated.ro";

/// txd's default port.
pub const default_port = 8739;

pub const Source = struct {
    /// The ssh client.
    ssh: []const u8,
    /// `host` or `user@host`, as ssh takes it.
    destination: []const u8,
    /// A txd command given with `--server`. It runs as given, and is never
    /// copied.
    server_command: ?[]const u8,
    /// The port txd listens on.
    port: u16,
    /// The signal mask from before tx blocked the signals its threads
    /// handle. ssh starts with it, since a child inherits the mask.
    signal_mask: std.posix.sigset_t,
    environ: *const std.process.Environ.Map,
};

/// The status the remote command exits with when the host has no txd.
const need_status = 3;

/// The status the host's download exits with when it fails.
const download_failed_status = 4;

/// Runs `txd OPTIONS` in the remote account, with `--listen` for a port
/// other than the default, and copies txd there first if the host has
/// none. Its stderr, such as what `--install` did, goes to the user.
pub fn runTxd(gpa: Allocator, io: Io, source: Source, options: []const u8) !Result {
    var listen_buf: [32]u8 = undefined;
    const listen = if (source.port == default_port) "" else std.fmt.bufPrint(&listen_buf, " --listen \"[::]:{d}\"", .{source.port}) catch unreachable;

    if (source.server_command) |command| {
        const line = try std.fmt.allocPrint(gpa, "{s} {s}{s}", .{ command, options, listen });
        defer gpa.free(line);
        return runOverSsh(gpa, io, source, line, null);
    }

    var local: Local = try .find(gpa, io);
    defer local.deinit(gpa);

    // `sh -c` keeps the script the same whatever the login shell is. The
    // script has no single quotes.
    const find = try std.fmt.allocPrint(gpa,
        \\sh -c 'd="$HOME/.local/share/tx/{s}"; if [ -x "$d/txd" ]; then t="$d/txd"; elif command -v txd >/dev/null 2>&1; then t=txd; else echo "need $(uname -s) $(uname -m)"; exit {d}; fi; exec "$t" {s}{s}'
    , .{ local.dir, need_status, options, listen });
    defer gpa.free(find);
    const found = try runOverSsh(gpa, io, source, find, null);
    const need = needed(found) orelse return found;
    defer gpa.free(found.stdout);

    const platform = Platform.fromUname(need.system, need.machine) orelse {
        std.debug.print("tx: {s} has no txd, and tx has no build for {s} {s}\n", .{ source.destination, need.system, need.machine });
        return error.NoTxd;
    };
    // A release build's txd for the platform, which the host can download.
    const release: ?Release = if (releaseHash(platform)) |hash| .{
        .url = try std.fmt.allocPrint(gpa, "{s}/tx/{s}/txd-{s}-{s}", .{
            source.environ.get("TX_DOWNLOAD_URL") orelse default_download_url,
            build_options.version,
            platform.os,
            platform.arch,
        }),
        .sha256_hex = hash,
    } else null;
    defer if (release) |r| gpa.free(r.url);

    if (release) |r| {
        std.debug.print("tx: {s} has no txd; downloading {s} there\n", .{ source.destination, r.url });
        const download = try std.fmt.allocPrint(gpa,
            \\sh -c 'd="$HOME/.local/share/tx/{s}"; f="$d/txd.part"; mkdir -p "$d" || exit {d}; if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$f" "{s}"; else wget -qO "$f" "{s}"; fi || {{ rm -f "$f"; exit {d}; }}; s=$(sha256sum "$f" 2>/dev/null || shasum -a 256 "$f"); if [ "${{s%% *}}" != "{s}" ]; then rm -f "$f"; echo "the downloaded txd has the wrong SHA-256" >&2; exit {d}; fi; chmod 755 "$f" && mv "$f" "$d/txd" && exec "$d/txd" {s}{s}'
        , .{ local.dir, download_failed_status, r.url, r.url, download_failed_status, r.sha256_hex, download_failed_status, options, listen });
        defer gpa.free(download);
        const downloaded = try runOverSsh(gpa, io, source, download, null);
        if (downloaded.status != download_failed_status) return downloaded;
        gpa.free(downloaded.stdout);
        std.debug.print("tx: {s} can't download txd\n", .{source.destination});
    }

    // Next, the txd next to tx, then one tx downloads.
    const path = try local.forPlatform(gpa, io, platform) orelse found: {
        if (release) |r| if (try fetch(gpa, io, source.environ, r, platform)) |fetched| break :found fetched;
        std.debug.print("tx: {s} has no txd, and tx has no txd for {s}-{s} to copy there. Install txd on the host, or give its path with --server.\n", .{ source.destination, platform.os, platform.arch });
        return error.NoTxd;
    };
    defer gpa.free(path);

    std.debug.print("tx: copying {s} to {s}:~/.local/share/tx/{s}/txd\n", .{ path, source.destination, local.dir });
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    // A partly written txd never takes the place of a complete one.
    const copy = try std.fmt.allocPrint(gpa,
        \\sh -c 'd="$HOME/.local/share/tx/{s}"; mkdir -p "$d" && cat > "$d/txd.part" && chmod 755 "$d/txd.part" && mv "$d/txd.part" "$d/txd" && exec "$d/txd" {s}{s}'
    , .{ local.dir, options, listen });
    defer gpa.free(copy);
    const copied = try runOverSsh(gpa, io, source, copy, file);

    // 126 and 127 are the shell's statuses for a program that can't run.
    if (copied.status == 126 or copied.status == 127) {
        std.debug.print("tx: the copied txd doesn't run on {s}. A development build of txd uses this machine's C library; `zig build release` makes static builds.\n", .{source.destination});
    }
    return copied;
}

const Need = struct { system: []const u8, machine: []const u8 };

/// The host's platform, when the remote command reported it has no txd.
fn needed(result: Result) ?Need {
    if (result.status != need_status) return null;
    var fields = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
    if (!std.mem.eql(u8, fields.next() orelse return null, "need")) return null;
    const system = fields.next() orelse return null;
    const machine = fields.next() orelse return null;
    return .{ .system = system, .machine = machine };
}

pub const Result = struct {
    ok: bool,
    /// Null when the command was killed by a signal.
    status: ?u8,
    /// Owned.
    stdout: []u8,
};

/// Runs `command` in the remote account, with `stdin` as its input or
/// none. stdout is collected, and stderr goes to the user's terminal.
fn runOverSsh(gpa: Allocator, io: Io, source: Source, command: []const u8, stdin: ?Io.File) !Result {
    // ssh asks for passwords and its own host keys on the terminal, not on
    // stdin. A copy is compressed on the way.
    const argv: []const []const u8 = if (stdin != null)
        &.{ source.ssh, "-T", "-C", "-o", "ConnectTimeout=10", "--", source.destination, command }
    else
        &.{ source.ssh, "-T", "-o", "ConnectTimeout=10", "--", source.destination, command };
    var blocked: std.posix.sigset_t = undefined;
    _ = std.c.pthread_sigmask(std.posix.SIG.SETMASK, &source.signal_mask, &blocked);
    const spawned = std.process.spawn(io, .{
        .argv = argv,
        .stdin = if (stdin) |file| .{ .file = file } else .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    var ignored: std.posix.sigset_t = undefined;
    _ = std.c.pthread_sigmask(std.posix.SIG.SETMASK, &blocked, &ignored);
    var child = try spawned;

    var buf: [1024]u8 = undefined;
    var reader = child.stdout.?.readerStreaming(io, &buf);
    const stdout = reader.interface.allocRemaining(gpa, .limited(4096)) catch |err| {
        child.kill(io);
        return err;
    };
    errdefer gpa.free(stdout);

    const term = try child.wait(io);
    const status: ?u8 = switch (term) {
        .exited => |code| code,
        else => null,
    };
    return .{ .ok = status == 0, .status = status, .stdout = stdout };
}

/// A platform tx has txd builds for, named as `builtin.os.tag` and
/// `builtin.cpu.arch` name it.
pub const Platform = struct {
    os: []const u8,
    arch: []const u8,

    pub const local: Platform = .{ .os = @tagName(builtin.os.tag), .arch = @tagName(builtin.cpu.arch) };

    /// From `uname -s` and `uname -m`. Null for a system or CPU tx has no
    /// builds for.
    pub fn fromUname(system: []const u8, machine: []const u8) ?Platform {
        const os: []const u8 = if (eql(system, "Linux")) "linux" else if (eql(system, "Darwin")) "macos" else return null;
        const arch: []const u8 = if (eql(machine, "x86_64") or eql(machine, "amd64"))
            "x86_64"
        else if (eql(machine, "aarch64") or eql(machine, "arm64"))
            "aarch64"
        else
            return null;
        return .{ .os = os, .arch = arch };
    }

    pub fn eqlPlatform(a: Platform, b: Platform) bool {
        return eql(a.os, b.os) and eql(a.arch, b.arch);
    }

    fn eql(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
};

/// The txd builds next to this tx.
const Local = struct {
    /// The directory of tx's binary. Null if it can't be found.
    exe_dir: ?[]u8,
    /// The directory under `~/.local/share/tx` on a host.
    dir: []u8,

    fn find(gpa: Allocator, io: Io) !Local {
        const exe_dir: ?[]u8 = if (std.process.executablePathAlloc(io, gpa)) |exe| dir: {
            defer gpa.free(exe);
            break :dir try gpa.dupe(u8, std.fs.path.dirname(exe) orelse ".");
        } else |_| null;
        errdefer if (exe_dir) |d| gpa.free(d);

        if (txd_builds.builds.len > 0) return .{ .exe_dir = exe_dir, .dir = try gpa.dupe(u8, build_options.version) };

        // A development build's directory adds the local txd's hash to the
        // version.
        const sibling = if (exe_dir) |d| try std.fs.path.join(gpa, &.{ d, "txd" }) else null;
        defer if (sibling) |p| gpa.free(p);
        const hash = if (sibling) |p| sha256Hex(gpa, io, p) catch null else null;
        const dir = if (hash) |h|
            try std.fmt.allocPrint(gpa, "{s}-{s}", .{ build_options.version, h[0..12] })
        else
            try gpa.dupe(u8, build_options.version);
        return .{ .exe_dir = exe_dir, .dir = dir };
    }

    fn deinit(l: *Local, gpa: Allocator) void {
        if (l.exe_dir) |d| gpa.free(d);
        gpa.free(l.dir);
    }

    /// The path of a txd that runs on `platform`, owned, or null.
    fn forPlatform(l: *const Local, gpa: Allocator, io: Io, platform: Platform) !?[]u8 {
        const exe_dir = l.exe_dir orelse return null;

        if (txd_builds.builds.len == 0) {
            if (!platform.eqlPlatform(.local)) return null;
            const path = try std.fs.path.join(gpa, &.{ exe_dir, "txd" });
            Io.Dir.accessAbsolute(io, path, .{}) catch {
                gpa.free(path);
                return null;
            };
            return path;
        }

        // A release build only sends a file with the release's hash.
        const want = releaseHash(platform) orelse return null;
        var name_buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "txd-{s}-{s}", .{ platform.os, platform.arch });
        const candidates: []const []const u8 = if (platform.eqlPlatform(.local)) &.{ name, "txd" } else &.{name};
        for (candidates) |candidate| {
            const path = try std.fs.path.join(gpa, &.{ exe_dir, candidate });
            const got = sha256Hex(gpa, io, path) catch {
                gpa.free(path);
                continue;
            };
            if (std.mem.eql(u8, &got, want)) return path;
            std.debug.print("tx: skipping {s}, whose SHA-256 isn't the release's\n", .{path});
            gpa.free(path);
        }
        return null;
    }
};

/// The SHA-256 of the release's txd for `platform`. Null in a development
/// build, and for a platform the release has no build for.
fn releaseHash(platform: Platform) ?*const [64]u8 {
    for (txd_builds.builds) |b| {
        if (platform.eqlPlatform(.{ .os = b.os, .arch = b.arch })) return b.sha256_hex;
    }
    return null;
}

const Release = struct {
    url: []u8,
    sha256_hex: *const [64]u8,
};

/// Downloads the release's txd into `~/.cache/tx/VERSION/`, or finds it
/// there, and returns its path. Null when the download fails or has the
/// wrong SHA-256.
fn fetch(gpa: Allocator, io: Io, environ: *const std.process.Environ.Map, release: Release, platform: Platform) !?[]u8 {
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "{s}/txd-{s}-{s}", .{ build_options.version, platform.os, platform.arch });
    const path = try paths.cache(gpa, environ, name);
    errdefer gpa.free(path);

    if (sha256Hex(gpa, io, path)) |got| {
        if (std.mem.eql(u8, &got, release.sha256_hex)) return path;
    } else |_| {}

    std.debug.print("tx: downloading {s}\n", .{release.url});
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var body: Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    const result = client.fetch(.{ .location = .{ .url = release.url }, .response_writer = &body.writer }) catch |err| {
        std.debug.print("tx: downloading {s} failed: {t}\n", .{ release.url, err });
        gpa.free(path);
        return null;
    };
    if (result.status != .ok) {
        std.debug.print("tx: downloading {s} failed: HTTP {d}\n", .{ release.url, @backingInt(result.status) });
        gpa.free(path);
        return null;
    }

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(body.written(), &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), release.sha256_hex)) {
        std.debug.print("tx: {s} has the wrong SHA-256\n", .{release.url});
        gpa.free(path);
        return null;
    }

    // Written whole, then renamed, so the cache never holds part of one.
    const dir = Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    const part = try std.fmt.allocPrint(gpa, "{s}.part", .{path});
    defer gpa.free(part);
    try dir.writeFile(io, .{ .sub_path = part, .data = body.written() });
    try dir.rename(part, dir, path, io);
    return path;
}

fn sha256Hex(gpa: Allocator, io: Io, path: []const u8) ![64]u8 {
    const bytes = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(256 << 20));
    defer gpa.free(bytes);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

const testing = std.testing;

test "Platform.fromUname" {
    const linux = Platform.fromUname("Linux", "x86_64").?;
    try testing.expectEqualStrings("linux", linux.os);
    try testing.expectEqualStrings("x86_64", linux.arch);
    const mac = Platform.fromUname("Darwin", "arm64").?;
    try testing.expectEqualStrings("macos", mac.os);
    try testing.expectEqualStrings("aarch64", mac.arch);
    try testing.expect(Platform.fromUname("FreeBSD", "amd64") == null);
    try testing.expect(Platform.fromUname("Linux", "riscv64") == null);
}

test needed {
    var stdout = "need Linux aarch64\n".*;
    const need = needed(.{ .ok = false, .status = need_status, .stdout = &stdout }).?;
    try testing.expectEqualStrings("Linux", need.system);
    try testing.expectEqualStrings("aarch64", need.machine);
    try testing.expect(needed(.{ .ok = false, .status = 1, .stdout = &stdout }) == null);
}
