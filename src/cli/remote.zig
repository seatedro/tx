//! Running txd in the remote account over ssh, and putting it there when
//! the host has none. The commands that run on the host are in
//! `remote.sh`.
//!
//! tx looks for txd on the host in `~/.local/share/tx/DIR`, where DIR is
//! tx's version, then in PATH. With neither, the host reports its
//! `uname -s` and `uname -m`, and a txd for that platform goes into DIR.
//!
//! A release is a tarball per platform, `tx-VERSION-OS-ARCH.tar.gz`, with
//! tx and txd in a directory of the same name. A release build of tx tries
//! these in order, and each txd must have the SHA-256 tx carries for its
//! platform:
//!
//! 1. The host downloads `BASE/tx/VERSION/tx-VERSION-OS-ARCH.tar.gz` with
//!    curl or wget. BASE is `TX_DOWNLOAD_URL`, or
//!    `https://tarball.seated.ro`.
//! 2. tx sends the `txd` next to it through ssh's stdin, if the host's
//!    platform is its own.
//! 3. tx downloads the tarball, keeps its txd in `~/.cache/tx/VERSION/`,
//!    and sends that.
//!
//! Before it puts txd on a host that has never had one from tx, tx asks
//! (see `FirstInstall`). A host with a txd from another version of tx is
//! upgraded without asking.
//!
//! A development build has no release to download, and only does 2.
//! Development builds share a version, so DIR adds the first 12 hex digits
//! of that txd's SHA-256, and a rebuilt txd is sent again.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const build_options = @import("build_options");
const txd_builds = @import("txd_builds");
const paths = @import("paths.zig");

/// `remote.sh` without its comments and blank lines, since ssh sends the
/// script every time.
const script = stripComments(@embedFile("remote.sh"));

fn stripComments(comptime text: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: []const u8 = "";
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const code = std.mem.trimStart(u8, line, " ");
            if (code.len == 0 or code[0] == '#') continue;
            out = out ++ line ++ "\n";
        }
        const final = out[0..out.len].*;
        return &final;
    }
}

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
    first_install: FirstInstall = .ask,
};

/// What tx does on a host that has never had a txd from tx.
pub const FirstInstall = enum {
    /// Asks on the terminal, and fails with `error.Declined` on a no.
    ask,
    /// Installs txd without asking.
    yes,
    /// Fails with `error.NotInstalled`.
    no,
};

/// The statuses `remote.sh` exits with.
const need_status = 3;
const download_failed_status = 4;

/// Runs txd with `args` in the remote account, with `--listen` for a port
/// other than the default, and puts txd there first if the host has none.
/// Its stderr, such as what `--install` did, goes to the user.
pub fn runTxd(gpa: Allocator, io: Io, source: Source, args: []const []const u8) !Result {
    var listen_buf: [32]u8 = undefined;
    var txd_args: std.ArrayList([]const u8) = .empty;
    defer txd_args.deinit(gpa);
    try txd_args.appendSlice(gpa, args);
    if (source.port != default_port) {
        try txd_args.appendSlice(gpa, &.{ "--listen", std.fmt.bufPrint(&listen_buf, "[::]:{d}", .{source.port}) catch unreachable });
    }

    if (source.server_command) |command| {
        var line: Io.Writer.Allocating = .init(gpa);
        defer line.deinit();
        try line.writer.writeAll(command);
        for (txd_args.items) |arg| try writeWord(&line.writer, arg);
        return runOverSsh(gpa, io, source, line.written(), null);
    }

    var local: Local = try .find(gpa, io);
    defer local.deinit(gpa);

    const found = try runStep(gpa, io, source, .{ .step = "run", .dir = local.dir }, txd_args.items, null);
    const need = needed(found) orelse return found;
    defer gpa.free(found.stdout);
    if (need.first and source.first_install == .no) return error.NotInstalled;

    const platform = Platform.fromUname(need.system, need.machine) orelse {
        std.debug.print("tx: {s} has no txd, and tx has no build for {s} {s}\n", .{ source.destination, need.system, need.machine });
        return error.NoTxd;
    };

    // The user's yes, before tx puts anything on a host for the first time.
    if (need.first and source.first_install == .ask and !try askToInstall(io, source, platform)) return error.Declined;

    // A release build's tarball for the platform, which the host can
    // download.
    var release: ?Release = if (releaseHash(platform)) |hash| try .init(gpa, source.environ, platform, hash) else null;
    defer if (release) |*r| r.deinit(gpa);

    if (release) |r| {
        std.debug.print("tx: {s} has no txd; downloading {s} there\n", .{ source.destination, r.url });
        const downloaded = try runStep(gpa, io, source, .{
            .step = "download",
            .dir = local.dir,
            .url = r.url,
            .member = r.member,
            .sha256_hex = r.sha256_hex,
        }, txd_args.items, null);
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
    const copied = try runStep(gpa, io, source, .{ .step = "copy", .dir = local.dir }, txd_args.items, file);

    // 126 and 127 are the shell's statuses for a program that can't run.
    if (copied.status == 126 or copied.status == 127) {
        std.debug.print("tx: the copied txd doesn't run on {s}. A development build of txd uses this machine's C library; `zig build release` makes static builds.\n", .{source.destination});
    }
    return copied;
}

/// The arguments of a step of `remote.sh`, before txd's.
const Step = struct {
    step: []const u8,
    dir: []const u8,
    url: []const u8 = "",
    member: []const u8 = "",
    sha256_hex: []const u8 = "",
};

/// Runs `remote.sh` in the remote account.
fn runStep(gpa: Allocator, io: Io, source: Source, step: Step, txd_args: []const []const u8, stdin: ?Io.File) !Result {
    // `sh -c` runs the script the same way whatever the login shell is.
    var line: Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    try line.writer.writeAll("sh -c");
    for ([_][]const u8{ script, "tx", step.step, step.dir, step.url, step.member, step.sha256_hex }) |word| try writeWord(&line.writer, word);
    for (txd_args) |arg| try writeWord(&line.writer, arg);
    return runOverSsh(gpa, io, source, line.written(), stdin);
}

/// Writes a space and `word` in single quotes, which sh, bash and zsh take
/// literally. A single quote in `word` ends the quotes, adds an escaped
/// quote, and starts them again. fish reads backslashes in single quotes,
/// so a word with one reaches fish changed.
fn writeWord(w: *Io.Writer, word: []const u8) !void {
    try w.writeAll(" '");
    for (word) |byte| {
        if (byte == '\'') try w.writeAll("'\\''") else try w.writeByte(byte);
    }
    try w.writeByte('\'');
}

const Need = struct {
    system: []const u8,
    machine: []const u8,
    /// No other version of tx has put txd on the host.
    first: bool,
};

/// The host's platform, when the remote command reported it has no txd.
fn needed(result: Result) ?Need {
    if (result.status != need_status) return null;
    var fields = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
    if (!std.mem.eql(u8, fields.next() orelse return null, "need")) return null;
    const system = fields.next() orelse return null;
    const machine = fields.next() orelse return null;
    const previous = fields.next() orelse "first";
    return .{ .system = system, .machine = machine, .first = !std.mem.eql(u8, previous, "upgrade") };
}

/// Asks on the controlling terminal whether to install txd on a host that
/// has never had it. An empty answer is yes.
fn askToInstall(io: Io, source: Source, platform: Platform) !bool {
    // The uninstall command names the port as this one did.
    var port_buf: [16]u8 = undefined;
    const port_arg = if (source.port == default_port) "" else std.fmt.bufPrint(&port_buf, "-p {d} ", .{source.port}) catch unreachable;

    var buf: [1024]u8 = undefined;
    const question = try std.fmt.bufPrint(&buf,
        \\{s} has no txd. tx can install txd {s} for {s}-{s} in ~/.local/share/tx
        \\there, and keep it running as a user service. `tx {s}--uninstall {s}` removes it.
        \\Install txd?
    , .{ source.destination, build_options.version, platform.os, platform.arch, port_arg, source.destination });
    return try ask(io, question, true) orelse {
        std.debug.print("tx: {s} has no txd, and there's no terminal to ask on. With --yes, tx installs it without asking.\n", .{source.destination});
        return false;
    };
}

/// Asks `question` on the controlling terminal, and reads yes or no. An
/// empty answer is `default`, and the end of input is no. Null when there
/// is no terminal.
pub fn ask(io: Io, question: []const u8, default: bool) !?bool {
    const tty = Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write }) catch return null;
    defer tty.close(io);

    var write_buf: [1024]u8 = undefined;
    var tw = tty.writerStreaming(io, &write_buf);
    const w = &tw.interface;
    try w.print("{s} {s} ", .{ question, if (default) "[Y/n]" else "[y/N]" });

    var read_buf: [256]u8 = undefined;
    var tr = tty.readerStreaming(io, &read_buf);
    while (true) {
        try w.flush();
        const line = (tr.interface.takeDelimiter('\n') catch return false) orelse return false;
        const answer = std.mem.trim(u8, line, " \t\r");
        if (answer.len == 0) return default;
        if (std.ascii.eqlIgnoreCase(answer, "y") or std.ascii.eqlIgnoreCase(answer, "yes")) return true;
        if (std.ascii.eqlIgnoreCase(answer, "n") or std.ascii.eqlIgnoreCase(answer, "no")) return false;
        try w.writeAll("Please type 'y' or 'n': ");
    }
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

    /// The txd next to tx, owned, if it runs on `platform`. A release build
    /// only sends it with the release's SHA-256.
    fn forPlatform(l: *const Local, gpa: Allocator, io: Io, platform: Platform) !?[]u8 {
        const exe_dir = l.exe_dir orelse return null;
        if (!platform.eqlPlatform(.local)) return null;
        const path = try std.fs.path.join(gpa, &.{ exe_dir, "txd" });
        errdefer gpa.free(path);

        if (releaseHash(platform)) |want| {
            const got = sha256Hex(gpa, io, path) catch {
                gpa.free(path);
                return null;
            };
            if (!std.mem.eql(u8, &got, want)) {
                std.debug.print("tx: skipping {s}, whose SHA-256 isn't the release's\n", .{path});
                gpa.free(path);
                return null;
            }
        } else Io.Dir.accessAbsolute(io, path, .{}) catch {
            gpa.free(path);
            return null;
        };
        return path;
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

/// A release tarball, and the SHA-256 of the txd in it.
const Release = struct {
    url: []u8,
    /// The path of txd in the tarball.
    member: []u8,
    sha256_hex: *const [64]u8,

    fn init(gpa: Allocator, environ: *const std.process.Environ.Map, platform: Platform, sha256_hex: *const [64]u8) !Release {
        const name = try std.fmt.allocPrint(gpa, "tx-{s}-{s}-{s}", .{ build_options.version, platform.os, platform.arch });
        defer gpa.free(name);
        const url = try std.fmt.allocPrint(gpa, "{s}/tx/{s}/{s}.tar.gz", .{
            environ.get("TX_DOWNLOAD_URL") orelse default_download_url,
            build_options.version,
            name,
        });
        errdefer gpa.free(url);
        return .{ .url = url, .member = try std.fmt.allocPrint(gpa, "{s}/txd", .{name}), .sha256_hex = sha256_hex };
    }

    fn deinit(r: *Release, gpa: Allocator) void {
        gpa.free(r.url);
        gpa.free(r.member);
    }
};

/// The largest txd tx takes out of a tarball.
const max_txd_size = 256 << 20;

/// Downloads the release tarball and keeps its txd in
/// `~/.cache/tx/VERSION/`, or finds it there. Returns its path. Null when
/// the download fails or its txd has the wrong SHA-256.
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

    const txd = extract(gpa, body.written(), release.member) catch |err| {
        std.debug.print("tx: can't take {s} out of {s}: {t}\n", .{ release.member, release.url, err });
        gpa.free(path);
        return null;
    };
    defer gpa.free(txd);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(txd, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), release.sha256_hex)) {
        std.debug.print("tx: the txd in {s} has the wrong SHA-256\n", .{release.url});
        gpa.free(path);
        return null;
    }

    // Written whole, then renamed, so the cache never holds part of one.
    const dir = Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    const part = try std.fmt.allocPrint(gpa, "{s}.part", .{path});
    defer gpa.free(part);
    try dir.writeFile(io, .{ .sub_path = part, .data = txd });
    try dir.rename(part, dir, path, io);
    return path;
}

/// The file `member` in the gzip-compressed tarball `bytes`, owned.
fn extract(gpa: Allocator, bytes: []const u8, member: []const u8) ![]u8 {
    var input: Io.Reader = .fixed(bytes);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gzip: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var files: std.tar.Iterator = .init(&gzip.reader, .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });
    while (try files.next()) |file| {
        if (file.kind != .file or !std.mem.eql(u8, file.name, member)) continue;
        if (file.size > max_txd_size) return error.TooBig;
        var out: Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        try files.streamRemaining(file, &out.writer);
        return out.toOwnedSlice();
    }
    return error.NotInTarball;
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

test stripComments {
    try testing.expectEqualStrings("a=1\n    b\n", comptime stripComments("# doc\n\na=1\n    # more\n    b\n"));
    try testing.expect(std.mem.indexOf(u8, script, "case $step in") != null);
    try testing.expect(std.mem.indexOf(u8, script, "\n#") == null);
}

test writeWord {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeWord(&out.writer, "it's [::]:9000");
    try writeWord(&out.writer, "");
    try testing.expectEqualStrings(" 'it'\\''s [::]:9000' ''", out.written());
}

test needed {
    var first = "need Linux aarch64 first\n".*;
    const need = needed(.{ .ok = false, .status = need_status, .stdout = &first }).?;
    try testing.expectEqualStrings("Linux", need.system);
    try testing.expectEqualStrings("aarch64", need.machine);
    try testing.expect(need.first);
    try testing.expect(needed(.{ .ok = false, .status = 1, .stdout = &first }) == null);

    var upgrade = "need Darwin arm64 upgrade\n".*;
    try testing.expect(!needed(.{ .ok = false, .status = need_status, .stdout = &upgrade }).?.first);
}
