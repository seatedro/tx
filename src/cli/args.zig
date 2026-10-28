//! tx's command line: ssh's options, read as ssh reads them (see
//! `getopt`), so that a tool that runs ssh can run tx, and tx's own,
//! which are long.
//!
//! As in ssh, options come before the destination and after it. The first
//! word after the destination that isn't an option starts the command,
//! and `--` ends the options. The destination is `[user@]host` or
//! `ssh://[user@]host[:port]`.
//!
//! Of ssh's options, some take effect, some have nothing to do in tx and
//! are ignored, some ask for a feature tx lacks without changing what the
//! connection does and are ignored with a warning (`Args.ignored`), and
//! the rest are refused as unsupported.
const std = @import("std");
const Allocator = std.mem.Allocator;
const getopt = @import("getopt.zig");

/// ssh's option letters, from OpenSSH's ssh.c.
const ssh_spec = "1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:P:QR:S:TVw:W:XYy";

pub const Args = struct {
    host: []const u8 = "",
    /// `-l`, `user@`, or `User`. The first one given wins, as in ssh.
    user: ?[]const u8 = null,
    /// `-p`, `Port`, or the destination's. The first one given wins.
    port: ?u16 = null,
    /// The words after the destination, joined with spaces.
    command: ?[]const u8 = null,
    mode: Mode = .auto,
    /// `-t`, `-T` or `RequestTTY`. Null is the default: a terminal for a
    /// session, none for a command.
    tty: ?bool = null,
    /// `-4` or `-6`.
    family: ?Family = null,
    /// `-i` and `IdentityFile`, in order.
    key_files: []const []const u8 = &.{},
    /// `-e`. Null turns the escape character off.
    escape_char: ?u8 = '~',
    /// `-n`: stdin from /dev/null.
    no_stdin: bool = false,
    /// `-G`: print the configuration, and exit.
    print_config: bool = false,
    /// `--version` or `-V`.
    version: bool = false,
    /// `--yes`: no questions before installing or uninstalling.
    yes: bool = false,
    /// `--server`.
    server_command: ?[]const u8 = null,
    /// `--ssh`.
    ssh_path: []const u8 = "ssh",
    /// The letters of ssh's options ignored with a warning.
    ignored: []const u8 = "",
    /// The words of ssh's options, in order, for an ssh that tx runs with
    /// them. tx's own options are left out.
    ssh_options: []const []const u8 = &.{},
};

pub const Mode = union(enum) {
    /// Attaches the host's detached session, or starts one, or runs the
    /// command.
    auto,
    /// `--attach ID`.
    attach: u64,
    /// `--new`.
    new,
    /// `--list`.
    list,
    /// `--kill ID`.
    kill: u64,
    /// `--uninstall`.
    uninstall,
};

pub const Family = enum { ip4, ip6 };

pub const Result = union(enum) {
    ok: Args,
    /// What's wrong with the command line.
    usage: []const u8,
    /// An option tx doesn't support, as given, such as `-L`.
    unsupported: []const u8,
};

/// Parses `argv` without its first element. The result points into `argv`
/// and `arena`.
pub fn parse(arena: Allocator, argv: []const []const u8) Allocator.Error!Result {
    var s: State = .{ .arena = arena, .p = .{ .spec = ssh_spec, .args = argv } };
    s.run() catch |err| return switch (err) {
        error.Usage => .{ .usage = s.problem },
        error.Unsupported => .{ .unsupported = s.problem },
        error.OutOfMemory => |e| e,
    };
    return .{ .ok = s.args };
}

const State = struct {
    arena: Allocator,
    p: getopt.Parser,
    args: Args = .{},
    /// Modes and a command exclude each other.
    modes: usize = 0,
    key_files: std.ArrayList([]const u8) = .empty,
    ignored: std.ArrayList(u8) = .empty,
    ssh_options: std.ArrayList([]const u8) = .empty,
    /// The first word not yet put in `ssh_options` or passed over.
    recorded: usize = 0,
    /// For `error.Usage` and `error.Unsupported`.
    problem: []const u8 = "",

    const Error = error{ Usage, Unsupported, OutOfMemory };

    fn run(s: *State) Error!void {
        // Options, the destination, and unless `--` came, options again.
        try s.options();
        if (s.p.index < s.p.args.len) {
            try s.destination(s.p.args[s.p.index]);
            s.p.index += 1;
            s.recorded = s.p.index;
            if (!s.p.ended) try s.options();
        }

        const words = s.p.rest();
        if (words.len > 0) {
            s.args.command = try std.mem.join(s.arena, " ", words);
            s.modes += 1;
        }
        if (s.modes > 1) return s.usage("a command, --attach, --new, --list, --kill and --uninstall don't go together");
        if (s.args.host.len == 0 and !s.args.version) return s.usage("no host");

        s.args.key_files = s.key_files.items;
        s.args.ignored = s.ignored.items;
        s.args.ssh_options = s.ssh_options.items;
    }

    /// Reads options until the first operand, or `--`.
    fn options(s: *State) Error!void {
        while (true) {
            const item = (s.p.next() catch |err| return s.optionError(err)) orelse {
                // Passes over `--`.
                s.recorded = s.p.index;
                return;
            };
            switch (item) {
                .short => |o| {
                    try s.short(o);
                    try s.record(.ssh);
                },
                .long => |name| {
                    try s.long(name);
                    try s.record(.own);
                },
            }
        }
    }

    /// Puts the words of the option just read in `ssh_options`, if it is
    /// ssh's.
    fn record(s: *State, whose: enum { ssh, own }) Error!void {
        // A group of letters being read ends in the current word.
        const end = if (s.p.offset > 0) s.p.index + 1 else s.p.index;
        if (end <= s.recorded) return;
        if (whose == .ssh) try s.ssh_options.appendSlice(s.arena, s.p.args[s.recorded..end]);
        s.recorded = end;
    }

    fn optionError(s: *State, err: getopt.Error) Error {
        const problem = switch (err) {
            error.UnknownOption => std.fmt.allocPrint(s.arena, "unknown option -{c}", .{s.p.letter}),
            error.MissingValue => std.fmt.allocPrint(s.arena, "-{c} needs a value", .{s.p.letter}),
        } catch return error.OutOfMemory;
        return s.usage(problem);
    }

    /// One of ssh's options.
    fn short(s: *State, o: getopt.Item.Short) Error!void {
        switch (o.letter) {
            'p' => if (s.args.port == null) {
                s.args.port = parsePort(o.value.?) orelse return s.usage("invalid port");
            },
            'l' => if (s.args.user == null) {
                s.args.user = o.value.?;
            },
            't' => s.args.tty = true,
            'T' => s.args.tty = false,
            '4' => s.args.family = .ip4,
            '6' => s.args.family = .ip6,
            'i' => try s.key_files.append(s.arena, o.value.?),
            'e' => s.args.escape_char = escapeChar(o.value.?) catch return s.usage("invalid escape character"),
            'n' => s.args.no_stdin = true,
            'o' => try s.config(o.value.?),
            'G' => s.args.print_config = true,
            'V' => s.args.version = true,

            // Nothing to do in tx: protocol 2, no agent, X11 or GSSAPI
            // forwarding, compression, verbosity, syslog, forwarded ports
            // for others, ciphers and MACs (tx uses TLS), the local address,
            // a log file, and a Match tag.
            '2', 'a', 'x', 'k', 'K', 'C', 'q', 'v', 'y', 'g', 'c', 'm', 'b', 'B', 'E', 'P' => {},

            // Agent and X11 forwarding, ssh_config, and PKCS#11 keys. The
            // connection goes ahead without them.
            'A', 'X', 'Y', 'F', 'I' => try s.ignored.append(s.arena, o.letter),

            // Protocol 1, forwards, jump hosts, no command, going to the
            // background, connection sharing, tunnels, subsystems such as
            // sftp, and queries.
            '1', 'L', 'R', 'D', 'W', 'J', 'N', 'f', 'M', 'S', 'O', 'w', 's', 'Q' => {
                return s.unsupported(try std.fmt.allocPrint(s.arena, "-{c}", .{o.letter}));
            },
            else => unreachable,
        }
    }

    /// One of tx's own options.
    fn long(s: *State, name: []const u8) Error!void {
        const mode: ?Mode = if (eql(name, "attach"))
            .{ .attach = try s.sessionId() }
        else if (eql(name, "new"))
            .new
        else if (eql(name, "list"))
            .list
        else if (eql(name, "kill"))
            .{ .kill = try s.sessionId() }
        else if (eql(name, "uninstall"))
            .uninstall
        else
            null;
        if (mode) |m| {
            s.args.mode = m;
            s.modes += 1;
            return;
        }

        if (eql(name, "yes")) {
            s.args.yes = true;
        } else if (eql(name, "server")) {
            s.args.server_command = try s.value(name);
        } else if (eql(name, "ssh")) {
            s.args.ssh_path = try s.value(name);
        } else if (eql(name, "version")) {
            s.args.version = true;
        } else {
            return s.usage(try std.fmt.allocPrint(s.arena, "unknown option --{s}", .{name}));
        }
    }

    /// `-o`: `Key=value` or `Key value`, the key in any case, as ssh_config
    /// takes. Keys tx has no use for are ignored.
    fn config(s: *State, text: []const u8) Error!void {
        const trimmed = std.mem.trim(u8, text, " \t");
        const end = std.mem.indexOfAny(u8, trimmed, "= \t") orelse return s.usage("an -o option needs a value");
        const key = trimmed[0..end];
        var val = std.mem.trimStart(u8, trimmed[end..], " \t");
        if (std.mem.startsWith(u8, val, "=")) val = std.mem.trimStart(u8, val[1..], " \t");

        if (eqlIgnoreCase(key, "Port")) {
            if (s.args.port == null) s.args.port = parsePort(val) orelse return s.usage("invalid port");
        } else if (eqlIgnoreCase(key, "User")) {
            if (s.args.user == null) s.args.user = val;
        } else if (eqlIgnoreCase(key, "IdentityFile")) {
            try s.key_files.append(s.arena, val);
        } else if (eqlIgnoreCase(key, "RequestTTY")) {
            s.args.tty = requestTty(val) catch return s.usage("invalid RequestTTY");
        } else if (eqlIgnoreCase(key, "ForwardAgent")) {
            if (eqlIgnoreCase(val, "yes")) try s.ignored.append(s.arena, 'A');
        } else if (eqlIgnoreCase(key, "ForwardX11")) {
            if (eqlIgnoreCase(val, "yes")) try s.ignored.append(s.arena, 'X');
        } else if (oneOf(key, &.{ "LocalForward", "RemoteForward", "DynamicForward" })) {
            return s.unsupported(try std.fmt.allocPrint(s.arena, "-o {s}", .{key}));
        } else if (oneOf(key, &.{ "ProxyCommand", "ProxyJump", "RemoteCommand" })) {
            // `none` turns them off, as scp passes it.
            if (!eqlIgnoreCase(val, "none")) return s.unsupported(try std.fmt.allocPrint(s.arena, "-o {s}", .{key}));
        } else if (eqlIgnoreCase(key, "SessionType")) {
            if (!eqlIgnoreCase(val, "default")) return s.unsupported(try std.fmt.allocPrint(s.arena, "-o {s}", .{key}));
        }
    }

    /// `[user@]host`, or `ssh://[user@]host[:port]`.
    fn destination(s: *State, text: []const u8) Error!void {
        var rest = text;
        const uri = std.mem.startsWith(u8, rest, "ssh://");
        if (uri) rest = std.mem.trimEnd(u8, rest["ssh://".len..], "/");

        if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
            if (s.args.user == null) s.args.user = rest[0..at];
            rest = rest[at + 1 ..];
        }

        // A URI's port follows the host, which brackets hold if it has
        // colons.
        if (uri) {
            if (std.mem.startsWith(u8, rest, "[")) {
                const close = std.mem.indexOfScalar(u8, rest, ']') orelse return s.usage("invalid destination");
                const after = rest[close + 1 ..];
                rest = rest[1..close];
                if (after.len > 0) try s.uriPort(after);
            } else if (std.mem.indexOfScalar(u8, rest, ':')) |colon| {
                try s.uriPort(rest[colon..]);
                rest = rest[0..colon];
            }
        }
        if (rest.len == 0) return s.usage("no host");
        s.args.host = rest;
    }

    fn uriPort(s: *State, text: []const u8) Error!void {
        if (text[0] != ':') return s.usage("invalid destination");
        const port = parsePort(text[1..]) orelse return s.usage("invalid port");
        if (s.args.port == null) s.args.port = port;
    }

    fn sessionId(s: *State) Error!u64 {
        const text = try s.value("a session option");
        return std.fmt.parseInt(u64, text, 10) catch s.usage("invalid session id");
    }

    fn value(s: *State, name: []const u8) Error![]const u8 {
        return s.p.value() catch s.usage(try std.fmt.allocPrint(s.arena, "--{s} needs a value", .{name}));
    }

    fn usage(s: *State, problem: []const u8) error{Usage} {
        s.problem = problem;
        return error.Usage;
    }

    fn unsupported(s: *State, option: []const u8) error{Unsupported} {
        s.problem = option;
        return error.Unsupported;
    }
};

fn parsePort(text: []const u8) ?u16 {
    const port = std.fmt.parseInt(u16, text, 10) catch return null;
    return if (port == 0) null else port;
}

/// `-e`: a character, `^X` for a control character, or `none`.
fn escapeChar(text: []const u8) error{Invalid}!?u8 {
    if (std.mem.eql(u8, text, "none")) return null;
    if (text.len == 1) return text[0];
    if (text.len == 2 and text[0] == '^') return text[1] & 0x1f;
    return error.Invalid;
}

/// `RequestTTY`: `yes` and `force` ask for a terminal, `no` doesn't, and
/// `auto` leaves the default.
fn requestTty(text: []const u8) error{Invalid}!?bool {
    if (eqlIgnoreCase(text, "yes") or eqlIgnoreCase(text, "force")) return true;
    if (eqlIgnoreCase(text, "no")) return false;
    if (eqlIgnoreCase(text, "auto")) return null;
    return error.Invalid;
}

fn oneOf(key: []const u8, keys: []const []const u8) bool {
    for (keys) |k| if (eqlIgnoreCase(key, k)) return true;
    return false;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const eqlIgnoreCase = std.ascii.eqlIgnoreCase;

const testing = std.testing;

/// Parses `argv`, which must be valid.
fn expectArgs(arena: *std.heap.ArenaAllocator, argv: []const []const u8) !Args {
    return switch (try parse(arena.allocator(), argv)) {
        .ok => |a| a,
        .usage => |problem| {
            std.debug.print("usage: {s}\n", .{problem});
            return error.TestUnexpectedResult;
        },
        .unsupported => |option| {
            std.debug.print("unsupported: {s}\n", .{option});
            return error.TestUnexpectedResult;
        },
    };
}

test "git's ssh command" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "-o", "SendEnv=GIT_PROTOCOL", "-p", "2222", "-4", "tx-test@example.com", "git-upload-pack '/srv/repo.git'" });
    try testing.expectEqualStrings("example.com", a.host);
    try testing.expectEqualStrings("tx-test", a.user.?);
    try testing.expectEqual(2222, a.port.?);
    try testing.expectEqual(.ip4, a.family.?);
    try testing.expectEqualStrings("git-upload-pack '/srv/repo.git'", a.command.?);

    // git asks whether tx is OpenSSH with -G.
    try testing.expect((try expectArgs(&arena, &.{ "-G", "-p", "2222", "example.com" })).print_config);
}

test "rsync's shell command" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "-l", "ro", "example.com", "rsync", "--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", "/src/" });
    try testing.expectEqualStrings("ro", a.user.?);
    try testing.expectEqualStrings("rsync --server --sender -vlogDtpre.iLsfxCIvu . /src/", a.command.?);
}

test "options group, take joined values, and come after the destination too" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "-tp22", "example.com", "-l", "ro", "-e", "none", "ls", "-la" });
    try testing.expectEqual(true, a.tty.?);
    try testing.expectEqual(22, a.port.?);
    try testing.expectEqualStrings("ro", a.user.?);
    try testing.expectEqual(null, a.escape_char);
    try testing.expectEqualStrings("ls -la", a.command.?);

    // After `--`, everything after the destination is the command.
    const ended = try expectArgs(&arena, &.{ "--", "example.com", "-p", "22" });
    try testing.expectEqual(null, ended.port);
    try testing.expectEqualStrings("-p 22", ended.command.?);
}

test "ssh's options are kept for an ssh that tx runs, without tx's own" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "-tp", "22", "--yes", "-oUser=ro", "--", "example.com", "-v", "ls" });
    try testing.expectEqual(3, a.ssh_options.len);
    try testing.expectEqualStrings("-tp", a.ssh_options[0]);
    try testing.expectEqualStrings("22", a.ssh_options[1]);
    try testing.expectEqualStrings("-oUser=ro", a.ssh_options[2]);
    try testing.expectEqualStrings("-v ls", a.command.?);

    const after = try expectArgs(&arena, &.{ "example.com", "-i", "key", "--list" });
    try testing.expectEqual(2, after.ssh_options.len);
    try testing.expectEqualStrings("key", after.ssh_options[1]);
}

test "the first user and port given win" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "-l", "first", "-p", "1", "-o", "User=second", "-oPort 2", "third@example.com" });
    try testing.expectEqualStrings("first", a.user.?);
    try testing.expectEqual(1, a.port.?);
}

test "ssh URIs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{"ssh://ro@example.com:2222"});
    try testing.expectEqualStrings("example.com", a.host);
    try testing.expectEqualStrings("ro", a.user.?);
    try testing.expectEqual(2222, a.port.?);
    const v6 = try expectArgs(&arena, &.{"ssh://[2001:db8::1]:9/"});
    try testing.expectEqualStrings("2001:db8::1", v6.host);
    try testing.expectEqual(9, v6.port.?);
}

test "tx's own options, and modes that exclude each other" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "--attach", "3", "--yes", "--ssh", "/bin/ssh", "example.com" });
    try testing.expectEqual(3, a.mode.attach);
    try testing.expect(a.yes);
    try testing.expectEqualStrings("/bin/ssh", a.ssh_path);

    try testing.expectEqualStrings("a command, --attach, --new, --list, --kill and --uninstall don't go together", (try parse(arena.allocator(), &.{ "--list", "example.com", "ls" })).usage);
    try testing.expectEqualStrings("unknown option --frobnicate", (try parse(arena.allocator(), &.{ "--frobnicate", "example.com" })).usage);
    try testing.expectEqualStrings("unknown option -Z", (try parse(arena.allocator(), &.{ "-Z", "example.com" })).usage);
    try testing.expectEqualStrings("-p needs a value", (try parse(arena.allocator(), &.{"-p"})).usage);
    try testing.expectEqualStrings("no host", (try parse(arena.allocator(), &.{"-t"})).usage);
    try testing.expect((try expectArgs(&arena, &.{"--version"})).version);
}

test "scp's options: the ones tx has no use for pass, and sftp's subsystem doesn't" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try expectArgs(&arena, &.{ "-x", "-oForwardAgent=no", "-oPermitLocalCommand=no", "-oClearAllForwardings=yes", "-oRemoteCommand=none", "-oRequestTTY=no", "-oForwardX11=no", "-C", "example.com", "scp -f /etc/hosts" });
    try testing.expectEqual(false, a.tty.?);
    try testing.expectEqualStrings("", a.ignored);

    try testing.expectEqualStrings("-s", (try parse(arena.allocator(), &.{ "-s", "--", "example.com", "sftp" })).unsupported);
    try testing.expectEqualStrings("-L", (try parse(arena.allocator(), &.{ "-L", "8080:localhost:80", "example.com" })).unsupported);
    try testing.expectEqualStrings("-o LocalForward", (try parse(arena.allocator(), &.{ "-o", "LocalForward 8080 localhost:80", "example.com" })).unsupported);
    try testing.expectEqualStrings("AX", (try expectArgs(&arena, &.{ "-A", "-oForwardX11=yes", "example.com" })).ignored);
}
