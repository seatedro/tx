//! The settings tx connects to a destination with, from tx's config and
//! ssh's, read as ssh reads ssh_config(5).
//!
//! tx's config, `~/.config/tx/config`, is read first, then ssh's,
//! `~/.ssh/config` or the file given with `-F`. As in ssh, the first value
//! obtained for a keyword wins, and each `IdentityFile` adds to a list. The
//! keywords read are `Host`, `Match`, `Include`, `HostName`, `User`,
//! `IdentityFile`, `IdentitiesOnly`, `IdentityAgent` and `ProxyJump`, and
//! `Port` in tx's config only, since the port in ssh's is sshd's. Other
//! keywords are ignored.
//!
//! `Match` takes `all`, `host`, `originalhost`, `user`, `localuser`, `exec`,
//! `canonical` and `final`. tx reads the files once, so `final` matches and
//! `canonical` doesn't. A block under another criterion doesn't apply, with
//! a warning. `Match exec` runs its command with `/bin/sh -c`, and is the
//! only thing here that runs a program.
//!
//! `Include` paths take `~`, tokens, `${VAR}`, and `*` and `?`, with the
//! matches in byte order. A relative path is under `~/.ssh` in ssh's config,
//! and under tx's config directory in tx's. Includes nest 16 deep, as in
//! ssh. An Include in a block that doesn't apply isn't read.
//!
//! As ssh does, tx refuses a config file that others can write, or that
//! someone other than the user or root owns, except a file given with `-F`.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Environ = std.process.Environ;
const paths = @import("paths.zig");

pub const Options = struct {
    /// The destination's host, as given.
    host: []const u8,
    /// `-l`, `user@` or `-o User`, which wins over the config's.
    user: ?[]const u8 = null,
    /// `-p` or `-o Port`, which wins over the config's.
    port: ?u16 = null,
    /// The port when neither the command line nor the config gives one.
    default_port: u16,
    /// `-i` and `-o IdentityFile`, which come before the config's.
    identity_files: []const []const u8 = &.{},
    /// The key files when neither the command line nor the config names
    /// one.
    default_identity_files: []const []const u8 = &.{},
    /// `-F`: ssh's config file, which must exist, or `none`. Null is
    /// `~/.ssh/config`.
    ssh_config: ?[]const u8 = null,
    environ: *const Environ.Map,
    /// The signal mask a `Match exec` command starts with. Null leaves the
    /// current one.
    signal_mask: ?std.posix.sigset_t = null,
};

pub const Resolved = struct {
    /// `HostName`, or the host as given. Lowercase, unless it's an address.
    hostname: []const u8,
    /// Null when neither the command line nor the config gives one, for the
    /// local user's name.
    user: ?[]const u8,
    port: u16,
    /// The command line's, then the config's, or else the defaults, with
    /// `~`, tokens and variables expanded. `IdentityFile none` adds none.
    identity_files: []const []const u8,
    /// Only the identity files' keys are used, and the agent's keys that
    /// match them.
    identities_only: bool,
    /// Null when the config doesn't set it, and `SSH_AUTH_SOCK` applies.
    identity_agent: ?IdentityAgent,
    /// Null for none.
    proxy_jump: ?[]const u8,
    /// Lines for stderr.
    warnings: []const []const u8,
};

pub const IdentityAgent = union(enum) {
    /// `none`, or a variable that isn't set or is empty.
    none,
    /// The agent's socket.
    path: []const u8,
};

pub const Result = union(enum) {
    ok: Resolved,
    /// What's wrong, after the file and line.
    bad: []const u8,
};

pub const Error = Allocator.Error || Io.Cancelable;

/// Reads tx's config and ssh's for `options.host`. The result points into
/// `options` and `arena`.
pub fn resolve(arena: Allocator, io: Io, options: Options) Error!Result {
    var p: Parser = .{
        .arena = arena,
        .io = io,
        .options = options,
        .local = try .init(arena, options.environ),
    };
    const resolved = p.run() catch |err| return switch (err) {
        error.BadConfig => .{ .bad = p.problem },
        error.OutOfMemory, error.Canceled => |e| e,
    };
    return .{ .ok = resolved };
}

/// How deep Includes nest, as in ssh.
const max_include_depth = 16;

/// The largest config file tx reads.
const max_file_size = 1 << 20;

/// The tokens of `HostName`, besides `%%`.
const hostname_tokens = "h";
/// The tokens of `IdentityFile`, `IdentityAgent`, `Include` and
/// `Match exec`, besides `%%`.
const path_tokens = "dhilLnpru";
/// The tokens of `User`, which can't refer to itself.
const user_tokens = "dhilLnpu";

/// Whose config a file is part of.
const Kind = enum { tx, ssh };

/// Where a value came from, for messages.
const Origin = struct {
    /// A file's path, or a description such as `-i`.
    name: []const u8,
    /// The line, in a file.
    line: ?usize = null,

    pub fn format(o: Origin, w: *Io.Writer) Io.Writer.Error!void {
        if (o.line) |n| return w.print("{s} line {d}", .{ o.name, n });
        try w.writeAll(o.name);
    }
};

/// A value whose tokens are expanded once all the files are read.
const Setting = struct {
    value: []const u8,
    origin: Origin,
};

/// What `%` tokens stand for, besides what `Local` holds.
const Context = struct {
    /// `%h`.
    host: []const u8,
    /// `%r`.
    user: []const u8 = "",
};

/// The local side, for tokens and `~`.
const Local = struct {
    user: ?[]const u8,
    /// `HOME`, or the password database's.
    home: ?[]const u8,
    uid: []const u8,
    /// With its domain, as `%l` gives it.
    hostname: ?[]const u8,

    fn init(arena: Allocator, environ: *const Environ.Map) Allocator.Error!Local {
        // The password database's strings are overwritten by the next
        // lookup, so they're copied.
        var local: Local = .{
            .user = null,
            .home = environ.get("HOME"),
            .uid = try std.fmt.allocPrint(arena, "{d}", .{std.c.getuid()}),
            .hostname = null,
        };
        if (paths.userName(environ)) |name| local.user = try arena.dupe(u8, name);
        if (local.home == null) {
            if (std.c.getpwuid(std.c.getuid())) |pw| {
                if (pw.dir) |dir| local.home = try arena.dupe(u8, std.mem.span(dir));
            }
        }

        var name_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        if (std.posix.gethostname(&name_buf)) |name| {
            local.hostname = try arena.dupe(u8, name);
        } else |_| {}
        return local;
    }
};

const Parser = struct {
    arena: Allocator,
    io: Io,
    options: Options,
    local: Local,

    // The values found so far. The first one found wins.
    /// `HostName`, with its tokens expanded.
    hostname: ?[]const u8 = null,
    user: ?Setting = null,
    port: ?u16 = null,
    identity_files: std.ArrayList(Setting) = .empty,
    identities_only: ?bool = null,
    identity_agent: ?Setting = null,
    proxy_jump: ?[]const u8 = null,

    warnings: std.ArrayList([]const u8) = .empty,
    /// The Match criteria warned about.
    warned: std.ArrayList([]const u8) = .empty,
    /// For `error.BadConfig`.
    problem: []const u8 = "",

    const ParseError = Error || error{BadConfig};

    fn run(p: *Parser) ParseError!Resolved {
        for (p.options.identity_files) |file| {
            try p.identity_files.append(p.arena, .{ .value = file, .origin = .{ .name = "-i" } });
        }

        // tx's config, then ssh's.
        if (try p.txConfigPath()) |path| try p.readFile(path, .tx, .{});
        if (p.options.ssh_config) |path| {
            if (!eqlIgnoreCase(path, "none")) try p.readFile(path, .ssh, .{ .required = true, .check_owner = false });
        } else if (p.local.home) |dir| {
            try p.readFile(try std.fs.path.join(p.arena, &.{ dir, ".ssh", "config" }), .ssh, .{});
        }

        return p.finish();
    }

    fn txConfigPath(p: *Parser) Allocator.Error!?[]const u8 {
        return paths.config(p.arena, p.options.environ, "config") catch |err| switch (err) {
            error.NoHome => null,
            error.OutOfMemory => |e| e,
        };
    }

    /// The values once every file is read, with their tokens expanded.
    fn finish(p: *Parser) ParseError!Resolved {
        const hostname = try lowerHost(p.arena, p.hostname orelse p.options.host);

        // The command line's user, or the config's, whose tokens are
        // expanded.
        var user = p.options.user;
        if (user == null) {
            if (p.user) |setting| user = try p.expand(setting.origin, setting.value, user_tokens, .{ .host = hostname }, true);
        }
        const context: Context = .{ .host = hostname, .user = user orelse p.local.user orelse "" };

        var identity_files: std.ArrayList([]const u8) = .empty;
        for (try p.identityFileSettings()) |setting| {
            if (eqlIgnoreCase(setting.value, "none")) continue;
            try identity_files.append(p.arena, try p.expandPath(setting.origin, setting.value, context));
        }

        var identity_agent: ?IdentityAgent = null;
        if (p.identity_agent) |setting| identity_agent = try p.agent(setting, context);

        var proxy_jump = p.proxy_jump;
        if (proxy_jump) |jump| if (eqlIgnoreCase(jump, "none")) {
            proxy_jump = null;
        };

        return .{
            .hostname = hostname,
            .user = user,
            .port = p.currentPort(),
            .identity_files = identity_files.items,
            .identities_only = p.identities_only orelse false,
            .identity_agent = identity_agent,
            .proxy_jump = proxy_jump,
            .warnings = p.warnings.items,
        };
    }

    /// The identity files given, or else the defaults.
    fn identityFileSettings(p: *Parser) Allocator.Error![]const Setting {
        if (p.identity_files.items.len > 0) return p.identity_files.items;
        const defaults = try p.arena.alloc(Setting, p.options.default_identity_files.len);
        for (defaults, p.options.default_identity_files) |*setting, file| {
            setting.* = .{ .value = file, .origin = .{ .name = "the default key files" } };
        }
        return defaults;
    }

    /// `IdentityAgent`: `none`, `SSH_AUTH_SOCK` for that variable, `$VAR`
    /// for another, or a path.
    fn agent(p: *Parser, setting: Setting, context: Context) ParseError!IdentityAgent {
        const value = setting.value;
        if (std.mem.eql(u8, value, "none")) return .none;
        if (std.mem.eql(u8, value, "SSH_AUTH_SOCK")) return p.agentVariable("SSH_AUTH_SOCK");
        if (std.mem.startsWith(u8, value, "$") and !std.mem.startsWith(u8, value, "${")) {
            const name = value[1..];
            if (!validVariableName(name)) return p.fail(setting.origin, "invalid variable name in IdentityAgent {s}", .{value});
            return p.agentVariable(name);
        }

        const path = try p.expandPath(setting.origin, value, context);
        return if (path.len == 0) .none else .{ .path = path };
    }

    /// An agent named by a variable. Without the variable, or with it
    /// empty, there's none, as in ssh.
    fn agentVariable(p: *Parser, name: []const u8) IdentityAgent {
        const path = p.options.environ.get(name) orelse return .none;
        return if (path.len == 0) .none else .{ .path = path };
    }

    const ReadOptions = struct {
        /// A missing file is an error.
        required: bool = false,
        /// Refuses a file that others could have written.
        check_owner: bool = true,
        /// How many Includes led to the file.
        depth: usize = 0,
    };

    /// Reads a config file, if it exists, from its first line to its last.
    fn readFile(p: *Parser, path: []const u8, kind: Kind, how: ReadOptions) ParseError!void {
        const origin: Origin = .{ .name = path };
        const file = Io.Dir.cwd().openFile(p.io, path, .{ .allow_directory = false }) catch |err| switch (err) {
            error.FileNotFound => if (how.required) return p.fail(origin, "no such file", .{}) else return,
            // An Include's pattern can match a directory.
            error.IsDir => return,
            error.Canceled => |e| return e,
            else => return p.fail(origin, "can't open it: {t}", .{err}),
        };
        defer file.close(p.io);

        if (how.check_owner and !(safelyOwned(file) catch |err| return p.fail(origin, "can't check its owner: {t}", .{err}))) {
            return p.fail(origin, "bad owner or permissions: it must be yours or root's, and only its owner may write it", .{});
        }

        var reader = file.reader(p.io, &.{});
        const text = reader.interface.allocRemaining(p.arena, .limited(max_file_size)) catch |err| switch (err) {
            error.StreamTooLong => return p.fail(origin, "too big", .{}),
            error.OutOfMemory => |e| return e,
            error.ReadFailed => switch (reader.err.?) {
                error.Canceled => |e| return e,
                else => |e| return p.fail(origin, "can't read it: {t}", .{e}),
            },
        };

        // Lines before the first Host or Match apply, as the block of the
        // Include that read the file does.
        var active = true;
        var lines = std.mem.splitScalar(u8, text, '\n');
        var number: usize = 0;
        while (lines.next()) |line| {
            number += 1;
            const at: Origin = .{ .name = path, .line = number };
            try p.readLine(at, kind, how.depth, line, &active);
        }
    }

    /// One line. `active` is whether the block it's in applies.
    fn readLine(p: *Parser, at: Origin, kind: Kind, depth: usize, text: []const u8, active: *bool) ParseError!void {
        const line = (splitLine(p.arena, text) catch |err| switch (err) {
            error.NoArgument => return p.fail(at, "no argument after the keyword", .{}),
            error.InvalidQuotes => return p.fail(at, "invalid quotes", .{}),
            error.OutOfMemory => |e| return e,
        }) orelse return;
        const keyword = line.keyword;
        const args = line.args;

        if (eqlIgnoreCase(keyword, "Host")) {
            active.* = try p.hostLine(at, args);
        } else if (eqlIgnoreCase(keyword, "Match")) {
            active.* = try p.matchLine(at, args);
        } else if (eqlIgnoreCase(keyword, "Include")) {
            if (active.*) try p.include(at, kind, depth, args);
        } else if (eqlIgnoreCase(keyword, "HostName")) {
            // `%h` is the host as given.
            const value = try p.single(at, keyword, args);
            if (active.* and p.hostname == null) {
                p.hostname = try p.expand(at, value, hostname_tokens, .{ .host = p.options.host }, false);
            }
        } else if (eqlIgnoreCase(keyword, "User")) {
            const value = try p.single(at, keyword, args);
            if (active.* and p.user == null) p.user = .{ .value = value, .origin = at };
        } else if (eqlIgnoreCase(keyword, "Port")) {
            // ssh's port is sshd's.
            if (kind == .ssh) return;
            const value = try p.single(at, keyword, args);
            const port = std.fmt.parseInt(u16, value, 10) catch 0;
            if (port == 0) return p.fail(at, "bad port {s}", .{value});
            if (active.* and p.port == null) p.port = port;
        } else if (eqlIgnoreCase(keyword, "IdentityFile")) {
            const value = try p.single(at, keyword, args);
            if (active.*) try p.identity_files.append(p.arena, .{ .value = value, .origin = at });
        } else if (eqlIgnoreCase(keyword, "IdentitiesOnly")) {
            const value = try p.single(at, keyword, args);
            const yes = parseFlag(value) orelse return p.fail(at, "IdentitiesOnly takes yes or no, not {s}", .{value});
            if (active.* and p.identities_only == null) p.identities_only = yes;
        } else if (eqlIgnoreCase(keyword, "IdentityAgent")) {
            const value = try p.single(at, keyword, args);
            if (active.* and p.identity_agent == null) p.identity_agent = .{ .value = value, .origin = at };
        } else if (eqlIgnoreCase(keyword, "ProxyJump")) {
            const value = try p.single(at, keyword, args);
            if (active.* and p.proxy_jump == null) p.proxy_jump = value;
        }
    }

    /// The argument of a keyword that takes one.
    fn single(p: *Parser, at: Origin, keyword: []const u8, args: []const []const u8) ParseError![]const u8 {
        if (args.len == 0 or args[0].len == 0) return p.fail(at, "{s} needs an argument", .{keyword});
        if (args.len > 1) return p.fail(at, "{s} takes one argument", .{keyword});
        return args[0];
    }

    /// Whether a Host line's patterns match the host as given: one must,
    /// and no negated one may.
    fn hostLine(p: *Parser, at: Origin, patterns: []const []const u8) ParseError!bool {
        var matched = false;
        for (patterns) |pattern| {
            if (pattern.len == 0) return p.fail(at, "empty Host pattern", .{});
            if (pattern[0] == '!') {
                if (matchPattern(p.options.host, pattern[1..], .sensitive)) return false;
            } else if (matchPattern(p.options.host, pattern, .sensitive)) {
                matched = true;
            }
        }
        return matched;
    }

    /// Whether every criterion of a Match line holds.
    fn matchLine(p: *Parser, at: Origin, words: []const []const u8) ParseError!bool {
        var result = true;
        var criteria: usize = 0;
        var i: usize = 0;
        while (i < words.len) {
            var name = words[i];
            i += 1;
            const negate = std.mem.startsWith(u8, name, "!");
            if (negate) name = name[1..];

            // `all` stands alone, or after `canonical` or `final`.
            if (eqlIgnoreCase(name, "all")) {
                if (criteria > 1 or i < words.len) return p.fail(at, "Match all can't be combined with other criteria", .{});
                return result and !negate;
            }
            criteria += 1;

            // tx's one pass over the files is the final one, and isn't
            // after canonicalization.
            if (eqlIgnoreCase(name, "final") or eqlIgnoreCase(name, "canonical")) {
                const holds = eqlIgnoreCase(name, "final");
                if (holds == negate) result = false;
                continue;
            }

            // The other criteria take an argument: `NAME ARG` or `NAME=ARG`.
            var arg: []const u8 = undefined;
            if (std.mem.indexOfScalar(u8, name, '=')) |eq| {
                arg = name[eq + 1 ..];
                name = name[0..eq];
            } else if (i < words.len) {
                arg = words[i];
                i += 1;
            } else {
                return p.fail(at, "Match {s} needs an argument", .{name});
            }
            const may_be_empty = eqlIgnoreCase(name, "tagged") or eqlIgnoreCase(name, "command");
            if ((arg.len == 0 and !may_be_empty) or std.mem.startsWith(u8, arg, "#")) {
                return p.fail(at, "Match {s} needs an argument", .{name});
            }

            const holds = if (eqlIgnoreCase(name, "host"))
                matchPatternList(p.currentHost(), arg, .insensitive)
            else if (eqlIgnoreCase(name, "originalhost"))
                matchPatternList(p.options.host, arg, .insensitive)
            else if (eqlIgnoreCase(name, "user"))
                matchPatternList(p.currentUser(), arg, .sensitive)
            else if (eqlIgnoreCase(name, "localuser"))
                matchPatternList(p.local.user orelse "", arg, .sensitive)
            else if (eqlIgnoreCase(name, "exec")) holds: {
                // As in ssh, the command doesn't run once another
                // criterion has failed.
                const command = try p.expand(at, arg, path_tokens, p.parseContext(), false);
                if (!result) continue;
                break :holds try p.exec(at, command);
            } else {
                try p.warnOnce(at, name);
                result = false;
                continue;
            };
            if (holds == negate) result = false;
        }

        if (criteria == 0) return p.fail(at, "Match needs a criterion", .{});
        return result;
    }

    /// Notes a Match criterion tx doesn't support, the first time it
    /// appears.
    fn warnOnce(p: *Parser, at: Origin, name: []const u8) Allocator.Error!void {
        for (p.warned.items) |warned| if (eqlIgnoreCase(warned, name)) return;
        try p.warned.append(p.arena, name);
        try p.warnings.append(p.arena, try std.fmt.allocPrint(p.arena, "{f}: Match {s} isn't supported; its block doesn't apply", .{ at, name }));
    }

    /// Runs a `Match exec` command as ssh does: `/bin/sh -c`, with stdin and
    /// stdout on /dev/null. It holds when the command exits with 0.
    fn exec(p: *Parser, at: Origin, command: []const u8) ParseError!bool {
        // A child inherits the signal mask.
        var blocked: std.posix.sigset_t = undefined;
        if (p.options.signal_mask) |*mask| _ = std.c.pthread_sigmask(std.posix.SIG.SETMASK, mask, &blocked);
        const spawned = std.process.spawn(p.io, .{
            .argv = &.{ "/bin/sh", "-c", command },
            .environ_map = p.options.environ,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .inherit,
        });
        if (p.options.signal_mask != null) {
            var ignored: std.posix.sigset_t = undefined;
            _ = std.c.pthread_sigmask(std.posix.SIG.SETMASK, &blocked, &ignored);
        }

        var child = spawned catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => return p.fail(at, "can't run /bin/sh for Match exec: {t}", .{err}),
        };
        const term = child.wait(p.io) catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => return p.fail(at, "Match exec failed: {t}", .{err}),
        };
        return switch (term) {
            .exited => |code| code == 0,
            else => p.fail(at, "Match exec {s}: {f}", .{ command, term }),
        };
    }

    /// Reads the files an Include line names, in order.
    fn include(p: *Parser, at: Origin, kind: Kind, depth: usize, patterns: []const []const u8) ParseError!void {
        for (patterns) |pattern| {
            if (pattern.len == 0) return p.fail(at, "empty Include path", .{});
            const expanded = try p.expand(at, pattern, path_tokens, p.parseContext(), true);
            const path = try p.anchor(at, expanded, kind);
            for (try p.glob(at, path)) |file| {
                if (depth == max_include_depth) return p.fail(at, "Includes nest more than {d} deep", .{max_include_depth});
                try p.readFile(file, kind, .{ .depth = depth + 1 });
            }
        }
    }

    /// An Include path, with `~` expanded, and a relative one under
    /// `~/.ssh` or tx's config directory.
    fn anchor(p: *Parser, at: Origin, path: []const u8, kind: Kind) ParseError![]const u8 {
        const expanded = try p.expandTilde(at, path);
        if (std.fs.path.isAbsolute(expanded)) return expanded;

        const dir = switch (kind) {
            .ssh => try std.fs.path.join(p.arena, &.{ try p.home(at), ".ssh" }),
            .tx => std.fs.path.dirname((try p.txConfigPath()) orelse return p.fail(at, "can't tell tx's config directory", .{})).?,
        };
        return std.fs.path.join(p.arena, &.{ dir, expanded });
    }

    /// The files that match `path`, whose components may hold `*` and `?`,
    /// in byte order. A path without them is returned as it is.
    fn glob(p: *Parser, at: Origin, path: []const u8) ParseError![]const []const u8 {
        var found: std.ArrayList([]const u8) = .empty;
        if (!hasWildcard(path)) {
            try found.append(p.arena, path);
            return found.items;
        }

        const start = if (std.fs.path.isAbsolute(path)) "/" else ".";
        try p.globFrom(at, &found, start, path);
        std.mem.sort([]const u8, found.items, {}, lessThan);
        return found.items;
    }

    /// Adds to `found` the paths under `dir` that match `rest`.
    fn globFrom(p: *Parser, at: Origin, found: *std.ArrayList([]const u8), dir: []const u8, rest: []const u8) ParseError!void {
        const trimmed = std.mem.trimStart(u8, rest, "/");
        if (trimmed.len == 0) return found.append(p.arena, dir);
        const end = std.mem.indexOfScalar(u8, trimmed, '/') orelse trimmed.len;
        const component = trimmed[0..end];
        const after = trimmed[end..];

        if (!hasWildcard(component)) {
            return p.globFrom(at, found, try std.fs.path.join(p.arena, &.{ dir, component }), after);
        }

        // A directory that can't be listed holds no matches.
        var d = Io.Dir.cwd().openDir(p.io, dir, .{ .iterate = true }) catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => return,
        };
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => return p.fail(at, "can't list {s}: {t}", .{ dir, err }),
        }) |entry| {
            if (!matchComponent(entry.name, component)) continue;
            try p.globFrom(at, found, try std.fs.path.join(p.arena, &.{ dir, entry.name }), after);
        }
    }

    /// A path's tokens and variables, then `~` or `~USER` at its start.
    fn expandPath(p: *Parser, at: Origin, path: []const u8, context: Context) ParseError![]const u8 {
        return p.expandTilde(at, try p.expand(at, path, path_tokens, context, true));
    }

    fn expandTilde(p: *Parser, at: Origin, path: []const u8) ParseError![]const u8 {
        if (!std.mem.startsWith(u8, path, "~")) return path;
        const end = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
        const name = path[1..end];
        const rest = path[end..];

        const dir = if (name.len == 0) try p.home(at) else dir: {
            const name_z = try p.arena.dupeSentinel(u8, name, 0);
            const pw = std.c.getpwnam(name_z) orelse return p.fail(at, "no user {s}, for {s}", .{ name, path });
            const dir = pw.dir orelse return p.fail(at, "{s} has no home directory, for {s}", .{ name, path });
            break :dir try p.arena.dupe(u8, std.mem.span(dir));
        };
        return std.mem.concat(p.arena, u8, &.{ std.mem.trimEnd(u8, dir, "/"), rest });
    }

    fn home(p: *Parser, at: Origin) ParseError![]const u8 {
        return p.local.home orelse p.fail(at, "can't tell the home directory", .{});
    }

    /// Expands `%` tokens, and `${VAR}` with `variables`. `letters` are the
    /// tokens allowed besides `%%`.
    fn expand(p: *Parser, at: Origin, text: []const u8, letters: []const u8, context: Context, variables: bool) ParseError![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < text.len) {
            if (variables and std.mem.startsWith(u8, text[i..], "${")) {
                const close = std.mem.indexOfScalarPos(u8, text, i, '}') orelse return p.fail(at, "no closing }} in {s}", .{text});
                const name = text[i + 2 .. close];
                if (name.len == 0) return p.fail(at, "empty variable name in {s}", .{text});
                const value = p.options.environ.get(name) orelse return p.fail(at, "{s} isn't set, for {s}", .{ name, text });
                try out.appendSlice(p.arena, value);
                i = close + 1;
                continue;
            }
            if (text[i] != '%') {
                try out.append(p.arena, text[i]);
                i += 1;
                continue;
            }

            // `%` and a letter.
            if (i + 1 == text.len) return p.fail(at, "a lone % ends {s}", .{text});
            const letter = text[i + 1];
            i += 2;
            if (letter == '%') {
                try out.append(p.arena, '%');
            } else if (std.mem.indexOfScalar(u8, letters, letter) != null) {
                try out.appendSlice(p.arena, try p.token(at, letter, context));
            } else {
                return p.fail(at, "unknown token %{c} in {s}", .{ letter, text });
            }
        }
        return out.items;
    }

    fn token(p: *Parser, at: Origin, letter: u8, context: Context) ParseError![]const u8 {
        switch (letter) {
            'h' => return context.host,
            'r' => return context.user,
            'n' => return p.options.host,
            'p' => return std.fmt.allocPrint(p.arena, "{d}", .{p.currentPort()}),
            'd' => return p.home(at),
            'i' => return p.local.uid,
            'u' => return p.local.user orelse p.fail(at, "can't tell the local user name, for %u", .{}),
            'l', 'L' => {
                const name = p.local.hostname orelse return p.fail(at, "can't tell the local host name, for %{c}", .{letter});
                if (letter == 'l') return name;

                // Up to the first dot.
                return name[0 .. std.mem.indexOfScalar(u8, name, '.') orelse name.len];
            },
            else => unreachable,
        }
    }

    /// `%h` and `%r` while the files are read, as ssh has them then.
    fn parseContext(p: *Parser) Context {
        return .{ .host = p.currentHost(), .user = p.currentUser() };
    }

    fn currentHost(p: *Parser) []const u8 {
        return p.hostname orelse p.options.host;
    }

    fn currentUser(p: *Parser) []const u8 {
        if (p.options.user) |user| return user;
        if (p.user) |setting| return setting.value;
        return p.local.user orelse "";
    }

    fn currentPort(p: *Parser) u16 {
        return p.options.port orelse p.port orelse p.options.default_port;
    }

    fn fail(p: *Parser, at: Origin, comptime format: []const u8, args: anytype) ParseError {
        p.problem = std.fmt.allocPrint(p.arena, "{f}: " ++ format, .{at} ++ args) catch |err| return err;
        return error.BadConfig;
    }
};

const Line = struct {
    keyword: []const u8,
    args: []const []const u8,
};

/// Splits a line into its keyword and arguments, as ssh does. Null for a
/// blank line or a comment.
fn splitLine(arena: Allocator, text: []const u8) error{ NoArgument, InvalidQuotes, OutOfMemory }!?Line {
    const line = std.mem.trim(u8, text, " \t\r\n\x0c");
    if (line.len == 0 or line[0] == '#') return null;

    // Spaces, or one `=` with spaces around it, end the keyword.
    const end = std.mem.indexOfAny(u8, line, " \t=") orelse line.len;
    var rest = line[end..];
    if (std.mem.startsWith(u8, rest, "=")) {
        rest = std.mem.trimStart(u8, rest[1..], " \t");
    } else {
        rest = std.mem.trimStart(u8, rest, " \t");
        if (std.mem.startsWith(u8, rest, "=")) rest = std.mem.trimStart(u8, rest[1..], " \t");
    }
    if (rest.len == 0) return error.NoArgument;

    return .{ .keyword = line[0..end], .args = try splitArgs(arena, rest) };
}

/// Splits arguments at spaces and tabs, as ssh's argv_split does. Double or
/// single quotes keep spaces in an argument. A backslash escapes a quote, a
/// backslash, or outside quotes, a space. An argument that starts with `#`
/// starts a comment.
fn splitArgs(arena: Allocator, text: []const u8) error{ InvalidQuotes, OutOfMemory }![]const []const u8 {
    var args: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (true) {
        while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
        if (i == text.len or text[i] == '#') break;

        var arg: std.ArrayList(u8) = .empty;
        var quote: ?u8 = null;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            if (c == '\\' and i + 1 < text.len and escapes(text[i + 1], quote)) {
                i += 1;
                try arg.append(arena, text[i]);
            } else if (quote) |q| {
                if (c == q) quote = null else try arg.append(arena, c);
            } else if (c == ' ' or c == '\t') {
                break;
            } else if (c == '"' or c == '\'') {
                quote = c;
            } else {
                try arg.append(arena, c);
            }
        }
        if (quote != null) return error.InvalidQuotes;
        try args.append(arena, arg.items);
    }
    return args.items;
}

/// Whether a backslash before `c` escapes it.
fn escapes(c: u8, quote: ?u8) bool {
    return c == '"' or c == '\'' or c == '\\' or (c == ' ' and quote == null);
}

const Case = enum { sensitive, insensitive };

/// Whether `s` matches `pattern`, in which `*` matches any run of
/// characters and `?` any one.
fn matchPattern(s: []const u8, pattern: []const u8, case: Case) bool {
    var si: usize = 0;
    var pi: usize = 0;
    // The last `*` seen, and the end of what it matches so far. On a
    // mismatch, it takes one more character, and matching resumes after it.
    var star: ?usize = null;
    var star_end: usize = 0;
    while (si < s.len) {
        if (pi < pattern.len and pattern[pi] == '*') {
            star = pi;
            star_end = si;
            pi += 1;
        } else if (pi < pattern.len and (pattern[pi] == '?' or sameChar(s[si], pattern[pi], case))) {
            si += 1;
            pi += 1;
        } else if (star) |star_pi| {
            star_end += 1;
            si = star_end;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }

    // What's left of the pattern must match nothing.
    while (pi < pattern.len and pattern[pi] == '*') pi += 1;
    return pi == pattern.len;
}

fn sameChar(a: u8, b: u8, case: Case) bool {
    return switch (case) {
        .sensitive => a == b,
        .insensitive => std.ascii.toLower(a) == std.ascii.toLower(b),
    };
}

/// Whether `s` matches a comma-separated list of patterns: one must, and
/// no negated one, such as `!*.example.com`, may.
fn matchPatternList(s: []const u8, list: []const u8, case: Case) bool {
    var matched = false;
    var patterns = std.mem.splitScalar(u8, list, ',');
    while (patterns.next()) |pattern| {
        if (std.mem.startsWith(u8, pattern, "!")) {
            if (matchPattern(s, pattern[1..], case)) return false;
        } else if (matchPattern(s, pattern, case)) {
            matched = true;
        }
    }
    return matched;
}

/// A path component's match, as glob(7) has it: a leading `.` matches only
/// a `.`.
fn matchComponent(name: []const u8, pattern: []const u8) bool {
    if (std.mem.startsWith(u8, name, ".") and !std.mem.startsWith(u8, pattern, ".")) return false;
    return matchPattern(name, pattern, .sensitive);
}

fn hasWildcard(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "*?") != null;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// `yes` or `no`, or `true` or `false`, as ssh takes them.
fn parseFlag(value: []const u8) ?bool {
    if (eqlIgnoreCase(value, "yes") or eqlIgnoreCase(value, "true")) return true;
    if (eqlIgnoreCase(value, "no") or eqlIgnoreCase(value, "false")) return false;
    return null;
}

fn validVariableName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    return true;
}

/// The host in lowercase, as ssh has it, unless it's an address.
fn lowerHost(arena: Allocator, host: []const u8) Allocator.Error![]const u8 {
    if (Io.net.IpAddress.parse(host, 0)) |_| return host else |_| {}
    return std.ascii.allocLowerString(arena, host);
}

/// Whether a config file is safe to take commands from: the user's or
/// root's, and not writable by others.
fn safelyOwned(file: Io.File) error{Unexpected}!bool {
    const uid = std.c.getuid();
    // std.c has no fstat on Linux.
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        const rc = linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .MODE = true, .UID = true }, &st);
        if (linux.errno(rc) != .SUCCESS) return std.posix.unexpectedErrno(linux.errno(rc));
        return safeMode(st.mode, st.uid, uid);
    }
    var st: std.c.Stat = undefined;
    if (std.c.fstat(file.handle, &st) != 0) return std.posix.unexpectedErrno(std.posix.errno(-1));
    return safeMode(st.mode, st.uid, uid);
}

fn safeMode(mode: std.posix.mode_t, owner: std.posix.uid_t, uid: std.posix.uid_t) bool {
    return (owner == 0 or owner == uid) and mode & 0o022 == 0;
}

const eqlIgnoreCase = std.ascii.eqlIgnoreCase;

const testing = std.testing;

/// A temporary home, for config files, and an environment that finds them
/// there: `~/.ssh/config`, and tx's config at `~/config/tx/config`.
const TestHome = struct {
    tmp: testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    dir: []const u8,
    environ: Environ.Map,

    fn init(h: *TestHome) !void {
        h.tmp = testing.tmpDir(.{});
        h.arena = .init(testing.allocator);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        h.dir = try h.arena.allocator().dupe(u8, buf[0..try h.tmp.dir.realPath(testing.io, &buf)]);
        h.environ = .init(testing.allocator);
        try h.environ.put("HOME", h.dir);
        try h.environ.put("XDG_CONFIG_HOME", try h.path("config"));
        // For Match exec.
        try h.environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    }

    fn deinit(h: *TestHome) void {
        h.environ.deinit();
        h.arena.deinit();
        h.tmp.cleanup();
    }

    fn path(h: *TestHome, sub_path: []const u8) ![]const u8 {
        return std.fs.path.join(h.arena.allocator(), &.{ h.dir, sub_path });
    }

    /// Writes a file that only the user may read or write.
    fn write(h: *TestHome, sub_path: []const u8, text: []const u8) !void {
        if (std.fs.path.dirname(sub_path)) |dir| try h.tmp.dir.createDirPath(testing.io, dir);
        try h.tmp.dir.writeFile(testing.io, .{
            .sub_path = sub_path,
            .data = text,
            .flags = .{ .permissions = .fromMode(0o600) },
        });
    }

    fn optionsFor(h: *TestHome, host: []const u8) Options {
        return .{ .host = host, .default_port = 8739, .environ = &h.environ };
    }

    fn resolve(h: *TestHome, options: Options) !Resolved {
        return switch (try ssh_config.resolve(h.arena.allocator(), testing.io, options)) {
            .ok => |resolved| resolved,
            .bad => |problem| {
                std.debug.print("bad config: {s}\n", .{problem});
                return error.TestUnexpectedResult;
            },
        };
    }

    /// The problem with the config, which must be bad.
    fn badConfig(h: *TestHome, options: Options) ![]const u8 {
        return switch (try ssh_config.resolve(h.arena.allocator(), testing.io, options)) {
            .ok => error.TestUnexpectedResult,
            .bad => |problem| problem,
        };
    }

    /// The problem with `text` as ssh's config, which must be bad.
    fn badSshConfig(h: *TestHome, text: []const u8) ![]const u8 {
        try h.write(".ssh/config", text);
        return h.badConfig(h.optionsFor("example.com"));
    }

    /// Expects a problem with a file under the home.
    fn expectProblem(h: *TestHome, expected: []const u8, problem: []const u8) !void {
        try testing.expectEqualStrings(try std.mem.concat(h.arena.allocator(), u8, &.{ h.dir, "/", expected }), problem);
    }
};

// `TestHome.resolve` hides the file's `resolve`.
const ssh_config = @This();

fn expectFiles(expected: []const []const u8, actual: []const []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| try testing.expectEqualStrings(e, a);
}

test "keywords in any case, with = or spaces, comments, and quoted arguments" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config",
        \\# A comment.
        \\HOSTNAME=real.example.com
        \\  user = "first user" # A comment after.
        \\User second
        \\
        \\IdentityFile "/keys/with space"
        \\identityfile=/keys/b
        \\IdentityFile '/keys/single quoted'
        \\IdentityFile /keys/escaped\ space
        \\
    );

    const r = try h.resolve(h.optionsFor("example.com"));
    try testing.expectEqualStrings("real.example.com", r.hostname);
    try testing.expectEqualStrings("first user", r.user.?);
    try expectFiles(&.{ "/keys/with space", "/keys/b", "/keys/single quoted", "/keys/escaped space" }, r.identity_files);
}

test "the first value wins, and IdentityFile adds, from the command line, then tx's config, then ssh's" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write("config/tx/config",
        \\Host *
        \\  HostName from-tx
        \\  IdentityFile /keys/tx
        \\
    );
    try h.write(".ssh/config",
        \\Host *
        \\  HostName from-ssh
        \\  User from-ssh
        \\  IdentityFile /keys/ssh
        \\
    );

    var options = h.optionsFor("example.com");
    options.identity_files = &.{"/keys/command-line"};
    const r = try h.resolve(options);
    try testing.expectEqualStrings("from-tx", r.hostname);
    try testing.expectEqualStrings("from-ssh", r.user.?);
    try expectFiles(&.{ "/keys/command-line", "/keys/tx", "/keys/ssh" }, r.identity_files);
}

test "Port comes from tx's config alone, and the command line's user and port win" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config",
        \\Port 22
        \\User from-config
        \\
    );
    try testing.expectEqual(8739, (try h.resolve(h.optionsFor("example.com"))).port);

    try h.write("config/tx/config", "Port 9000\n");
    const r = try h.resolve(h.optionsFor("example.com"));
    try testing.expectEqual(9000, r.port);
    try testing.expectEqualStrings("from-config", r.user.?);

    var options = h.optionsFor("example.com");
    options.port = 1234;
    options.user = "from-command-line";
    const given = try h.resolve(options);
    try testing.expectEqual(1234, given.port);
    try testing.expectEqualStrings("from-command-line", given.user.?);
}

test "Host patterns take * and ?, and a negated match rules the line out" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config",
        \\Host *.example.com !secret.example.com
        \\  HostName wildcard
        \\Host db? other
        \\  HostName one-character
        \\Host *
        \\  HostName fallback
        \\
    );

    try testing.expectEqualStrings("wildcard", (try h.resolve(h.optionsFor("www.example.com"))).hostname);
    try testing.expectEqualStrings("fallback", (try h.resolve(h.optionsFor("secret.example.com"))).hostname);
    try testing.expectEqualStrings("one-character", (try h.resolve(h.optionsFor("db1"))).hostname);
    try testing.expectEqualStrings("one-character", (try h.resolve(h.optionsFor("other"))).hostname);
    try testing.expectEqualStrings("fallback", (try h.resolve(h.optionsFor("db12"))).hostname);
    // Host patterns are case-sensitive.
    try testing.expectEqualStrings("fallback", (try h.resolve(h.optionsFor("WWW.EXAMPLE.COM"))).hostname);
}

test "Match host, originalhost, user, localuser, all, final and canonical, with lists and negation" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config",
        \\HostName real.example.com
        \\Match host real.example.com user alice
        \\  IdentityFile /keys/host-and-user
        \\Match host real.example.com user bob
        \\  IdentityFile /keys/other-user
        \\Match originalhost ALIAS
        \\  IdentityFile /keys/originalhost
        \\Match host alias
        \\  IdentityFile /keys/host-is-hostname
        \\Match !host *.other
        \\  IdentityFile /keys/negated-criterion
        \\Match host *.other,!real.*,*.com
        \\  IdentityFile /keys/negated-pattern
        \\Match host=*.example.com
        \\  IdentityFile /keys/equals
        \\Match localuser *
        \\  IdentityFile /keys/localuser
        \\Match localuser !*
        \\  IdentityFile /keys/no-localuser
        \\Match final
        \\  IdentityFile /keys/final
        \\Match canonical
        \\  IdentityFile /keys/canonical
        \\Match !canonical
        \\  IdentityFile /keys/not-canonical
        \\Match final all
        \\  IdentityFile /keys/all
        \\Match !all
        \\  IdentityFile /keys/not-all
        \\
    );

    var options = h.optionsFor("alias");
    options.user = "alice";
    const r = try h.resolve(options);
    try expectFiles(&.{
        "/keys/host-and-user",
        "/keys/originalhost",
        "/keys/negated-criterion",
        "/keys/equals",
        "/keys/localuser",
        "/keys/final",
        "/keys/not-canonical",
        "/keys/all",
    }, r.identity_files);
}

test "Match exec runs sh with tokens, and only while the other criteria hold" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config",
        \\HostName real.example.com
        \\Match exec "test %h = real.example.com && test %n = alias && touch %d/ran"
        \\  IdentityFile /keys/exec-true
        \\Match exec false
        \\  IdentityFile /keys/exec-false
        \\Match !exec false
        \\  IdentityFile /keys/not-exec-false
        \\Match host nothing exec "touch %d/skipped"
        \\  IdentityFile /keys/skipped
        \\
    );

    const r = try h.resolve(h.optionsFor("alias"));
    try expectFiles(&.{ "/keys/exec-true", "/keys/not-exec-false" }, r.identity_files);
    try h.tmp.dir.access(testing.io, "ran", .{});
    try testing.expectError(error.FileNotFound, h.tmp.dir.access(testing.io, "skipped", .{}));
}

test "a Match criterion tx doesn't support is warned about once, and its block doesn't apply" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config",
        \\Match localnetwork 10.0.0.0/8
        \\  IdentityFile /keys/a
        \\Match localnetwork 192.168.0.0/16
        \\  IdentityFile /keys/b
        \\Match all
        \\  IdentityFile /keys/c
        \\Match tagged=work
        \\  IdentityFile /keys/d
        \\
    );

    const r = try h.resolve(h.optionsFor("example.com"));
    try expectFiles(&.{"/keys/c"}, r.identity_files);
    try testing.expectEqual(2, r.warnings.len);
    const a = h.arena.allocator();
    try testing.expectEqualStrings(try std.fmt.allocPrint(a, "{s}/.ssh/config line 1: Match localnetwork isn't supported; its block doesn't apply", .{h.dir}), r.warnings[0]);
    try testing.expectEqualStrings(try std.fmt.allocPrint(a, "{s}/.ssh/config line 7: Match tagged isn't supported; its block doesn't apply", .{h.dir}), r.warnings[1]);
}

test "Include reads globs in byte order, relative to ~/.ssh or tx's config directory, under the block it's in" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write("config/tx/config", "Include extra\n");
    try h.write("config/tx/extra", "IdentityFile /keys/tx-extra\n");
    try h.write(".ssh/config",
        \\Include config.d/*
        \\IdentityFile /keys/after-glob
        \\Host nomatch
        \\  Include ~/never
        \\Host *
        \\  Include ~/vms/*/ssh_config ~/missing
        \\
    );
    // A Host in an included file ends with the file.
    try h.write(".ssh/config.d/b", "IdentityFile /keys/b\nHost nomatch\n");
    try h.write(".ssh/config.d/a", "IdentityFile /keys/a\n");
    try h.write(".ssh/config.d/.hidden", "IdentityFile /keys/hidden\n");
    try h.write("never", "IdentityFile /keys/never\n");
    try h.write("vms/two/ssh_config", "IdentityFile /keys/two\n");
    try h.write("vms/one/ssh_config", "IdentityFile /keys/one\n");

    const r = try h.resolve(h.optionsFor("example.com"));
    try expectFiles(&.{ "/keys/tx-extra", "/keys/a", "/keys/b", "/keys/after-glob", "/keys/one", "/keys/two" }, r.identity_files);
}

test "Includes nest 16 deep" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    const a = h.arena.allocator();

    // ssh's config includes ~/n1, which includes ~/n2, and so on.
    try h.write(".ssh/config", "Include ~/n1\n");
    for (1..16) |n| try h.write(try std.fmt.allocPrint(a, "n{d}", .{n}), try std.fmt.allocPrint(a, "Include ~/n{d}\n", .{n + 1}));
    try h.write("n16", "IdentityFile /keys/deep\n");
    try expectFiles(&.{"/keys/deep"}, (try h.resolve(h.optionsFor("example.com"))).identity_files);

    try h.write("n16", "Include ~/n17\n");
    try h.write("n17", "IdentityFile /keys/too-deep\n");
    try testing.expectEqualStrings(
        try std.fmt.allocPrint(a, "{s}/n16 line 1: Includes nest more than 16 deep", .{h.dir}),
        try h.badConfig(h.optionsFor("example.com")),
    );
}

test "HostName takes %h and %%" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config", "HostName %h.Example.com\n");
    try testing.expectEqualStrings("web.example.com", (try h.resolve(h.optionsFor("web"))).hostname);

    try h.write(".ssh/config", "HostName 10.0.0.1%%eth0\n");
    try testing.expectEqualStrings("10.0.0.1%eth0", (try h.resolve(h.optionsFor("web"))).hostname);

    try h.expectProblem(".ssh/config line 1: unknown token %u in %u.example.com", try h.badSshConfig("HostName %u.example.com\n"));
}

test "IdentityFile, IdentityAgent and User take ~, tokens and variables" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.environ.put("AGENT_DIR", "/agents");
    try h.write(".ssh/config",
        \\HostName Real.Example.com
        \\User u-%n
        \\IdentityFile ~/.ssh/%h-%r-%p
        \\IdentityFile %d/%u/%n/%i/%%
        \\IdentityFile ${AGENT_DIR}/%l
        \\IdentityAgent ${AGENT_DIR}/%L.sock
        \\
    );

    const r = try h.resolve(h.optionsFor("alias"));
    try testing.expectEqualStrings("real.example.com", r.hostname);
    try testing.expectEqualStrings("u-alias", r.user.?);

    const a = h.arena.allocator();
    const local = try Local.init(a, &h.environ);
    const short = local.hostname.?[0 .. std.mem.indexOfScalar(u8, local.hostname.?, '.') orelse local.hostname.?.len];
    try expectFiles(&.{
        try std.fmt.allocPrint(a, "{s}/.ssh/real.example.com-u-alias-8739", .{h.dir}),
        try std.fmt.allocPrint(a, "{s}/{s}/alias/{d}/%", .{ h.dir, local.user.?, std.c.getuid() }),
        try std.fmt.allocPrint(a, "/agents/{s}", .{local.hostname.?}),
    }, r.identity_files);
    try testing.expectEqualStrings(try std.fmt.allocPrint(a, "/agents/{s}.sock", .{short}), r.identity_agent.?.path);

    // The command line's files, too.
    var options = h.optionsFor("alias");
    options.identity_files = &.{"~/%h"};
    try testing.expectEqualStrings(try h.path("real.example.com"), (try h.resolve(options)).identity_files[0]);
}

test "IdentityAgent SSH_AUTH_SOCK, none, and $VAR" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.environ.put("SSH_AUTH_SOCK", "/agent.sock");
    try testing.expectEqual(null, (try h.resolve(h.optionsFor("example.com"))).identity_agent);

    try h.write(".ssh/config", "IdentityAgent SSH_AUTH_SOCK\n");
    try testing.expectEqualStrings("/agent.sock", (try h.resolve(h.optionsFor("example.com"))).identity_agent.?.path);

    try h.write(".ssh/config", "IdentityAgent none\nIdentityAgent /ignored.sock\n");
    try testing.expectEqual(.none, (try h.resolve(h.optionsFor("example.com"))).identity_agent.?);

    try h.write(".ssh/config", "IdentityAgent $OTHER_AGENT\n");
    try testing.expectEqual(.none, (try h.resolve(h.optionsFor("example.com"))).identity_agent.?);
    try h.environ.put("OTHER_AGENT", "/other.sock");
    try testing.expectEqualStrings("/other.sock", (try h.resolve(h.optionsFor("example.com"))).identity_agent.?.path);
}

test "IdentityFile none adds no file, and the defaults apply when no file is named" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    var options = h.optionsFor("example.com");
    options.default_identity_files = &.{"~/.ssh/id_ed25519"};
    try expectFiles(&.{try h.path(".ssh/id_ed25519")}, (try h.resolve(options)).identity_files);

    try h.write(".ssh/config", "IdentityFile none\n");
    try expectFiles(&.{}, (try h.resolve(options)).identity_files);
}

test "IdentitiesOnly and ProxyJump" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    const unset = try h.resolve(h.optionsFor("example.com"));
    try testing.expect(!unset.identities_only);
    try testing.expectEqual(null, unset.proxy_jump);

    try h.write(".ssh/config", "IdentitiesOnly yes\nProxyJump bastion.example.com\n");
    const set = try h.resolve(h.optionsFor("example.com"));
    try testing.expect(set.identities_only);
    try testing.expectEqualStrings("bastion.example.com", set.proxy_jump.?);

    try h.write(".ssh/config", "ProxyJump none\nProxyJump bastion.example.com\n");
    try testing.expectEqual(null, (try h.resolve(h.optionsFor("example.com"))).proxy_jump);
}

test "bad lines and unknown tokens are errors with the file and line" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.expectProblem(".ssh/config line 2: unknown token %C in ~/%C", try h.badSshConfig("# keys\nIdentityFile ~/%C\n"));
    try h.expectProblem(".ssh/config line 1: invalid quotes", try h.badSshConfig("HostName \"unclosed\n"));
    try h.expectProblem(".ssh/config line 1: no argument after the keyword", try h.badSshConfig("User\n"));
    try h.expectProblem(".ssh/config line 1: HostName takes one argument", try h.badSshConfig("HostName a b\n"));
    try h.expectProblem(".ssh/config line 1: IdentitiesOnly takes yes or no, not maybe", try h.badSshConfig("IdentitiesOnly maybe\n"));
    try h.expectProblem(".ssh/config line 1: Match all can't be combined with other criteria", try h.badSshConfig("Match all host x\n"));
    try h.expectProblem(".ssh/config line 1: Match host needs an argument", try h.badSshConfig("Match host\n"));
    try h.expectProblem(".ssh/config line 1: UNSET isn't set, for ${UNSET}/key", try h.badSshConfig("IdentityFile ${UNSET}/key\n"));
    // Keywords tx doesn't read still need an argument.
    try h.expectProblem(".ssh/config line 1: no argument after the keyword", try h.badSshConfig("ForwardAgent\n"));

    // Only active values are expanded, as in ssh.
    try h.write(".ssh/config", "Host other\n  IdentityFile ~/%C\n");
    _ = try h.resolve(h.optionsFor("example.com"));

    try h.write(".ssh/config", "");
    try h.write("config/tx/config", "Port 0\n");
    try h.expectProblem("config/tx/config line 1: bad port 0", try h.badConfig(h.optionsFor("example.com")));
}

test "missing files are fine, -F names ssh's config, and -F none reads none" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try testing.expectEqualStrings("example.com", (try h.resolve(h.optionsFor("example.com"))).hostname);

    try h.write(".ssh/config", "HostName from-ssh-config\n");
    try h.write("given", "HostName from-given\n");
    var options = h.optionsFor("example.com");
    options.ssh_config = try h.path("given");
    try testing.expectEqualStrings("from-given", (try h.resolve(options)).hostname);

    options.ssh_config = "none";
    try testing.expectEqualStrings("example.com", (try h.resolve(options)).hostname);
    try h.write("config/tx/config", "HostName from-tx\n");
    try testing.expectEqualStrings("from-tx", (try h.resolve(options)).hostname);

    options.ssh_config = try h.path("missing");
    try h.expectProblem("missing: no such file", try h.badConfig(options));
}

test "a config file others can write is refused" {
    var h: TestHome = undefined;
    try h.init();
    defer h.deinit();
    try h.write(".ssh/config", "HostName real.example.com\n");
    _ = try h.resolve(h.optionsFor("example.com"));

    try h.tmp.dir.setFilePermissions(testing.io, ".ssh/config", .fromMode(0o620), .{});
    try h.expectProblem(".ssh/config: bad owner or permissions: it must be yours or root's, and only its owner may write it", try h.badConfig(h.optionsFor("example.com")));

    // A file given with -F isn't checked, as in ssh.
    var options = h.optionsFor("example.com");
    options.ssh_config = try h.path(".ssh/config");
    try testing.expectEqualStrings("real.example.com", (try h.resolve(options)).hostname);
}

test matchPattern {
    try testing.expect(matchPattern("", "", .sensitive));
    try testing.expect(matchPattern("", "*", .sensitive));
    try testing.expect(!matchPattern("a", "", .sensitive));
    try testing.expect(matchPattern("web.example.com", "*.example.com", .sensitive));
    try testing.expect(!matchPattern("example.com", "*.example.com", .sensitive));
    try testing.expect(matchPattern("db1", "db?", .sensitive));
    try testing.expect(!matchPattern("db12", "db?", .sensitive));
    try testing.expect(matchPattern("abcbcd", "a*bcd", .sensitive));
    try testing.expect(matchPattern("a*b", "a*b", .sensitive));
    try testing.expect(matchPattern("*xb", "*b", .sensitive));
    try testing.expect(matchPattern("aXb", "a?b", .sensitive));
    try testing.expect(!matchPattern("WEB", "web", .sensitive));
    try testing.expect(matchPattern("WEB", "web", .insensitive));
}

test splitArgs {
    const a = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const args = try splitArgs(arena.allocator(), "one \"two three\"  fo'u r'\\\" five\\ six \\x # seven");
    try expectFiles(&.{ "one", "two three", "fou r\"", "five six", "\\x" }, args);
    try testing.expectError(error.InvalidQuotes, splitArgs(arena.allocator(), "\"open"));
}
