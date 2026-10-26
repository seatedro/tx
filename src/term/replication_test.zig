//! Replication tests: a replica restored from a snapshot cut anywhere in a
//! primary's output, then given the rest of the log, must reach exactly
//! the primary's state, not just right after the restore but at every
//! later point we look.
//!
//! Every random choice uses a fixed seed, so a failure reproduces.
const std = @import("std");
const testing = std.testing;
const vt = @import("ghostty-vt");
const log = @import("log.zig");
const Primary = @import("primary.zig").Primary;
const Handler = @import("primary.zig").Handler;
const Replica = @import("replica.zig").Replica;
const state = @import("state.zig");

const gpa = testing.allocator;
const io = testing.io;

/// Dumps are large and there are many of them, so they skip the
/// leak-checking allocator, which scans every freed byte in Debug.
const dump_gpa = std.heap.smp_allocator;

/// A script step: output from the program, or a resize from the client.
const Step = union(enum) {
    out: []const u8,
    resize: log.Resize,
};

/// What a cut can fall between: one byte of output, or one resize.
const Atom = union(enum) {
    byte: u8,
    resize: log.Resize,
};

const Config = struct {
    cols: u16 = 20,
    rows: u16 = 6,
    max_scrollback_bytes: ?usize = 10_000_000,
    max_scrollback_lines: ?usize = null,
    /// Install effect callbacks on the primary, as a host would. They
    /// answer queries, which must not change state.
    effects: bool = true,
    /// Records the primary's output is split into are 1 to this many
    /// bytes long.
    max_chunk: usize = 24,
    /// How many times to compare after the restore, the last at the end of
    /// the script. The first comparison is right after the restore.
    checkpoints: usize = 3,
    /// Print the dumps' first difference when they diverge.
    report: bool = true,
    /// Run the primary and replica on the leak-checking allocator. It
    /// records a stack trace for every allocation, which makes the tests
    /// that run thousands of cuts several times slower, so those use the
    /// plain allocator and others cover leaks.
    leak_check: bool = true,

    fn allocator(config: Config) std.mem.Allocator {
        return if (config.leak_check) testing.allocator else std.heap.smp_allocator;
    }
};

const Cut = struct {
    name: []const u8,
    /// Atoms fed before the snapshot.
    at: usize,
    seed: u64,
};

fn flatten(steps: []const Step) ![]Atom {
    var atoms: std.ArrayList(Atom) = .empty;
    errdefer atoms.deinit(gpa);
    for (steps) |step| switch (step) {
        .out => |bytes| for (bytes) |b| try atoms.append(gpa, .{ .byte = b }),
        .resize => |r| try atoms.append(gpa, .{ .resize = r }),
    };
    return atoms.toOwnedSlice(gpa);
}

/// Answers queries the way a host would, and counts the replies.
const Effects = struct {
    var replies: usize = 0;

    fn install(h: *Handler) void {
        h.effects.write_pty = &writePty;
        h.effects.bell = &bell;
        h.effects.device_attributes = &deviceAttributes;
        h.effects.enquiry = &enquiry;
        h.effects.xtversion = &xtversion;
        h.effects.size = &size;
        h.effects.color_scheme = &colorScheme;
        h.effects.title_changed = &bell;
        h.effects.pwd_changed = &bell;
        h.effects.clipboard_write = &clipboardWrite;
        h.effects.desktop_notification = &desktopNotification;
        h.title_report = true;
    }

    fn writePty(_: *Handler, data: []const u8) void {
        if (data.len > 0) replies += 1;
    }
    fn bell(_: *Handler) void {}
    fn deviceAttributes(_: *Handler) vt.device_attributes.Attributes {
        return .{};
    }
    fn enquiry(_: *Handler) []const u8 {
        return "tx";
    }
    fn xtversion(_: *Handler) []const u8 {
        return "tx 0";
    }
    fn size(h: *Handler) ?vt.size_report.Size {
        return .{ .rows = h.terminal.rows, .columns = h.terminal.cols, .cell_width = 10, .cell_height = 20 };
    }
    fn colorScheme(_: *Handler) ?vt.device_status.ColorScheme {
        return .dark;
    }
    fn clipboardWrite(_: *Handler, _: vt.clipboard.Write) void {}
    fn desktopNotification(_: *Handler, _: vt.StreamAction.ShowDesktopNotification) void {}
};

const kitty_limit = 1024 * 1024;
const continuation_limit = 64 * 1024;

fn createPrimary(config: Config) !*Primary {
    const a: *Primary = try .create(config.allocator(), io, .{
        .cols = config.cols,
        .rows = config.rows,
        .max_scrollback_bytes = config.max_scrollback_bytes,
        .max_scrollback_lines = config.max_scrollback_lines,
        .kitty_image_storage_limit = kitty_limit,
        .log_capacity = 64 * 1024 * 1024,
        .continuation_max_bytes = continuation_limit,
    });
    if (config.effects) Effects.install(a.handler());
    return a;
}

/// Feed `atoms` to the primary, output in randomly sized records.
fn feed(a: *Primary, atoms: []const Atom, rng: std.Random, max_chunk: usize) !void {
    var i: usize = 0;
    while (i < atoms.len) i += try feedRecord(a, atoms[i..], rng, max_chunk);
}

/// Apply every record the replica hasn't seen yet.
fn catchUp(m: *Replica, a: *Primary) !void {
    var it = try a.log.iterator(m.next_seq);
    while (it.next()) |record| try m.apply(record);
}

fn restore(a: *Primary) !*Replica {
    var snapshot: std.Io.Writer.Allocating = .init(a.gpa);
    defer snapshot.deinit();
    const seq = try a.snapshot(a.gpa, &snapshot.writer);
    var reader: std.Io.Reader = .fixed(snapshot.written());
    const m = try Replica.restore(a.gpa, io, &reader, seq, .{
        .kitty_image_storage_limit = kitty_limit,
        .max_continuation_bytes = continuation_limit,
    });
    // Restoring consumes exactly the snapshot.
    try testing.expectEqual(snapshot.written().len, reader.seek);
    try testing.expectEqual(a.log.nextSeq(), m.next_seq);
    return m;
}

/// What a terminal and its stream look like at one point: the state dump,
/// and the unfinished sequence or null if it is too long to track.
const Expected = struct {
    dump: []u8,
    continuation: ?[]u8,

    fn of(t: *const vt.Terminal, stream: *const vt.TerminalStream) !Expected {
        const dump = try state.dumpAlloc(dump_gpa, t);
        errdefer dump_gpa.free(dump);
        var buf: std.Io.Writer.Allocating = .init(dump_gpa);
        defer buf.deinit();
        const cont: ?[]u8 = if (stream.writeContinuation(&buf.writer)) |_|
            try buf.toOwnedSlice()
        else |err| switch (err) {
            error.ContinuationUnavailable => null,
            error.ContinuationDisabled => unreachable,
            error.WriteFailed => return error.OutOfMemory,
        };
        return .{ .dump = dump, .continuation = cont };
    }

    fn deinit(self: Expected) void {
        dump_gpa.free(self.dump);
        if (self.continuation) |c| dump_gpa.free(c);
    }
};

/// Compare the replica with what the primary looked like at `at`.
fn compare(expected: Expected, m: *Replica, cut: Cut, at: usize, config: Config) !void {
    const actual: Expected = try .of(&m.terminal, &m.stream);
    defer actual.deinit();
    if (!std.mem.eql(u8, expected.dump, actual.dump)) {
        if (config.report) reportDiff(cut, at, expected.dump, actual.dump);
        return error.Diverged;
    }
    // The primary's sequence can be too long to track. The replica's
    // can't be, since the replica only replays what fit in the snapshot.
    const e = expected.continuation orelse return;
    if (actual.continuation == null or !std.mem.eql(u8, e, actual.continuation.?)) {
        if (config.report) std.debug.print("{s}: cut {d}, at {d}: continuations differ: \"{f}\" and \"{f}\"\n", .{
            cut.name,
            cut.at,
            at,
            std.zig.fmtString(e),
            std.zig.fmtString(actual.continuation orelse "(unavailable)"),
        });
        return error.Diverged;
    }
}

fn reportDiff(cut: Cut, at: usize, expected: []const u8, actual: []const u8) void {
    std.debug.print("{s}: cut {d} (seed {d}), compared at {d}: the replica diverged\n", .{ cut.name, cut.at, cut.seed, at });
    // The first difference, then a few lines of each side, since a line
    // missing from one side shifts everything after it.
    var e_lines = std.mem.splitScalar(u8, expected, '\n');
    var a_lines = std.mem.splitScalar(u8, actual, '\n');
    while (true) {
        const e = e_lines.next();
        const l = a_lines.next();
        if (e == null and l == null) return;
        if (e != null and l != null and std.mem.eql(u8, e.?, l.?)) continue;
        std.debug.print("  primary: {s}\n", .{e orelse "(end)"});
        for (0..3) |_| std.debug.print("             {s}\n", .{e_lines.next() orelse break});
        std.debug.print("  replica:    {s}\n", .{l orelse "(end)"});
        for (0..3) |_| std.debug.print("             {s}\n", .{a_lines.next() orelse break});
        return;
    }
}

/// Run one cut: feed a primary up to `cut.at`, restore a replica from
/// its snapshot, then keep both going to the end, comparing the replica
/// with the primary right after the restore and at each checkpoint.
fn checkCut(atoms: []const Atom, cut: Cut, config: Config) !void {
    var prng: std.Random.DefaultPrng = .init(cut.seed);
    const rng = prng.random();

    const a = try createPrimary(config);
    defer a.destroy();
    try feed(a, atoms[0..cut.at], rng, config.max_chunk);
    const m = try restore(a);
    defer m.destroy();

    var pos = cut.at;
    for (0..config.checkpoints + 1) |i| {
        const next = cut.at + (atoms.len - cut.at) * i / config.checkpoints;
        if (i != 0 and i != config.checkpoints and next == pos) continue;
        try feed(a, atoms[pos..next], rng, config.max_chunk);
        try catchUp(m, a);
        const expected: Expected = try .of(&a.terminal, &a.stream);
        defer expected.deinit();
        compare(expected, m, cut, next, config) catch |err| {
            if (err == error.Diverged and config.report) try findFirstDivergence(atoms, cut, config);
            return err;
        };
        pos = next;
    }
}

/// Replay a diverged cut one atom at a time and print the first atom
/// after which the replica differs, with the bytes leading up to it.
fn findFirstDivergence(atoms: []const Atom, cut: Cut, config: Config) !void {
    var prng: std.Random.DefaultPrng = .init(cut.seed);
    const a = try createPrimary(config);
    defer a.destroy();
    try feed(a, atoms[0..cut.at], prng.random(), config.max_chunk);
    const m = try restore(a);
    defer m.destroy();
    var quiet = config;
    quiet.report = false;
    for (cut.at..atoms.len) |i| {
        try feed(a, atoms[i .. i + 1], prng.random(), 1);
        try catchUp(m, a);
        const expected: Expected = try .of(&a.terminal, &a.stream);
        defer expected.deinit();
        compare(expected, m, cut, i + 1, quiet) catch {
            std.debug.print("  first differs after atom {d}, which ends:", .{i});
            for (atoms[i -| 24 .. i + 1]) |atom| switch (atom) {
                .byte => |b| std.debug.print("{f}", .{std.zig.fmtString(&.{b})}),
                .resize => |r| std.debug.print(" [resize {d}x{d}] ", .{ r.cols, r.rows }),
            };
            std.debug.print("\n", .{});
            return;
        };
    }
}

/// Check a cut at every atom of a script, and at every record boundary of
/// a second run in records of random sizes.
///
/// Running a new primary to each of thousands of cuts is slow in Debug,
/// so each run uses one primary, snapshots it after every record, and
/// keeps its whole log. Each snapshot then restores a replica that applies
/// the log from there. The replicas are compared with the state after each
/// atom, recorded from the first run.
fn checkEveryCut(name: []const u8, steps: []const Step, config: Config) !void {
    const atoms = try flatten(steps);
    defer gpa.free(atoms);

    var reference: std.ArrayList(Expected) = .empty;
    defer {
        for (reference.items) |e| e.deinit();
        reference.deinit(gpa);
    }
    for ([_]usize{ 1, config.max_chunk }) |max_chunk| {
        var prng: std.Random.DefaultPrng = .init(max_chunk);
        const a = try createPrimary(config);
        defer a.destroy();
        var snapshots: std.ArrayList(Snapshot) = .empty;
        defer {
            for (snapshots.items) |s| a.gpa.free(s.bytes);
            snapshots.deinit(gpa);
        }
        // Atoms consumed by the end of each record, by seq.
        var ends: std.ArrayList(usize) = .empty;
        defer ends.deinit(gpa);

        var at: usize = 0;
        while (true) {
            if (max_chunk == 1) try reference.append(gpa, try .of(&a.terminal, &a.stream));
            var bytes: std.Io.Writer.Allocating = .init(a.gpa);
            defer bytes.deinit();
            const seq = try a.snapshot(a.gpa, &bytes.writer);
            const owned = try bytes.toOwnedSlice();
            errdefer a.gpa.free(owned);
            try snapshots.append(gpa, .{ .bytes = owned, .seq = seq, .at = at });
            if (at == atoms.len) break;
            at += try feedRecord(a, atoms[at..], prng.random(), max_chunk);
            try ends.append(gpa, at);
        }

        for (snapshots.items) |s| {
            const cut: Cut = .{ .name = name, .at = s.at, .seed = max_chunk };
            var reader: std.Io.Reader = .fixed(s.bytes);
            const m = try Replica.restore(a.gpa, io, &reader, s.seq, .{
                .kitty_image_storage_limit = kitty_limit,
                .max_continuation_bytes = continuation_limit,
            });
            defer m.destroy();
            var pos = s.at;
            for (0..config.checkpoints + 1) |i| {
                const target = s.at + (atoms.len - s.at) * i / config.checkpoints;
                if (i != 0 and i != config.checkpoints and target == pos) continue;
                while (m.next_seq < ends.items.len and ends.items[m.next_seq] <= target) {
                    pos = ends.items[m.next_seq];
                    try m.apply(try a.log.get(m.next_seq));
                }
                compare(reference.items[pos], m, cut, pos, config) catch |err| {
                    if (config.report) std.debug.print("  (records of up to {d} atoms)\n", .{max_chunk});
                    return err;
                };
            }
        }
    }
}

const Snapshot = struct {
    bytes: []u8,
    seq: u64,
    /// Atoms the primary had consumed.
    at: usize,
};

/// Feed the primary one record from the start of `atoms`: a resize, or
/// up to `max_chunk` bytes of output. Returns the atoms consumed.
fn feedRecord(a: *Primary, atoms: []const Atom, rng: std.Random, max_chunk: usize) !usize {
    switch (atoms[0]) {
        .resize => |r| {
            try a.resize(r);
            return 1;
        },
        .byte => {
            var buf: [4096]u8 = undefined;
            const want = rng.intRangeAtMost(usize, 1, @min(max_chunk, buf.len));
            var n: usize = 0;
            while (n < atoms.len and n < want and atoms[n] == .byte) : (n += 1) buf[n] = atoms[n].byte;
            try a.output(buf[0..n]);
            return n;
        },
    }
}

fn out(comptime bytes: []const u8) []const Step {
    return &.{.{ .out = bytes }};
}

// Base64 RGBA pixels for Kitty graphics transmissions.
const pixel_1x1 = "/wAA/w==";
const pixels_2x2 = "/wAA/wD/AP8AAP//////gA==";
const pixels_4x4_a = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";
const pixels_4x4_b = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";

/// `n` lines formatted with `fmt`, which gets `i % 8` and `i`.
fn lines(comptime n: usize, comptime fmt: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var s: []const u8 = "";
        for (0..n) |i| s = s ++ std.fmt.comptimePrint(fmt, .{ i % 8, i });
        return s;
    }
}

const corpora = [_]struct { []const u8, []const Step }{
    .{ "alternate screens", out("primary\r\n\x1b[1;31mred\x1b[0m\x1b[3;5H\x1b7" ++
        "\x1b[?1049halt one\r\n\x1b[2;2Hxy\x1b[?1049l" ++
        "after\x1b8!" ++
        "\x1b[?1047hfoo\x1b[?1047l" ++
        "\x1b[?47hbar\x1b[H\x1b[2J\x1b[?47l" ++
        "\x1b[?1048h\x1b[5;5H\x1b[?1048l*" ++
        "\x1b[?1049h\x1b[4;4H\x1b7\x1b[?1049h\x1b[?1049lend") },
    .{ "kitty keyboard stack", out("\x1b[>1u\x1b[>3u\x1b[=5;2u\x1b[=4;3u\x1b[<u" ++
        "\x1b[>31u\x1b[>1u\x1b[>2u\x1b[>4u\x1b[>8u\x1b[>16u\x1b[>1u\x1b[>2u\x1b[>3u" ++
        "\x1b[<3u\x1b[=7;1u\x1b[?1049h\x1b[>5u\x1b[=2u\x1b[?1049l\x1b[<20u\x1b[>9u") },
    .{ "synchronized output", out("\x1b[?2026hframe 1\x1b[H\x1b[2Jframe 2\x1b[?2026l" ++
        "\x1b[?2026h\x1b[5;1Hpartial\x1b[?2026h more") },
    .{
        "scrolling regions and origin mode",
        out("\x1b[2;5r\x1b[?6h\x1b[1;1Htop\r\n1\r\n2\r\n3\r\n4\r\n5\r\n6" ++
            "\x1b[3;1H\x1b[2M\x1b[L\x1bM\x1bM\x1bM\x1bD\x1bE\x1b[?6l\x1b[1;1Hout\x1b[r" ++
            // Text stays clear of the right margin: see "pending wrap at a
            // right margin is lost".
            "\x1b[?69h\x1b[3;8s\x1b[?6h\x1b[1;1Hmar\x1b[2;1Hgin\x1b[1;2H\x1b[2@\x1b[S\x1b[1;1H\x1b[P" ++
            "\x1b[?6l\x1b[s\x1b[?69l\x1b[2;3r"),
    },
    .{ "saved cursor", out("\x1b[2;3H\x1b[1;4;38;5;100m\x1b(0\x1b7\x1b[0m\x1b(B\x1b[6;10Hx\x1b8y" ++
        "\x1b[s\x1b[1;1H\x1b[uz\x1b[1;20Hw\x1b7\x1b[H\x1b8q") },
    .{ "insert mode and character editing", out("abcdef\x1b[1;3H\x1b[4hXY\x1b[4l\x1b[1;1H\x1b[2@\x1b[3P\x1b[2X" ++
        "\r\n\x1b[1;5H\x1b[4h\u{4E2D}\x1b[4l\x1b[2;18Hlong\x1b[4h\x1b[2;1Hpushed") },
    .{ "wide characters and graphemes", out("\u{4E2D}\u{6587} e\u{301} \u{1F469}\u{200D}\u{1F4BB} \u{1F1FA}\u{1F1F8}" ++
        " \u{2764}\u{FE0F} a\u{0308}\u{0323}\x1b[1;19H\u{4E2D}\u{1F600}x\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}" ++
        "\x1b[?2027l\u{1F469}\u{200D}\u{1F4BB}\x1b[?2027h\x1b[3;1H\u{4E2D}\x1b[3;2Hx\x1b[3;5H\u{301}") },
    .{ "SGR", out("\x1b[1;2;3;4;5;7;8;9;53mA\x1b[0m\x1b[4:3;58;2;10;20;30mB\x1b[38;5;196;48;5;21mC" ++
        "\x1b[38;2;1;2;3;48;2;250;251;252mD\x1b[39;49;59mE\x1b[21;22;23;24;25;27;28;29;55m" ++
        "\x1b[90;101mF\x1b[m\x1b[44m\x1b[K\x1b[0m\x1b[58:5:9;4:2mG\x1b[38:2::1:2:3mH\x1b[0m") },
    .{ "palette and dynamic colors", out("\x1b]4;1;rgb:11/22/33\x07\x1b]4;2;#445566;3;?\x1b\\\x1b[31mred" ++
        "\x1b]104;1\x1b\\\x1b]10;rgb:aa/bb/cc\x1b\\\x1b]11;#010203\x07\x1b]12;red\x1b\\\x1b]110\x1b\\" ++
        "\x1b]4;200;rgb:ff/00/ff\x1b\\\x1b]104\x1b\\\x1b]4;5;rgb:01/01/01\x1b\\" ++
        "\x1b]21;foreground=#123456;cursor=?;background\x1b\\") },
    .{ "hyperlinks", out("\x1b]8;id=one;https://one.example\x1b\\link one\x1b]8;;\x1b\\ plain " ++
        "\x1b]8;;https://two.example\x07implicit link wrapping across the line\x1b]8;;\x07" ++
        "\x1b]8;id=one;https://one.example\x1b\\again\x1b]8;;\x1b\\\x1b]8;;https://three\x1b\\") },
    .{ "titles and pwd", out("\x1b]0;both\x07\x1b]2;window \u{1F600}\x1b\\\x1b]1;icon\x1b\\" ++
        "\x1b]7;file://host/home/user\x1b\\\x1b]7;file://host/tmp%20dir\x07\x1b]2;\x1b\\" ++
        "\x1b]9;4;1;50\x1b\\\x1b]22;pointer\x1b\\\x1b]2;last\x07") },
    .{ "tabstops", out("\x1b[3g\x1b[1;4H\x1bH\x1b[1;10H\x1bH\r\ta\tb\tc\x1b[1;4H\x1b[0g\r\ta" ++
        "\x1b[2I\x1b[Z\x1b[?5W\r\tx\x1b[2;1H\x1b[3g\tq") },
    .{ "DEC special graphics", out("\x1b(0lqqk\x1b(B\r\n\x1b)0\x0elqk\x0fabc\x1b*0\x1bnx\x1bNy" ++
        "\x1b(A#\x1b(B\x1b+0\x1bo q\x1b|\x1b}\x1b~\x1b(0\x1b7\x1b(Bq\x1b8q") },
    .{ "scrollback", out(lines(30, "\x1b[3{d}mline {d}\x1b[0m\r\n") ++
        "\x1b[2S\x1b[1T\x1b[?1049h" ++ lines(8, "alt {d} {d}\r\n") ++ "\x1b[?1049l\x1b[3Jcleared\r\n\r\n") },
    .{ "control strings", out("\x1bP$qm\x1b\\\x1bP+q544e\x1b\\\x1b_Gi=31,a=q,s=1,v=1,f=32;AAAAAA==\x1b\\" ++
        "\x1b]52;c;aGVsbG8=\x1b\\\x1b]52;c;?\x1b\\\x1b]9;notify\x1b\\\x1b]777;notify;t;b\x1b\\" ++
        "\x1b]5522;type=write\x1b\\\x1b]7400;x\x1b\\\x1b_unknown apc\x1b\\\x1bXsos\x1b\\\x1b^pm\x1b\\" ++
        "\x1b]2;x\x9ctext\xc2\x9b\x1b[12\x18can\x1b]2;y\x1asub\x1b[3\x07m\x1b[1;" ++
        "\x1bP1$r\x1b\\\x1b]0;\xe2\x82\xac\x07") },
    .{ "queries", out("\x1b[c\x1b[>c\x1b[=c\x1b[5n\x1b[6n\x1b[?6n\x1b[?2004$p\x1b[4$p\x1b[>q\x05" ++
        "\x1b]10;?\x1b\\\x1b]4;1;?\x07\x1b[14t\x1b[18t\x1b[?996n\x1b[?u\x1bP$q\"p\x1b\\\x1b[21t" ++
        "\x1b[?2048h\x1b[?2048$p\x1bP+q544e;636f6c73\x1b\\\x1b[?1;2$p") },
    .{ "modes", out("\x1b[?1h\x1b=\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1005h\x1b[?1006h\x1b[?1015h" ++
        "\x1b[?1016h\x1b[?1004h\x1b[?2004h\x1b[?25l\x1b[?12h\x1b[?5h\x1b[20h\x1b[>4;2m\x1b[>1s" ++
        "\x1b[?1036h\x1b[?1039h\x1b[?2031h\x1b[?5522h\x1b[2 q\x1b[?1000l\x1b[?2004s\x1b[?2004l" ++
        "\x1b[?2004r\x1b[?7lno wrap past the edge\x1b[?45h\x1b[?67h\x1b>\x1b[6 q\x1b[>4m") },
    .{ "erasing and resets", out("\x1b#8\x1b[2;2H\x1b[1J\x1b[3;3H\x1b[0K\x1b[1\"qPROT\x1b[0\"q" ++
        "\x1b[?2J\x1b[?1K\x1b[2S\x1b[1T\x1b[3L\x1b[2Mab\x1b[5b\x1b[!pafter soft\x1b[?1049h" ++
        "\x1bcafter reset\x1b[1;31m\x1b]2;t\x07") },
    .{ "semantic prompts", out("\x1b]133;A;cl=line\x07$ \x1b]133;B\x07ls\x1b]133;C\x07\r\nout\r\n" ++
        "\x1b]133;D;0\x07\x1b]133;A;redraw=0\x07$ \x1b]133;B\x07\x1b]133;P;k=r\x07right") },
    .{ "status line", out("\x1b[2$~\x1b[1$}status text\x1b[0$}main\x1b[0$~more") },
    .{ "kitty graphics", &.{
        .{ .resize = .{ .cols = 20, .rows = 6, .cell_size_px = .{ .width = 10, .height = 20 } } },
        .{ .out = "ab\x1b_Ga=T,f=32,s=2,v=2,i=1,p=1,q=2;" ++ pixels_2x2 ++ "\x1b\\cd" ++
            "\x1b_Ga=t,f=32,s=4,v=4,i=2,q=2,m=1;" ++ pixels_4x4_a ++ "\x1b\\" ++
            "\x1b_Gm=0;" ++ pixels_4x4_b ++ "\x1b\\" ++
            "\x1b[3;3H\x1b_Ga=p,i=2,p=5,c=3,r=2,z=-1,q=2\x1b\\" ++
            "\x1b_Ga=p,i=2,p=6,P=2,Q=5,H=1,V=1,q=2\x1b\\" ++
            "\x1b_Ga=p,i=2,p=7,U=1,c=2,r=1,q=2\x1b\\\x1b[38;5;2m\u{10EEEE}\u{305}\u{10EEEE}\u{30D}\x1b[0m" ++
            "\x1b_Ga=T,f=32,s=1,v=1,q=2;" ++ pixel_1x1 ++ "\x1b\\" ++
            "\x1b_Ga=T,f=32,s=1,v=1,I=9,q=2;" ++ pixel_1x1 ++ "\x1b\\" ++
            "\x1b_Ga=f,i=2,f=32,s=4,v=4,z=50,q=2;" ++ pixels_4x4_a ++ pixels_4x4_b ++ "\x1b\\" ++
            "\x1b_Ga=a,i=2,s=3,v=2,q=2\x1b\\\x1b_Ga=a,i=2,c=2,q=2\x1b\\" ++
            "\r\n\r\n\r\n\r\n\r\n" ++
            "\x1b_Ga=d,d=i,i=1,q=2\x1b\\" ++
            "\x1b[?1049h\x1b_Ga=T,f=32,s=1,v=1,i=4,q=2;" ++ pixel_1x1 ++ "\x1b\\\x1b[?1049l" ++
            "\x1b_Ga=d,d=I,i=2,q=2\x1b\\" ++
            "\x1b_Ga=T,f=32,s=1,v=1,i=8,m=1,q=2;/wAA\x1b\\\x1b_Gm=0;/w==\x1b\\" ++
            "\x1b_Ga=T,f=32,s=1,v=1,i=10;" ++ pixel_1x1 ++ "\x1b\\\x1b_Ga=d,d=a\x1b\\" ++
            "\x1b_Ga=t,f=32,s=1,v=1,i=11,m=1,q=2;/wAA\x1b\\" },
    } },
    .{ "resizes", &.{
        .{ .out = "a long line that wraps around the edge twice over\r\nshort\r\n\x1b[1;31mstyled wrapped text here\x1b[0m" },
        .{ .resize = .{ .cols = 12, .rows = 6 } },
        .{ .out = "more\r\n" },
        .{ .resize = .{ .cols = 30, .rows = 4 } },
        .{ .out = "\x1b[?1049halt screen text\x1b[3;3H\x1b[?2026h" },
        .{ .resize = .{ .cols = 15, .rows = 8, .cell_size_px = .{ .width = 9, .height = 18 } } },
        .{ .out = "in alt\x1b[?1049l\u{4E2D}\u{4E2D}\u{4E2D}\u{4E2D}\u{4E2D}\u{4E2D}\u{4E2D}\u{4E2D}" },
        .{ .resize = .{ .cols = 20, .rows = 6 } },
        .{ .out = "\x1b[?7lno wrap mode text longer than line\x1b[?7h\x1b[2;4r" },
        .{ .resize = .{ .cols = 9, .rows = 6 } },
        .{ .out = "\x1b[?2048h\x1b]133;A\x07$ prompt" },
        .{ .resize = .{ .cols = 9, .rows = 6, .cell_size_px = .{ .width = 8, .height = 16 } } },
        .{ .resize = .{ .cols = 20, .rows = 3 } },
        .{ .out = "end" },
    } },
};

test "a replica restored at every cut point matches the primary" {
    testing.log_level = .err;
    for (corpora) |corpus| try checkEveryCut(corpus[0], corpus[1], .{ .leak_check = false });
}

test "a replica matches a primary without effect callbacks" {
    // A read-only primary, so the effects can't be hiding anything.
    testing.log_level = .err;
    for (corpora) |corpus| {
        const atoms = try flatten(corpus[1]);
        defer gpa.free(atoms);
        var at: usize = 0;
        while (at <= atoms.len) : (at += 11) {
            try checkCut(atoms, .{ .name = corpus[0], .at = at, .seed = at }, .{ .effects = false });
        }
    }
}

test "only the primary answers queries" {
    testing.log_level = .err;
    const queries = corpora[15];
    try testing.expectEqualStrings("queries", queries[0]);

    const a = try createPrimary(.{});
    defer a.destroy();
    const before = Effects.replies;
    try a.output(queries[1][0].out);
    try testing.expect(Effects.replies > before);

    // The replica has no callbacks at all, so it can't reply or fire an
    // effect.
    const m = try restore(a);
    defer m.destroy();
    try testing.expect(std.meta.eql(Handler.Effects.readonly, m.stream.handler.effects));
}

test "a replica loads Kitty images only from inline data" {
    // Whatever the primary allows, on screens restored from the snapshot
    // and on one the replica creates later.
    for ([_][]const u8{ "\x1b[?1049h\x1b[?1049l", "" }) |before| {
        const a = try createPrimary(.{});
        defer a.destroy();
        a.terminal.setKittyGraphicsLoadingLimits(.allWithTempDir("/tmp"));
        try a.output(before);
        const m = try restore(a);
        defer m.destroy();
        try a.output("\x1b[?1049h");
        try catchUp(m, a);

        var it = m.terminal.screens.all.iterator();
        var screens: usize = 0;
        while (it.next()) |entry| : (screens += 1) {
            const limits = entry.value.*.kitty_images.image_limits;
            try testing.expect(!limits.file and !limits.shared_memory and limits.temporary_file == .disabled);
        }
        try testing.expectEqual(2, screens);
    }
}

test "the same bytes in different records reach the same state" {
    testing.log_level = .err;
    for (corpora) |corpus| {
        const atoms = try flatten(corpus[1]);
        defer gpa.free(atoms);

        var expected: ?Expected = null;
        defer if (expected) |e| e.deinit();
        // One record per step, records of up to 4 KiB, and random sizes.
        for ([_]usize{ 4096, 1, 3, 17, 4096 }, 0..) |max_chunk, seed| {
            var prng: std.Random.DefaultPrng = .init(seed);
            const a = try createPrimary(.{});
            defer a.destroy();
            if (seed == 0) {
                for (corpus[1]) |step| switch (step) {
                    .out => |bytes| try a.output(bytes),
                    .resize => |r| try a.resize(r),
                };
            } else {
                try feed(a, atoms, prng.random(), max_chunk);
            }
            const got: Expected = try .of(&a.terminal, &a.stream);
            if (expected) |e| {
                defer got.deinit();
                if (!std.mem.eql(u8, e.dump, got.dump)) {
                    reportDiff(.{ .name = corpus[0], .at = atoms.len, .seed = seed }, atoms.len, e.dump, got.dump);
                    return error.Diverged;
                }
                try testing.expectEqualDeep(e.continuation, got.continuation);
            } else expected = got;
        }
    }
}

test "a replica applies records in order only" {
    const a = try createPrimary(.{});
    defer a.destroy();
    try a.output("one");
    const m = try restore(a);
    defer m.destroy();
    try a.output("two");
    try a.resize(.{ .cols = 30, .rows = 5 });
    try a.output("three");

    const before: Expected = try .of(&m.terminal, &m.stream);
    defer before.deinit();
    // A record it already has, one past a gap, and one far ahead are all
    // refused without touching the terminal.
    try testing.expectError(error.OutOfOrder, m.apply(try a.log.get(0)));
    try testing.expectError(error.OutOfOrder, m.apply(try a.log.get(2)));
    try testing.expectError(error.OutOfOrder, m.apply(.{ .seq = 99, .payload = .{ .output = "x" } }));
    try testing.expectEqual(1, m.next_seq);
    try compare(before, m, .{ .name = "out of order", .at = 0, .seed = 0 }, 0, .{});

    try m.apply(try a.log.get(1));
    try testing.expectError(error.OutOfOrder, m.apply(try a.log.get(1)));
    try catchUp(m, a);
    try testing.expectEqual(4, m.next_seq);
    const expected: Expected = try .of(&a.terminal, &a.stream);
    defer expected.deinit();
    try compare(expected, m, .{ .name = "in order", .at = 0, .seed = 0 }, 0, .{});
}

test "a replica that falls behind a trimmed log resyncs from a snapshot" {
    const a: *Primary = try .create(gpa, io, .{
        .cols = 20,
        .rows = 4,
        .kitty_image_storage_limit = kitty_limit,
        .log_capacity = 8 * (log.Log.record_overhead + 64),
    });
    defer a.destroy();
    try a.output("before");
    const m = try restore(a);
    defer m.destroy();

    // More than the ring holds, so the replica's next record is dropped.
    for (0..100) |i| {
        var buf: [32]u8 = undefined;
        try a.output(try std.fmt.bufPrint(&buf, "line {d}\r\n", .{i}));
    }
    try testing.expect(a.log.firstSeq() > m.next_seq);
    try testing.expectError(error.Trimmed, a.log.iterator(m.next_seq));
    try testing.expectError(error.Trimmed, a.log.get(m.next_seq));

    const resynced = try restore(a);
    defer resynced.destroy();
    try a.output("\x1b[1mafter");
    try catchUp(resynced, a);
    const expected: Expected = try .of(&a.terminal, &a.stream);
    defer expected.deinit();
    try compare(expected, resynced, .{ .name = "resync", .at = 0, .seed = 0 }, 0, .{});
}

/// Random scripts mixing all of the above, cut and chunked at random.
const fragments = [_][]const u8{
    "hello",
    " world ",
    "\r\n",
    "the quick brown fox jumps",
    "\t",
    "\x08",
    "\x1b[1;31m",
    "\x1b[0m",
    "\x1b[38;5;99;48;2;1;2;3m",
    "\x1b[4:3;58;5;4m",
    "\u{4E2D}\u{6587}",
    "e\u{301}",
    "\u{1F469}\u{200D}\u{1F4BB}",
    "\u{1F1FA}\u{1F1F8}",
    "\x1b[?1049h",
    "\x1b[?1049l",
    "\x1b[?47h",
    "\x1b[?47l",
    "\x1b[?1047h",
    "\x1b[?1047l",
    "\x1b7",
    "\x1b8",
    "\x1b[>1u",
    "\x1b[>5u",
    "\x1b[<u",
    "\x1b[=3;2u",
    "\x1b[?2026h",
    "\x1b[?2026l",
    "\x1b[2;4r",
    "\x1b[r",
    "\x1b[?6h",
    "\x1b[?6l",
    "\x1b[4h",
    "\x1b[4l",
    "\x1b]4;3;rgb:10/20/30\x1b\\",
    "\x1b]104\x07",
    // Links have IDs: see "an implicit hyperlink is renumbered...".
    "\x1b]8;id=x;https://x.example\x1b\\",
    "\x1b]8;id=k;https://k.example\x07",
    "\x1b]8;;\x1b\\",
    "\x1b]2;title\x07",
    "\x1b]0;\u{1F600}\x1b\\",
    "\x1b]7;file://h/p\x1b\\",
    "\x1bH",
    "\x1b[3g",
    "\x1b[0g",
    "\x1b(0",
    "\x1b(B",
    "\x1b)0\x0e",
    "\x0f",
    "\x1b[H",
    "\x1b[3;7H",
    "\x1b[2J",
    "\x1b[K",
    "\x1b[1J",
    "\x1b[2L",
    "\x1b[M",
    "\x1b[3@",
    "\x1b[2P",
    "\x1bM",
    "\x1b[2S",
    "\x1b[T",
    "\x1b[5b",
    "\x1b[?2027l",
    "\x1b[?2027h",
    // Wraparound is never left off across a resize: see "a resize without
    // reflow drops wrap flags...".
    "\x1b[?7lthe end of the line is overwritten\x1b[?7h",
    "\x1b]133;A\x07",
    "\x1b]133;C\x07",
    "\x1b[1\"q",
    "\x1b[0\"q",
    "\x1b[?2004h",
    "\x1b[?1003h\x1b[?1006h",
    "\x1b[5 q",
    "\x1b[!p",
    "\x1b#8",
    // Images and placements all have IDs, so the automatic ID counters
    // never move: see "Kitty ID counters are lost with the last image".
    "\x1b_Ga=T,f=32,s=1,v=1,i=3,p=1,q=2;" ++ pixel_1x1 ++ "\x1b\\",
    "\x1b_Ga=T,f=32,s=2,v=2,i=4,p=1,q=2;" ++ pixels_2x2 ++ "\x1b\\",
    "\x1b_Ga=p,i=3,p=2,c=2,r=1,q=2\x1b\\",
    // A chunked load, finished or left in progress. A lone last chunk would
    // be a transmission without an ID.
    "\x1b_Ga=t,f=32,s=1,v=1,i=6,m=1,q=2;/wAA\x1b\\\x1b_Gm=0;/w==\x1b\\",
    "\x1b_Ga=T,f=32,s=1,v=1,i=7,p=1,m=1,q=2;/wAA\x1b\\",
    "\x1b_Ga=d,d=i,i=3,q=2\x1b\\",
    "\x1b_Ga=d,q=2\x1b\\",
    "\x1b[c\x1b[6n",
    "\x1bc",
};

/// A random script for a terminal `cols` wide. The alternate screen is
/// never widened: see "a resize without reflow drops wrap flags...".
fn randomScript(rng: std.Random, cols: u16, steps: *std.ArrayList(Step)) !void {
    var width = cols;
    var alternate = false;
    const count = rng.intRangeAtMost(usize, 20, 80);
    for (0..count) |_| {
        if (rng.uintLessThan(u8, 12) == 0) {
            width = if (alternate) rng.intRangeAtMost(u16, @min(4, width), width) else rng.intRangeAtMost(u16, 4, 30);
            try steps.append(gpa, .{ .resize = .{
                .cols = width,
                .rows = rng.intRangeAtMost(u16, 2, 10),
                .cell_size_px = if (rng.boolean()) .{ .width = 8, .height = 16 } else null,
            } });
        } else {
            const fragment = fragments[rng.uintLessThan(usize, fragments.len)];
            try steps.append(gpa, .{ .out = fragment });
            if (std.mem.startsWith(u8, fragment, "\x1b[?1049") or
                std.mem.startsWith(u8, fragment, "\x1b[?1047") or
                std.mem.startsWith(u8, fragment, "\x1b[?47"))
            {
                alternate = fragment[fragment.len - 1] == 'h';
            } else if (std.mem.eql(u8, fragment, "\x1bc")) alternate = false;
        }
    }
}

test "random scripts, chunkings and cut points" {
    testing.log_level = .err;
    for (0..40) |script_seed| {
        var prng: std.Random.DefaultPrng = .init(0x7478 + script_seed);
        const rng = prng.random();
        const cols = rng.intRangeAtMost(u16, 4, 30);
        const rows = rng.intRangeAtMost(u16, 2, 10);
        var steps: std.ArrayList(Step) = .empty;
        defer steps.deinit(gpa);
        try randomScript(rng, cols, &steps);
        const atoms = try flatten(steps.items);
        defer gpa.free(atoms);

        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "random script {d}", .{script_seed});
        for (0..8) |_| {
            const cut: Cut = .{ .name = name, .at = rng.uintAtMost(usize, atoms.len), .seed = rng.int(u64) };
            try checkCut(atoms, cut, .{
                .cols = cols,
                .rows = rows,
                .max_chunk = rng.intRangeAtMost(usize, 1, 64),
                .effects = rng.boolean(),
                .leak_check = false,
            });
        }
    }
}

// Known divergences: libghostty-vt limitations these tests found. Each is
// a minimal script whose cut still diverges. Once one stops diverging, its
// test fails, so the script can move into the corpora.

/// Check that a cut at `at` still diverges, then skip.
fn expectKnownDivergence(name: []const u8, steps: []const Step, at: usize, config: Config) !void {
    testing.log_level = .err;
    const atoms = try flatten(steps);
    defer gpa.free(atoms);
    var quiet = config;
    quiet.report = false;
    checkCut(atoms, .{ .name = name, .at = at, .seed = 0 }, quiet) catch |err| switch (err) {
        error.Diverged => return error.SkipZigTest,
        else => return err,
    };
    std.debug.print("{s} no longer diverges\n", .{name});
    return error.TestUnexpectedResult;
}

test "pending wrap at a right margin is lost" {
    // With left and right margins (DECLRMM, DECSLRM), printing up to the
    // right margin sets pending wrap there, so the next character wraps to
    // the next line. The snapshot decoder keeps pending wrap only in the
    // last column (snapshot/screen.zig: "pending_wrap = ... and
    // x == cols - 1"), so the restored cursor overwrites the margin column
    // instead. The saved cursor has the same rule.
    const script = "\x1b[?69h\x1b[1;4s\x1b[1;1Habcd";
    try expectKnownDivergence("pending wrap at a right margin", out(script ++ "e"), script.len, .{});
}

test "Kitty ID counters are lost with the last image" {
    // A screen's Kitty storage, including its next automatic image and
    // placement IDs, is only in the snapshot while the screen has an image
    // or a load in progress. Here a transmission without an ID takes the
    // next automatic ID and then fails (too few pixels), leaving no image,
    // so the restored replica starts its counter over and gives the next
    // such image another ID. Deleting the last image does the same.
    const script = "\x1b_Ga=T,f=32,s=2,v=2,q=2;" ++ pixel_1x1 ++ "\x1b\\";
    try expectKnownDivergence(
        "Kitty image ID counter",
        out(script ++ "\x1b_Ga=T,f=32,s=1,v=1,q=2;" ++ pixel_1x1 ++ "\x1b\\"),
        script.len,
        .{},
    );
}

test "Glyph Protocol registrations are not in the snapshot" {
    // Terminal.glyph_glossary is not encoded, so a replica restored after a
    // registration renders the codepoint with the font instead of the
    // registered glyph.
    const script = "\x1b_25a1;r;cp=e0a0;AAAAAAAAAAAAAA==\x1b\\";
    try expectKnownDivergence("glyph registration", out(script ++ "\u{E0A0}"), script.len, .{});
}

test "a Kitty drag and drop registration is not in the snapshot" {
    // Terminal.kitty_dnd (OSC 72) is not encoded, so a replica restored
    // after a program registered to accept drops doesn't know it does.
    const script = "\x1b]72;t=a;text/plain\x1b\\";
    try expectKnownDivergence("drag and drop registration", out(script ++ "x"), script.len, .{});
}

test "scrollback is pruned at different rows after a restore" {
    // Scrollback past its limit is pruned a whole page at a time. A
    // restored page has room for exactly the rows it holds (the snapshot
    // PAGE header carries the used rows, not the row capacity), so after a
    // restore the replica's later rows land on pages that start and end at
    // other rows than the primary's, and pruning drops a different
    // number of the oldest rows. The screen itself still matches; only the
    // depth of history differs. Byte limits prune by page the same way.
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    for (0..600) |i| try buf.writer.print("line {d} of scrollback\r\n", .{i});
    try expectKnownDivergence("scrollback pruning", &.{.{ .out = buf.written() }}, 0, .{
        .cols = 400,
        .rows = 4,
        .max_scrollback_lines = 100,
        .max_chunk = 4096,
        .checkpoints = 1,
        .leak_check = false,
    });
}

test "an implicit hyperlink is renumbered when the cursor changes page" {
    // A hyperlink without an id= gets the screen's next implicit ID. When
    // the cursor moves onto another page while such a link is open, the
    // link is started again on the new page (Screen.cursorChangePin), which
    // takes a new implicit ID. A restored page has room for exactly its
    // rows, so the replica's cursor changes page on the first scroll where
    // the primary's doesn't, and the rest of the link gets another ID.
    const script = "\x1b]8;;https://a.example\x1b\\";
    try expectKnownDivergence("implicit hyperlink ID", out(script ++ "\x1b[6;1Hlink\r\nmore"), script.len, .{});
}

test "a resize without reflow drops wrap flags on a restored page" {
    // The alternate screen never reflows, and neither does the primary
    // with wraparound off. Narrowing such a screen leaves its pages as
    // wide as they were, and widening it back within that width keeps the
    // rows' soft-wrap flags; widening past it moves the rows to wider
    // pages, which drops the flags. A restored page is exactly as wide as
    // the screen was at the cut, so after a narrowing, a restore and a
    // widening, the replica has dropped flags that the primary kept.
    const steps: []const Step = &.{
        .{ .out = "\x1b[?1049ha line that wraps on the alternate screen" },
        .{ .resize = .{ .cols = 10, .rows = 6 } },
        .{ .resize = .{ .cols = 20, .rows = 6 } },
    };
    try expectKnownDivergence("wrap flags on widening", steps, steps[0].out.len + 1, .{});
}
