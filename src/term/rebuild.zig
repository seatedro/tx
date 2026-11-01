//! Writes escape sequences that bring a terminal to the state of a ghostty-vt
//! Terminal of the same size. The receiving terminal may hold state from
//! earlier output, so the sequences reset it first. The tests rebuild each
//! change in state.changes into a second Terminal and compare the two dumps.

const std = @import("std");
const Writer = std.Io.Writer;
const vt = @import("ghostty-vt");

const Terminal = vt.Terminal;
const Screen = vt.Screen;
const Mode = vt.Mode;
const ScreenFormatter = vt.formatter.ScreenFormatter;
const ModePacked = vt.modes.ModePacked;
const CharsetState = Screen.CharsetState;
const ScreenKey = vt.ScreenSet.Key;
const MouseEvent = @FieldType(@FieldType(Terminal, "flags"), "mouse_event");
const MouseFormat = @FieldType(@FieldType(Terminal, "flags"), "mouse_format");

pub const Kind = enum {
    /// Moves the receiving terminal's screen into its scrollback and writes
    /// each screen in full, scrollback included.
    attach,
    /// Resets both of the receiving terminal's screens and writes only their
    /// active areas, keeping the scrollback it already has.
    repaint,
};

/// Writes the sequences that bring a terminal of t's size to t's state.
pub fn write(w: *Writer, t: *const Terminal, kind: Kind) Writer.Error!void {
    var r: Rebuild = .{ .w = w, .t = t, .kind = kind, .modes = t.modes.default, .charset = .{} };
    try r.all();
}

/// Modes DECSTR leaves as they are, which reset() turns off after it.
const reset_modes = [_]Mode{
    .reverse_colors,
    .mouse_event_x10,
    .mouse_event_normal,
    .mouse_event_button,
    .mouse_event_any,
    .focus_event,
    .mouse_format_utf8,
    .mouse_format_sgr,
    .mouse_format_urxvt,
    .mouse_format_sgr_pixels,
    .bracketed_paste,
    .report_color_scheme,
    .in_band_size_reports,
    .kitty_paste_events,
};

/// unwrap leaves out the line break after a soft-wrapped row, so the receiving
/// terminal wraps the text again and marks the row wrapped. trim = false keeps
/// trailing blank cells and rows, which are part of the layout.
const format_options: vt.formatter.Options = .{ .emit = .vt, .unwrap = true, .trim = false };

const Rebuild = struct {
    w: *Writer,
    t: *const Terminal,
    kind: Kind,
    /// The modes the receiving terminal has, taken to be t's defaults after
    /// reset().
    modes: ModePacked,
    /// The receiving terminal's charsets. A screen switch carries them to the
    /// other screen, so one copy covers both.
    charset: CharsetState,
    /// Whether the receiving terminal's pen writes protected cells (DECSCA).
    protected: bool = false,

    fn all(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        try r.reset();

        // Mode 2027 decides how the text below is split into cells.
        if (t.modes.get(.grapheme_cluster)) try r.setMode(.grapheme_cluster, true);

        // An inactive alternate screen keeps its text and cursor. Mode 47
        // switches screens without clearing either one or saving the cursor.
        if (t.screens.active_key == .primary and t.screens.get(.alternate) != null) {
            try r.w.writeAll("\x1b[?47h");
            try r.text(.alternate);
            try r.savedCursor(.alternate);
            try r.cursor(.alternate, false);
            try r.w.writeAll("\x1b[?47l");
        }

        try r.text(.primary);

        if (t.screens.active_key == .alternate) {
            // Entering with 1049 saves the primary screen's cursor, which
            // gives the primary screen its saved cursor the way it did in t.
            if (!t.modes.get(.alt_screen_save_cursor_clear_enter)) try r.savedCursor(.primary);
            try r.cursor(.primary, false);
            try r.enterAlternate();
            try r.text(.alternate);
        }
        try r.savedCursor(t.screens.active_key);

        // DECSLRM needs mode 69, and resetting mode 69 clears the left and
        // right margins, so the margins follow the modes. Setting margins
        // homes the cursor, which goes after them. Origin mode is set by
        // then if t has it, and the cursor's CUP counts from the margins.
        try r.tabstops();
        try r.allModes();
        try r.scrollingRegion();
        try r.cursor(t.screens.active_key, t.modes.get(.origin));
        try r.colors();
        try r.terminalState();

        if (t.modes.get(.synchronized_output)) try r.setMode(.synchronized_output, true);
    }

    fn reset(r: *Rebuild) Writer.Error!void {
        try r.w.writeAll("\x1b[?2026l");

        // Leave the alternate screen, whichever mode entered it.
        try r.w.writeAll("\x1b[?1049l\x1b[?1047l\x1b[?47l");

        // Kitty keyboard flags belong to each screen, and DECSTR resets the
        // pen, charsets and saved cursor of the active screen only. A repaint
        // resets them on the alternate screen as well, and leaving it with
        // 1047 clears it. Popping more entries than the keyboard stack holds
        // (8 in Ghostty) empties it.
        if (r.kind == .repaint) try r.w.writeAll("\x1b[?1047h\x1b[<99u\x1b[!p\x1b[?1047l");
        try r.w.writeAll("\x1b[<99u");

        // DECSTR, then the modes it leaves, then LNM (ANSI mode 20).
        try r.w.writeAll("\x1b[!p");
        for (reset_modes) |mode| try r.setMode(mode, false);
        try r.w.writeAll("\x1b[20l");

        // DECSTR keeps the dynamic colors, title, pwd, mouse shape and open
        // hyperlink. OSC 110-112 reset the colors, and the empty OSC 2, 7,
        // 22 and 8 clear the rest.
        try r.w.writeAll("\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\\x1b]2;\x1b\\\x1b]7;\x1b\\\x1b]22;\x1b\\\x1b]8;;\x1b\\");

        // TBC and an HTS every 8 columns give Ghostty's default tabstops,
        // which tabstops() leaves alone when t has them.
        try r.w.writeAll("\x1b[3g");
        var x: usize = 8;
        while (x < r.t.cols - 1) : (x += 8) try r.w.print("\x1b[{d}G\x1bH", .{x + 1});

        // ED 22, a kitty extension, moves the screen into the scrollback.
        try r.w.writeAll(switch (r.kind) {
            .attach => "\x1b[22J\x1b[2J\x1b[H",
            .repaint => "\x1b[2J\x1b[H",
        });
    }

    fn text(r: *Rebuild, key: ScreenKey) Writer.Error!void {
        try r.w.writeAll("\x1b[H");
        try r.plainPen();

        const s = r.t.screens.get(key).?;
        var f: ScreenFormatter = .init(s, format_options);
        // A null selection covers the screen and its scrollback.
        f.content = .{ .selection = switch (r.kind) {
            .attach => null,
            .repaint => .init(s.pages.getTopLeft(.active), s.pages.getBottomRight(.active).?, false),
        } };
        try f.format(r.w);
    }

    /// Resets the pen, protection and charsets, so the formatter's text lands
    /// in cells as written.
    fn plainPen(r: *Rebuild) Writer.Error!void {
        try r.w.writeAll("\x1b[0m");
        if (r.protected) try r.setProtected(false);
        if (r.charset.gl != .G0) try r.w.writeAll("\x0f");
        r.charset.gl = .G0;
        switch (r.charset.charsets.get(.G0)) {
            .utf8, .ascii => {},
            else => {
                try r.w.writeAll("\x1b(B");
                r.charset.charsets.set(.G0, .ascii);
            },
        }
    }

    fn enterAlternate(r: *Rebuild) Writer.Error!void {
        const modes = &r.t.modes;
        for ([_]Mode{ .alt_screen_save_cursor_clear_enter, .alt_screen, .alt_screen_legacy }) |mode| {
            if (modes.get(mode)) return r.setMode(mode, true);
        }
        try r.w.writeAll("\x1b[?1047h");
        r.setTracked(.alt_screen, true);
    }

    fn tabstops(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        // Ghostty's default has a stop every 8 columns, short of the last.
        const default = for (0..t.cols) |x| {
            const want = x > 0 and x % 8 == 0 and x < t.cols - 1;
            if (t.tabstops.get(x) != want) break false;
        } else true;
        if (default) return;

        try r.w.writeAll("\x1b[3g");
        for (0..t.cols) |x| if (t.tabstops.get(x)) try r.w.print("\x1b[{d}G\x1bH", .{x + 1});
    }

    fn allModes(r: *Rebuild) Writer.Error!void {
        const modes = &r.t.modes;

        // XTSAVE (CSI ? n s) saves DEC private modes only. A saved value
        // that differs from the default is set and saved here, and the loop
        // below sets the current values.
        inline for (@typeInfo(Mode).@"enum".field_values) |value| {
            const mode: Mode = comptime @fromBackingInt(value);
            const tag: vt.modes.ModeTag = comptime .fromMode(mode);
            if (comptime !tag.ansi and replayable(mode)) {
                const saved = getPacked(&modes.saved, mode);
                if (saved != getPacked(&modes.default, mode)) {
                    if (getPacked(&r.modes, mode) != saved) try r.setMode(mode, saved);
                    try r.w.print("\x1b[?{d}s", .{tag.value});
                }
            }
        }

        // Setting or resetting a mouse event mode changes flags.mouse_event,
        // and a mouse format mode flags.mouse_format. The modes the flags
        // name go last, so the flags end up as in t. The loop leaves out
        // synchronized_output and grapheme_cluster, which all() sets.
        const flags = r.t.flags;
        const event = eventMode(flags.mouse_event);
        const format = formatMode(flags.mouse_format);
        inline for (@typeInfo(Mode).@"enum".field_values) |value| {
            const mode: Mode = comptime @fromBackingInt(value);
            if (comptime replayable(mode) and mode != .synchronized_output and mode != .grapheme_cluster) {
                if (mode != event and mode != format) try r.restoreMode(mode);
            }
        }
        if (event) |mode| try r.restoreMode(mode);
        if (format) |mode| try r.restoreMode(mode);
    }

    fn restoreMode(r: *Rebuild, mode: Mode) Writer.Error!void {
        const want = r.t.modes.get(mode);
        if (getPacked(&r.modes, mode) != want) try r.setMode(mode, want);
    }

    fn setMode(r: *Rebuild, mode: Mode, value: bool) Writer.Error!void {
        const tag: vt.modes.ModeTag = .fromMode(mode);
        try r.w.print("\x1b[{s}{d}{s}", .{ if (tag.ansi) "" else "?", tag.value, if (value) "h" else "l" });
        r.setTracked(mode, value);
    }

    /// Records a mode change in the receiving terminal without writing it.
    fn setTracked(r: *Rebuild, mode: Mode, value: bool) void {
        switch (mode) {
            inline else => |m| @field(r.modes, @tagName(m)) = value,
        }
    }

    fn scrollingRegion(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        const region = t.scrolling_region;
        // DECSTBM, then DECSLRM.
        if (region.top != 0 or region.bottom != t.rows - 1) try r.w.print("\x1b[{d};{d}r", .{ region.top + 1, region.bottom + 1 });
        if (region.left != 0 or region.right != t.cols - 1) try r.w.print("\x1b[{d};{d}s", .{ region.left + 1, region.right + 1 });
    }

    /// Puts the receiving terminal's cursor in the saved cursor's state and
    /// saves it with DECSC. Protection and origin mode are turned off again
    /// after the save.
    fn savedCursor(r: *Rebuild, key: ScreenKey) Writer.Error!void {
        const saved = r.t.screens.get(key).?.saved_cursor orelse return;

        // DECSC saves origin mode. Setting it homes the cursor, so it goes
        // before CUP. The margins are the full screen until
        // scrollingRegion(), so CUP is absolute here.
        if (saved.origin) try r.setMode(.origin, true);
        try r.w.print("\x1b[{d};{d}H{f}", .{ saved.y + 1, saved.x + 1, saved.style.formatterVt() });
        if (saved.protected != r.protected) try r.setProtected(saved.protected);
        try r.charsets(saved.charset);
        try r.w.writeAll("\x1b7");

        if (saved.protected) try r.setProtected(false);
        if (saved.origin) try r.setMode(.origin, false);
    }

    /// Writes the screen's cursor position, pen, hyperlink, protection,
    /// charsets, kitty keyboard flags and cursor shape. With origin set, the
    /// position counts from the margins.
    fn cursor(r: *Rebuild, key: ScreenKey, origin: bool) Writer.Error!void {
        const s = r.t.screens.get(key).?;
        const region = r.t.scrolling_region;
        var f: ScreenFormatter = .init(s, format_options);
        f.content = .none;
        // The formatter writes only the top of the keyboard stack, and writes
        // protection and charsets only where they differ from a fresh
        // terminal. The calls below write them against what the receiving
        // terminal has.
        f.extra = .all;
        f.extra.kitty_keyboard = false;
        f.extra.charsets = false;
        f.extra.protection = false;
        if (origin) f.cursor_origin = .{ .x = region.left, .y = region.top };

        if (s.cursor.pending_wrap) {
            try r.pendingWrap(s, f.cursor_origin);
            f.extra.cursor = false;
        }
        try f.format(r.w);

        if (s.cursor.protected != r.protected) try r.setProtected(s.cursor.protected);
        try r.charsets(s.charset);
        try r.keyboardStack(s);
        try r.cursorShape(s);
    }

    /// CUP clears pending wrap. Printing the cell under the cursor again sets
    /// it, wherever the right margin is. The formatter's own version works
    /// only at the last column, and over a blank cell it replaces the saved
    /// cursor.
    fn pendingWrap(r: *Rebuild, s: *const Screen, origin: ScreenFormatter.CursorOrigin) Writer.Error!void {
        const c = &s.cursor;

        // A wide character is printed from its first cell.
        const x = if (c.page_cell.wide == .spacer_tail) c.x - 1 else c.x;
        try r.w.print("\x1b[{d};{d}H", .{ (c.y -| origin.y) + 1, (x -| origin.x) + 1 });
        try r.plainPen();

        if (!c.page_cell.hasText()) return r.w.writeByte(' ');
        var f: vt.formatter.PageFormatter = .init(c.page_pin.node.page(), format_options);
        f.start_x = x;
        f.end_x = c.x;
        f.start_y = c.page_pin.y;
        f.end_y = c.page_pin.y;
        try f.format(r.w);
    }

    fn charsets(r: *Rebuild, want: CharsetState) Writer.Error!void {
        const have = &r.charset;
        for (std.enums.values(@FieldType(CharsetState, "gl"))) |slot| {
            const set = want.charsets.get(slot);
            if (set == have.charsets.get(slot)) continue;
            const final: u8 = switch (set) {
                .ascii => 'B',
                .british => 'A',
                .dec_special => '0',
                // No sequence designates utf8.
                .utf8 => continue,
            };
            const intermediate: u8 = switch (slot) {
                .G0 => '(',
                .G1 => ')',
                .G2 => '*',
                .G3 => '+',
            };
            try r.w.print("\x1b{c}{c}", .{ intermediate, final });
            have.charsets.set(slot, set);
        }

        if (want.gl != have.gl) try r.w.writeAll(switch (want.gl) {
            .G0 => "\x0f",
            .G1 => "\x0e",
            .G2 => "\x1bn",
            .G3 => "\x1bo",
        });
        if (want.gr != have.gr) switch (want.gr) {
            // No locking shift puts G0 in GR.
            .G0 => {},
            .G1 => try r.w.writeAll("\x1b~"),
            .G2 => try r.w.writeAll("\x1b}"),
            .G3 => try r.w.writeAll("\x1b|"),
        };
        have.gl = want.gl;
        have.gr = want.gr;
    }

    /// DECSCA.
    fn setProtected(r: *Rebuild, protected: bool) Writer.Error!void {
        try r.w.writeAll(if (protected) "\x1b[1\"q" else "\x1b[0\"q");
        r.protected = protected;
    }

    /// Rebuilds the kitty keyboard stack over an empty one. CSI = n ; 1 u sets
    /// the bottom entry, and CSI > n u pushes each entry above it.
    fn keyboardStack(r: *Rebuild, s: *const Screen) Writer.Error!void {
        const stack = s.kitty_keyboard;
        if (stack.flags[0].int() != 0) try r.w.print("\x1b[={d};1u", .{stack.flags[0].int()});
        for (stack.flags[1 .. @as(usize, stack.idx) + 1]) |flags| try r.w.print("\x1b[>{d}u", .{flags.int()});
    }

    /// Writes DECSCUSR unless the program left the cursor shape at its default,
    /// which DECSTR restores. DECSCUSR also sets mode 12 (cursor_blinking).
    /// block_hollow has no DECSCUSR number and is written as a block.
    fn cursorShape(r: *Rebuild, s: *const Screen) Writer.Error!void {
        if (r.t.cursor.is_default) return;
        const blink = r.t.modes.get(.cursor_blinking);
        const n: u8 = switch (s.cursor.cursor_style) {
            .block, .block_hollow => if (blink) 1 else 2,
            .underline => if (blink) 3 else 4,
            .bar => if (blink) 5 else 6,
        };
        try r.w.print("\x1b[{d} q", .{n});
        r.setTracked(.cursor_blinking, blink);
    }

    /// Writes the palette entries and dynamic colors the program set.
    fn colors(r: *Rebuild) Writer.Error!void {
        const c = &r.t.colors;
        var it = c.palette.mask.iterator(.{});
        while (it.next()) |i| {
            const rgb = c.palette.current[i];
            try r.w.print("\x1b]4;{d};rgb:{x:0>2}/{x:0>2}/{x:0>2}\x1b\\", .{ i, rgb.r, rgb.g, rgb.b });
        }
        for ([_]struct { u8, vt.color.DynamicRGB }{ .{ 10, c.foreground }, .{ 11, c.background }, .{ 12, c.cursor } }) |dynamic| {
            const n, const color = dynamic;
            const rgb = color.override orelse continue;
            try r.w.print("\x1b]{d};rgb:{x:0>2}/{x:0>2}/{x:0>2}\x1b\\", .{ n, rgb.r, rgb.g, rgb.b });
        }
    }

    fn terminalState(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        if (t.getTitle()) |title| try r.w.print("\x1b]2;{s}\x1b\\", .{title});
        if (t.getPwd()) |pwd| try r.w.print("\x1b]7;{s}\x1b\\", .{pwd});
        if (t.mouse_shape != .text) {
            // OSC 22 names use hyphens where the tag names have underscores.
            var name: [32]u8 = undefined;
            const tag = @tagName(t.mouse_shape);
            _ = std.mem.replace(u8, tag, "_", "-", name[0..tag.len]);
            try r.w.print("\x1b]22;{s}\x1b\\", .{name[0..tag.len]});
        }
        // modifyOtherKeys level 2, and DECSASD selecting the status line.
        if (t.flags.modify_other_keys_2) try r.w.writeAll("\x1b[>4;2m");
        if (t.status_display == .status_line) try r.w.writeAll("\x1b[1$}");
    }
};

/// False for the alternate screen modes, which switch screens, for 1048,
/// which saves or restores the cursor, and for 132_column (DECCOLM), which
/// resizes and clears the screen when mode 40 is set.
fn replayable(comptime mode: Mode) bool {
    return switch (mode) {
        .alt_screen_legacy, .alt_screen, .alt_screen_save_cursor_clear_enter, .save_cursor, .@"132_column" => false,
        else => true,
    };
}

fn getPacked(values: *const ModePacked, mode: Mode) bool {
    return switch (mode) {
        inline else => |m| @field(values, @tagName(m)),
    };
}

fn eventMode(event: MouseEvent) ?Mode {
    return switch (event) {
        .none => null,
        .x10 => .mouse_event_x10,
        .normal => .mouse_event_normal,
        .button => .mouse_event_button,
        .any => .mouse_event_any,
    };
}

fn formatMode(format: MouseFormat) ?Mode {
    return switch (format) {
        .x10 => null,
        .utf8 => .mouse_format_utf8,
        .sgr => .mouse_format_sgr,
        .urxvt => .mouse_format_urxvt,
        .sgr_pixels => .mouse_format_sgr_pixels,
    };
}

const testing = std.testing;
const state = @import("state.zig");

/// Prefixes of dump lines a rebuild can't match. previous_char is the last
/// character the rebuild printed.
const not_rebuilt = [_][]const u8{"previous_char "};

const not_rebuilt_changes = [_][]const u8{
    "a semantic prompt",
    "a semantic click mode",
    "protected mode",
    "a kitty image",
    "a kitty placement",
    "a kitty chunked load",
    "a kitty virtual placement",
    "a kitty relative placement",
    "a kitty animation frame",
    "the kitty image ID counter",
    "a wide character split by the line end",
    "a glyph registration",
    "a drag and drop registration",
};

fn isNotRebuilt(name: []const u8) bool {
    for (not_rebuilt_changes) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

/// Rebuilds a terminal fed input into a terminal fed before, and compares the
/// two dumps, printing the lines that differ.
fn rebuilds(before: []const u8, input: []const u8, kind: Kind) !bool {
    var t: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer t.deinit(testing.allocator);
    var stream = t.vtStream();
    defer stream.deinit();
    stream.nextSlice(input);

    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try write(&out.writer, &t, kind);

    var copy: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer copy.deinit(testing.allocator);
    var copy_stream = copy.vtStream();
    defer copy_stream.deinit();
    copy_stream.nextSlice(before);
    copy_stream.nextSlice(out.written());

    const want = try state.dumpAlloc(testing.allocator, &t);
    defer testing.allocator.free(want);
    const got = try state.dumpAlloc(testing.allocator, &copy);
    defer testing.allocator.free(got);

    var same = true;
    var want_lines = std.mem.splitScalar(u8, want, '\n');
    var got_lines = std.mem.splitScalar(u8, got, '\n');
    while (true) {
        const a = want_lines.next();
        const b = got_lines.next();
        if (a == null and b == null) break;
        if (a != null and b != null and std.mem.eql(u8, a.?, b.?)) continue;
        if (a != null and b != null and for (not_rebuilt) |prefix| {
            if (std.mem.startsWith(u8, a.?, prefix) and std.mem.startsWith(u8, b.?, prefix)) break true;
        } else false) continue;
        if (same) std.debug.print("  rebuild bytes \"{f}\"\n", .{std.zig.fmtString(out.written())});
        same = false;
        std.debug.print("  want {s}\n  got  {s}\n", .{ a orelse "(end)", b orelse "(end)" });
    }
    return same;
}

test "each state change rebuilds" {
    testing.log_level = .err;
    var failed = false;
    for (state.changes) |change| {
        if (isNotRebuilt(change[0])) continue;
        const input = try std.mem.concat(testing.allocator, u8, &.{ state.changes_base, change[1] });
        defer testing.allocator.free(input);
        if (!try rebuilds("", input, .attach)) {
            std.debug.print("rebuilding {s} failed\n", .{change[0]});
            failed = true;
        }
    }
    if (failed) return error.TestUnexpectedResult;
}

const combinations = [_]struct { []const u8, []const u8 }{
    .{ "both screens", "ab\r\n\x1b[1mcd\x1b[?1049h\x1b[3;3H\x1b[4mxy" },
    .{ "both screens with the legacy mode", "ab\x1b[?47h\x1b[2;2Hxy" },
    .{ "a charset carried into the alternate screen", "\x1b(0qq\x1b[?1049hqq" },
    .{ "the saved cursor on both screens", "\x1b[2;2H\x1b7\x1b[?47h\x1b[3;3H\x1b7\x1b[H" },
    .{ "the saved cursor in origin mode", "\x1b[2;4r\x1b[?6h\x1b[2;2H\x1b7\x1b[?6l" },
    .{ "origin mode in a scrolling region", "\x1b[2;4r\x1b[?6h\x1b[2;3Hx" },
    .{ "left and right margins", "\x1b[?69h\x1b[3;10s\x1b[1;5Hx" },
    .{ "pending wrap at the right margin", "\x1b[?69h\x1b[1;10s\x1b[1;10Hx" },
    .{ "pending wrap in insert mode", "\x1b[4h\x1b[1;20Hx" },
    .{ "autowrap off", "\x1b[?7l\x1b[1;18Hxyz" },
    .{ "the mouse mode set last", "\x1b[?1003h\x1b[?1000h\x1b[?1006h\x1b[?1005h" },
    .{ "kitty keyboard flags on both screens", "\x1b[>1u\x1b[?1049h\x1b[>3u" },
    .{ "a steady bar cursor", "\x1b[6 q" },
    .{ "a blinking block cursor", "\x1b[1 q" },
    .{ "grapheme clustering", "\x1b[?2027h\u{1F469}\u{200D}\u{1F4BB}x" },
    .{ "synchronized output", "\x1b[?2026hx" },
    .{ "the palette and dynamic colors", "\x1b]4;1;rgb:12/34/56\x1b\\\x1b]11;rgb:01/02/03\x1b\\\x1b]12;rgb:0a/0b/0c\x1b\\" },
    .{ "scrollback", "line 1\r\nline 2\r\nline 3\r\nline 4\r\nline 5\r\nline 6\r\nline 7\r\n" },
    .{ "wrapped and styled scrollback", "\x1b[31m" ++ "0123456789012345678901234567890123456789" ++ "\x1b[m\r\n\x1b]8;;https://a.example\x1b\\link\x1b]8;;\x1b\\\r\n\r\n\r\n\r\n\r\n\u{4E2D}\u{6587}" },
};

test "combined state rebuilds" {
    testing.log_level = .err;
    var failed = false;
    for (combinations) |combination| {
        if (!try rebuilds("", combination[1], .attach)) {
            std.debug.print("rebuilding {s} failed\n", .{combination[0]});
            failed = true;
        }
    }
    if (failed) return error.TestUnexpectedResult;
}

const not_reset_changes = [_][]const u8{
    "a saved mode",
    "grapheme clustering",
    "the cursor hyperlink",
};

/// Each target creates the alternate screen. A repaint's reset creates one in
/// the receiving terminal, and the dump lists every screen.
const repaint_targets = [_]struct { []const u8, []const u8 }{
    .{ "text", "\x1b[?1047h\x1b[?1047lab\r\ncd" },
    .{ "the alternate screen", "\x1b[?1047h\x1b[?1047lab\x1b[?1049h\x1b[2;2Hxy\x1b[?2004h" },
    .{ "a scrolling region in origin mode", "\x1b[?1047h\x1b[?1047lab\x1b[2;4r\x1b[?6h\x1b[2;3Hx" },
};

test "a repaint undoes the state a session left" {
    testing.log_level = .err;
    var failed = false;
    for (repaint_targets) |target| {
        for (state.changes ++ combinations) |change| {
            // A repaint keeps the receiving terminal's scrollback.
            if (isNotRebuilt(change[0]) or std.mem.indexOf(u8, change[0], "scrollback") != null) continue;
            if (for (not_reset_changes) |name| {
                if (std.mem.eql(u8, name, change[0])) break true;
            } else false) continue;
            const before = try std.mem.concat(testing.allocator, u8, &.{ state.changes_base, change[1] });
            defer testing.allocator.free(before);
            if (!try rebuilds(before, target[1], .repaint)) {
                std.debug.print("repainting {s} over {s} failed\n", .{ target[0], change[0] });
                failed = true;
            }
        }
    }
    if (failed) return error.TestUnexpectedResult;
}
