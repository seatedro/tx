//! VT output that brings a terminal in its initial state to a primary
//! terminal's state. The server sends it to a client attaching to a
//! running session.
//!
//! libghostty-vt's formatter writes each screen's cells, and the cursor,
//! pen, hyperlink, protection and charsets. The rest is written here: the
//! inactive screen, modes, saved modes, the saved cursor, the Kitty
//! keyboard stack, the cursor shape, colors, the title and the mouse shape.
//! Modes are set after the text, since some change how text is laid out.
//!
//! Not rebuilt: a pending wrap in the saved cursor, a blank cell under a
//! pending wrap (it becomes a space), a charset slot set back to UTF-8
//! (only a reset does that), the character REP repeats, semantic prompt
//! marks, Kitty images, Glyph Protocol registrations and the drag and drop
//! registration.
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

/// Writes rebuild bytes for `t`. The receiving terminal must be the size
/// of `t`, and in its initial state. The primary screen's scrollback is
/// written first, so it scrolls into the receiving terminal's.
pub fn write(w: *Writer, t: *const Terminal) Writer.Error!void {
    var r: Rebuild = .{ .w = w, .t = t, .modes = t.modes.default, .charset = .{} };
    try r.all();
}

/// Soft-wrapped rows are written as one line, which wraps again as it is
/// printed. Blank rows are kept, since they set where later rows land.
const format_options: vt.formatter.Options = .{ .emit = .vt, .unwrap = true, .trim = false };

const Rebuild = struct {
    w: *Writer,
    t: *const Terminal,
    /// The modes the receiving terminal has, as far as written.
    modes: ModePacked,
    /// The receiving terminal's charsets, as far as written. Switching
    /// screens carries them over.
    charset: CharsetState,
    /// The receiving terminal's cursor writes protected cells. Switching
    /// screens carries that over too.
    protected: bool = false,

    fn all(r: *Rebuild) Writer.Error!void {
        const t = r.t;

        // Grapheme clustering changes how wide some text is, so it has to
        // be on while the text is printed.
        if (t.modes.get(.grapheme_cluster)) try r.setMode(.grapheme_cluster, true);

        // An alternate screen the program left keeps its cells, which mode
        // 47 shows again. Entering with 47 doesn't clear them.
        if (t.screens.active_key == .primary and t.screens.get(.alternate) != null) {
            try r.w.writeAll("\x1b[?47h");
            try r.text(.alternate);
            try r.savedCursor(.alternate);
            try r.cursor(.alternate, false);
            try r.w.writeAll("\x1b[?47l");
        }

        try r.text(.primary);

        // The primary screen's cursor, pen and keyboard flags are written
        // before entering the alternate screen. Mode 1049 saves that
        // cursor, as it did for the program.
        if (t.screens.active_key == .alternate) {
            if (!t.modes.get(.alt_screen_save_cursor_clear_enter)) try r.savedCursor(.primary);
            try r.cursor(.primary, false);
            try r.enterAlternate();
            try r.text(.alternate);
        }
        try r.savedCursor(t.screens.active_key);

        try r.tabstops();
        try r.allModes();
        try r.scrollingRegion();
        try r.cursor(t.screens.active_key, t.modes.get(.origin));
        try r.colors();
        try r.terminalState();

        // Written last, because it holds the receiving terminal's display
        // until the program ends the update.
        if (t.modes.get(.synchronized_output)) try r.setMode(.synchronized_output, true);
    }

    /// A screen's cells, from the top of its scrollback.
    fn text(r: *Rebuild, key: ScreenKey) Writer.Error!void {
        // Switching screens carries the cursor over. The cells are written
        // from the corner.
        try r.w.writeAll("\x1b[H");
        try r.plainPen();

        var f: ScreenFormatter = .init(r.t.screens.get(key).?, format_options);
        f.content = .{ .selection = null };
        try f.format(r.w);
    }

    /// The default pen, without protection, and a charset that maps
    /// nothing, for writing cells as they are.
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

    /// Enters the alternate screen with the mode the program used.
    fn enterAlternate(r: *Rebuild) Writer.Error!void {
        const modes = &r.t.modes;
        for ([_]Mode{ .alt_screen_save_cursor_clear_enter, .alt_screen, .alt_screen_legacy }) |mode| {
            if (modes.get(mode)) return r.setMode(mode, true);
        }
        // The alternate screen is active with none of the modes set. 1047
        // switches without saving the cursor.
        try r.w.writeAll("\x1b[?1047h");
        r.setTracked(.alt_screen, true);
    }

    /// Clears every tabstop and sets the primary's, if they differ from the
    /// defaults: one every 8 columns.
    fn tabstops(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        const default = for (0..t.cols) |x| {
            const want = x > 0 and x % 8 == 0 and x < t.cols - 1;
            if (t.tabstops.get(x) != want) break false;
        } else true;
        if (default) return;

        try r.w.writeAll("\x1b[3g");
        for (0..t.cols) |x| if (t.tabstops.get(x)) try r.w.print("\x1b[{d}G\x1bH", .{x + 1});
    }

    /// Modes that differ from the defaults, and the values XTSAVE saved.
    fn allModes(r: *Rebuild) Writer.Error!void {
        const modes = &r.t.modes;

        // XTSAVE saves the current value, so each saved value is set
        // before it. A fresh terminal's saved values are the defaults.
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

        // The mouse event and format modes that were set last decide which
        // the terminal reports in, so they are set after the others.
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

    fn setTracked(r: *Rebuild, mode: Mode, value: bool) void {
        switch (mode) {
            inline else => |m| @field(r.modes, @tagName(m)) = value,
        }
    }

    /// DECSTBM and DECSLRM. Each moves the cursor, which is placed after.
    fn scrollingRegion(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        const region = t.scrolling_region;
        if (region.top != 0 or region.bottom != t.rows - 1) try r.w.print("\x1b[{d};{d}r", .{ region.top + 1, region.bottom + 1 });
        if (region.left != 0 or region.right != t.cols - 1) try r.w.print("\x1b[{d};{d}s", .{ region.left + 1, region.right + 1 });
    }

    /// The cursor DECSC saved. Written before the modes and the scrolling
    /// region, so that its position counts from the screen's corner.
    fn savedCursor(r: *Rebuild, key: ScreenKey) Writer.Error!void {
        const saved = r.t.screens.get(key).?.saved_cursor orelse return;

        // DECSC records origin mode with the position. Setting it homes
        // the cursor, which is placed after.
        if (saved.origin) try r.setMode(.origin, true);
        try r.w.print("\x1b[{d};{d}H{f}", .{ saved.y + 1, saved.x + 1, saved.style.formatterVt() });
        if (saved.protected != r.protected) try r.setProtected(saved.protected);
        try r.charsets(saved.charset);
        try r.w.writeAll("\x1b7");

        // The cursor's own state is written later, and only where it
        // isn't the default.
        if (saved.protected) try r.setProtected(false);
        if (saved.origin) try r.setMode(.origin, false);
    }

    /// The cursor's position, pen, hyperlink, protection, charsets and
    /// shape, and the screen's Kitty keyboard flags. In origin mode, the
    /// position counts from the scrolling region's corner.
    fn cursor(r: *Rebuild, key: ScreenKey, origin: bool) Writer.Error!void {
        const s = r.t.screens.get(key).?;
        const region = r.t.scrolling_region;
        var f: ScreenFormatter = .init(s, format_options);
        f.content = .none;
        f.extra = .all;
        f.extra.kitty_keyboard = false;
        f.extra.charsets = false;
        f.extra.protection = false;
        if (origin) f.cursor_origin = .{ .x = region.left, .y = region.top };

        // The formatter reaches a pending wrap only at the screen's edge,
        // and over a blank cell it saves the cursor, replacing the saved
        // cursor written already.
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

    /// Prints the cell under the cursor again, which leaves the cursor on
    /// it with a wrap pending, at the screen's edge or at a right margin.
    /// A blank cell is printed as a space.
    fn pendingWrap(r: *Rebuild, s: *const Screen, origin: ScreenFormatter.CursorOrigin) Writer.Error!void {
        const c = &s.cursor;

        // A wide character is printed from its first column.
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

    /// Designates and invokes charsets where they differ from what was
    /// written. The formatter writes only those that differ from a fresh
    /// terminal's, which doesn't undo the saved cursor's.
    fn charsets(r: *Rebuild, want: CharsetState) Writer.Error!void {
        const have = &r.charset;
        for (std.enums.values(@FieldType(CharsetState, "gl"))) |slot| {
            const set = want.charsets.get(slot);
            if (set == have.charsets.get(slot)) continue;
            const final: u8 = switch (set) {
                .ascii => 'B',
                .british => 'A',
                .dec_special => '0',
                // No sequence designates UTF-8.
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

        // SI, SO, LS2 and LS3 invoke into GL, and LS1R, LS2R and LS3R into
        // GR.
        if (want.gl != have.gl) try r.w.writeAll(switch (want.gl) {
            .G0 => "\x0f",
            .G1 => "\x0e",
            .G2 => "\x1bn",
            .G3 => "\x1bo",
        });
        if (want.gr != have.gr) switch (want.gr) {
            // No sequence invokes G0 into GR.
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

    /// The flags at each level of the Kitty keyboard stack, bottom first.
    /// Levels above the top, left by pops, start out disabled.
    fn keyboardStack(r: *Rebuild, s: *const Screen) Writer.Error!void {
        const stack = s.kitty_keyboard;
        if (stack.flags[0].int() != 0) try r.w.print("\x1b[={d};1u", .{stack.flags[0].int()});
        for (stack.flags[1 .. @as(usize, stack.idx) + 1]) |flags| try r.w.print("\x1b[>{d}u", .{flags.int()});
    }

    /// DECSCUSR, for a shape the program chose. It sets the blink mode
    /// too, to the value the primary has.
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

    /// Palette entries the program changed, and the dynamic colors it set.
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

    /// The title, the working directory, the mouse shape, modifyOtherKeys
    /// and the status display.
    fn terminalState(r: *Rebuild) Writer.Error!void {
        const t = r.t;
        if (t.getTitle()) |title| try r.w.print("\x1b]2;{s}\x1b\\", .{title});
        if (t.getPwd()) |pwd| try r.w.print("\x1b]7;{s}\x1b\\", .{pwd});
        if (t.mouse_shape != .text) {
            var name: [32]u8 = undefined;
            const tag = @tagName(t.mouse_shape);
            _ = std.mem.replace(u8, tag, "_", "-", name[0..tag.len]);
            try r.w.print("\x1b]22;{s}\x1b\\", .{name[0..tag.len]});
        }
        if (t.flags.modify_other_keys_2) try r.w.writeAll("\x1b[>4;2m");
        if (t.status_display == .status_line) try r.w.writeAll("\x1b[1$}");
    }
};

/// Modes the rebuild sets with SM and RM. `enterAlternate` switches
/// screens. Setting 1048 saves the cursor and holds no value. DECCOLM
/// would resize the receiving terminal, whose size is the client's.
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

/// Dump lines of state the rebuild leaves out.
const not_rebuilt = [_][]const u8{"previous_char "};

/// Changes in `state.changes` the rebuild leaves out. Kitty graphics come
/// with M4. The formatter writes neither semantic prompt marks nor
/// per-cell protection, and writes the blanks before a wide character
/// that wrapped as spaces.
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

/// Feeds `input` to a terminal, rebuilds it in a fresh one, and compares
/// their dumps. Prints the lines that differ.
fn rebuilds(input: []const u8) !bool {
    var t: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer t.deinit(testing.allocator);
    var stream = t.vtStream();
    defer stream.deinit();
    stream.nextSlice(input);

    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try write(&out.writer, &t);

    var copy: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer copy.deinit(testing.allocator);
    var copy_stream = copy.vtStream();
    defer copy_stream.deinit();
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
        if (for (not_rebuilt_changes) |name| {
            if (std.mem.eql(u8, name, change[0])) break true;
        } else false) continue;
        const input = try std.mem.concat(testing.allocator, u8, &.{ state.changes_base, change[1] });
        defer testing.allocator.free(input);
        if (!try rebuilds(input)) {
            std.debug.print("rebuilding {s} failed\n", .{change[0]});
            failed = true;
        }
    }
    if (failed) return error.TestUnexpectedResult;
}

/// State that depends on the order things are rebuilt in.
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
        if (!try rebuilds(combination[1])) {
            std.debug.print("rebuilding {s} failed\n", .{combination[0]});
            failed = true;
        }
    }
    if (failed) return error.TestUnexpectedResult;
}
