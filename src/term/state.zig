//! A canonical text dump of a Terminal's state, for checking that a mirror
//! matches its authority.
//!
//! Two terminals that will behave the same for every later byte, resize
//! and render must dump the same text, and the dump must not depend on how
//! that state is stored. So it reads values, not representation: styles
//! and hyperlinks are resolved out of the page that holds them and
//! numbered by first appearance, rows are numbered from the top of the
//! scrollback whatever pages hold them, and Kitty images are sorted by ID.
//! Process-local stamps (image generations, dirty counters) and client
//! presentation that no byte changes (viewport, animation clocks) are left
//! out.
//!
//! This walks the structures rather than using libghostty-vt's formatter.
//! The formatter covers less (the active screen, no Kitty images), and its
//! VT output isn't canonical: it tracks hyperlinks by page-local ID, so
//! the same cells on differently split pages format differently.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const vt = @import("ghostty-vt");

const Terminal = vt.Terminal;
const Screen = vt.Screen;
const Page = vt.Page;
const Style = vt.Style;

pub const Error = Allocator.Error || Writer.Error;

/// Write the dump of `t` to `w`.
pub fn dump(gpa: Allocator, w: *Writer, t: *const Terminal) Error!void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var d: Dumper = .{ .gpa = gpa, .arena = arena.allocator(), .w = w };
    try d.terminal(t);
}

/// The dump of `t`, owned by the caller.
pub fn dumpAlloc(gpa: Allocator, t: *const Terminal) Error![]u8 {
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    dump(gpa, &out.writer, t) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => |e| return e,
    };
    return out.toOwnedSlice();
}

const StyleContext = struct {
    pub fn hash(_: StyleContext, s: Style) u32 {
        return @truncate(s.hash());
    }
    pub fn eql(_: StyleContext, a: Style, b: Style, _: usize) bool {
        return a.eql(b);
    }
};

const Dumper = struct {
    gpa: Allocator,
    arena: Allocator,
    w: *Writer,
    /// Every distinct style and hyperlink, numbered by first appearance.
    styles: std.ArrayHashMapUnmanaged(Style, void, StyleContext, true) = .empty,
    links: std.StringArrayHashMapUnmanaged(void) = .empty,

    fn print(d: *Dumper, comptime fmt: []const u8, args: anytype) Error!void {
        try d.w.print(fmt, args);
    }

    /// Print any plain value field by field. Only for types without
    /// pointers or allocated lists, whose addresses and capacities
    /// aren't state.
    fn any(d: *Dumper, value: anytype) Error!void {
        try d.w.printValue("any", .{}, value, 16);
    }

    fn line(d: *Dumper, label: []const u8, value: anytype) Error!void {
        try d.print("{s} ", .{label});
        try d.any(value);
        try d.w.writeByte('\n');
    }

    fn terminal(d: *Dumper, t: *const Terminal) Error!void {
        try d.print("size {d}x{d} px {d}x{d}\n", .{ t.cols, t.rows, t.width_px, t.height_px });
        try d.line("status_display", t.status_display);
        try d.line("scrolling_region", t.scrolling_region);
        try d.print("tabstops", .{});
        for (0..t.cols) |x| if (t.tabstops.get(x)) try d.print(" {d}", .{x});
        try d.print("\ntitle \"{f}\"\npwd \"{f}\"\n", .{
            std.zig.fmtString(t.getTitle() orelse ""),
            std.zig.fmtString(t.getPwd() orelse ""),
        });
        try d.line("previous_char", t.previous_char);
        try d.line("modes", t.modes);
        try d.line("cursor_defaults", t.cursor);
        try d.line("default_xt_checksum", t.default_xt_checksum);
        try d.line("mouse_shape", t.mouse_shape);
        try d.flags(t);
        try d.colors(t);
        try d.glossary(t);
        try d.dnd(t);

        try d.line("active_screen", t.screens.active_key);
        for (std.enums.values(vt.ScreenSet.Key)) |key| {
            const s = t.screens.get(key) orelse continue;
            try d.print("screen {t}\n", .{key});
            try d.screen(s);
        }

        try d.print("styles\n", .{});
        for (d.styles.keys(), 0..) |s, i| {
            try d.print("  s{d} ", .{i});
            try d.any(s);
            try d.w.writeByte('\n');
        }
        try d.print("hyperlinks\n", .{});
        for (d.links.keys(), 0..) |link, i| {
            try d.print("  l{d} \"{f}\"\n", .{ i, std.zig.fmtString(link) });
        }
    }

    fn flags(d: *Dumper, t: *const Terminal) Error!void {
        // Every flag except the renderer's and search thread's dirty bits.
        const f = t.flags;
        try d.print("flags", .{});
        inline for (@typeInfo(@TypeOf(f)).@"struct".field_names) |name| {
            if (comptime std.mem.eql(u8, name, "dirty") or
                std.mem.eql(u8, name, "search_viewport_dirty")) continue;
            try d.print(" {s}=", .{name});
            try d.any(@field(f, name));
        }
        try d.w.writeByte('\n');
    }

    fn colors(d: *Dumper, t: *const Terminal) Error!void {
        try d.line("background", t.colors.background);
        try d.line("foreground", t.colors.foreground);
        try d.line("cursor_color", t.colors.cursor);
        // The two 256-entry tables are hashed to keep the dump short; the
        // overridden entries, which are what bytes change, are listed.
        const palette = &t.colors.palette;
        try d.print("palette original {x} current {x} overridden", .{
            paletteHash(palette.original),
            paletteHash(&palette.current),
        });
        var it = palette.mask.iterator(.{});
        while (it.next()) |i| {
            const c = palette.current[i];
            try d.print(" {d}={x:0>2}{x:0>2}{x:0>2}", .{ i, c.r, c.g, c.b });
        }
        try d.w.writeByte('\n');
    }

    fn paletteHash(palette: *const vt.color.Palette) u64 {
        var h: std.hash.Wyhash = .init(0);
        for (palette) |c| h.update(&.{ c.r, c.g, c.b });
        return h.final();
    }

    /// Glyph Protocol registrations, in their eviction order.
    fn glossary(d: *Dumper, t: *const Terminal) Error!void {
        const entries = &t.glyph_glossary.entries;
        for (entries.keys(), entries.values()) |cp, entry| {
            try d.print("glyph U+{X:0>4} ", .{cp});
            try d.any(entry);
            try d.w.writeByte('\n');
        }
    }

    /// Kitty drag and drop (OSC 72) registration.
    fn dnd(d: *Dumper, t: *const Terminal) Error!void {
        const state = t.kitty_dnd orelse return d.print("dnd none\n", .{});
        const drop = &state.drop;
        try d.print("dnd chunking ", .{});
        try d.any(state.chunking);
        try d.print(" client_id={d} registered=\"{f}\" hovered={} dropped={} accept_in_progress={} accepted_mimes=\"{f}\" accepted=", .{
            drop.client_id,
            std.zig.fmtString(drop.registered_mimes.items),
            drop.hovered,
            drop.dropped,
            drop.accept_in_progress,
            std.zig.fmtString(drop.accepted_mimes.items),
        });
        try d.any(drop.accepted);
        try d.print(" offered=", .{});
        try d.any(if (drop.offered) |o| o.mimes else null);
        try d.print(" items=", .{});
        try d.any(drop.items);
        try d.w.writeByte('\n');
    }

    fn screen(d: *Dumper, s: *const Screen) Error!void {
        try d.line("  no_scrollback", s.no_scrollback);
        const c = &s.cursor;
        try d.print("  cursor {d},{d} style={t} pending_wrap={} protected={} semantic={t} clear_eol={} implicit_link_id={d} pen ", .{
            c.x,
            c.y,
            c.cursor_style,
            c.pending_wrap,
            c.protected,
            c.semantic_content,
            c.semantic_content_clear_eol,
            c.hyperlink_implicit_id,
        });
        try d.any(c.style);
        try d.print(" link ", .{});
        if (c.hyperlink) |link| {
            try d.any(link.id);
            try d.print(" \"{f}\"", .{std.zig.fmtString(link.uri)});
        } else try d.print("none", .{});
        try d.w.writeByte('\n');
        try d.line("  saved_cursor", s.saved_cursor);
        try d.line("  charset", s.charset);
        try d.line("  protected_mode", s.protected_mode);
        try d.line("  kitty_keyboard", s.kitty_keyboard);
        // Not `semantic_prompt.seen`: libghostty-vt sets it but never reads
        // it, and the snapshot rederives it differently (a prompt cursor
        // carried onto the alternate screen counts there).
        try d.line("  semantic_click", s.semantic_prompt.click);
        if (s.selection) |sel| {
            try d.print("  selection rectangle={} ", .{sel.rectangle});
            try d.any(s.pages.pointFromPin(.screen, sel.start()));
            try d.print(" ", .{});
            try d.any(s.pages.pointFromPin(.screen, sel.end()));
            try d.w.writeByte('\n');
        }
        try d.pages(s);
        if (comptime @TypeOf(s.kitty_images) != void) try d.kitty(s);
    }

    fn pages(d: *Dumper, s: *const Screen) Error!void {
        const list = &s.pages;
        try d.print("  pages {d}x{d} total_rows={d} max_bytes={d} max_lines={d}\n", .{
            list.cols,
            list.rows,
            list.total_rows,
            list.limits.bytes.explicit,
            list.limits.lines.explicit,
        });
        var y: usize = 0;
        var node = list.pages.first;
        while (node) |n| : (node = n.next) {
            var preserved = try n.pagePreservingState(d.gpa);
            defer preserved.deinit();
            const page = preserved.page();
            for (0..page.size.rows) |row_y| {
                try d.row(page, page.getRow(row_y), y);
                y += 1;
            }
        }
    }

    fn row(d: *Dumper, page: *const Page, r: *vt.page.Row, y: usize) Error!void {
        // Only rows that differ from a blank row are written.
        var started = false;
        if (r.wrap or r.wrap_continuation or r.semantic_prompt != .none or r.kitty_virtual_placeholder) {
            try d.print("  y{d} wrap={} cont={} prompt={t} placeholder={}", .{
                y,
                r.wrap,
                r.wrap_continuation,
                r.semantic_prompt,
                r.kitty_virtual_placeholder,
            });
            started = true;
        }
        for (page.getCells(r), 0..) |*cell, x| {
            const style: Style = if (cell.style_id == 0) .{} else page.styles.get(page.memory, cell.style_id).*;
            const link: ?usize = if (cell.hyperlink) try d.cellLink(page, cell) else null;
            const blank = cell.content_tag == .codepoint and cell.content.codepoint.data == 0 and
                cell.wide == .narrow and !cell.protected and cell.semantic_content == .output and
                style.eql(.{}) and link == null;
            if (blank) continue;
            if (!started) {
                try d.print("  y{d}", .{y});
                started = true;
            }
            try d.print(" x{d}:", .{x});
            switch (cell.content_tag) {
                .codepoint, .codepoint_grapheme => {
                    try d.print("{X}", .{cell.content.codepoint.data});
                    if (cell.content_tag == .codepoint_grapheme) {
                        for (page.lookupGrapheme(cell) orelse &.{}) |cp| try d.print("+{X}", .{cp});
                    }
                },
                .bg_color_palette => try d.print("bg{d}", .{cell.content.color_palette.data}),
                .bg_color_rgb => {
                    const rgb = cell.content.color_rgb;
                    try d.print("bg{x:0>2}{x:0>2}{x:0>2}", .{ rgb.r, rgb.g, rgb.b });
                },
            }
            if (cell.wide != .narrow) try d.print("/{t}", .{cell.wide});
            if (cell.protected) try d.print("/protected", .{});
            if (cell.semantic_content != .output) try d.print("/{t}", .{cell.semantic_content});
            if (!style.eql(.{})) {
                const gop = try d.styles.getOrPut(d.arena, style);
                try d.print("/s{d}", .{gop.index});
            }
            if (link) |i| try d.print("/l{d}", .{i});
        }
        if (started) try d.w.writeByte('\n');
    }

    fn cellLink(d: *Dumper, page: *const Page, cell: *const vt.Cell) Error!usize {
        const id = page.lookupHyperlink(cell) orelse return d.internLink("missing");
        const entry = page.hyperlink_set.get(page.memory, id);
        const uri = entry.uri.slice(page.memory);
        const key = switch (entry.id) {
            .explicit => |slice| try std.fmt.allocPrint(d.arena, "id={s} {s}", .{ slice.slice(page.memory), uri }),
            .implicit => |n| try std.fmt.allocPrint(d.arena, "implicit={d} {s}", .{ n, uri }),
        };
        return d.internLink(key);
    }

    fn internLink(d: *Dumper, key: []const u8) Allocator.Error!usize {
        return (try d.links.getOrPut(d.arena, key)).index;
    }

    fn kitty(d: *Dumper, s: *const Screen) Error!void {
        const storage = &s.kitty_images;
        try d.print("  kitty next_image_id={d} next_placement_id={d} total_bytes={d} limit={d} limits=", .{
            storage.next_image_id,
            storage.next_internal_placement_id,
            storage.total_bytes,
            storage.total_limit,
        });
        try d.any(storage.image_limits);
        try d.w.writeByte('\n');

        const ids = try d.arena.alloc(u32, storage.images.count());
        var image_it = storage.images.keyIterator();
        for (ids) |*id| id.* = image_it.next().?.*;
        std.mem.sort(u32, ids, {}, std.sort.asc(u32));
        for (ids) |id| try d.image("  image", storage.images.getPtr(id).?);

        const Key = vt.kitty.graphics.ImageStorage.PlacementKey;
        const keys = try d.arena.alloc(Key, storage.placements.count());
        var placement_it = storage.placements.keyIterator();
        for (keys) |*key| key.* = placement_it.next().?.*;
        std.mem.sort(Key, keys, {}, struct {
            fn lessThan(_: void, a: Key, b: Key) bool {
                if (a.image_id != b.image_id) return a.image_id < b.image_id;
                if (a.placement_id.tag != b.placement_id.tag) return @backingInt(a.placement_id.tag) < @backingInt(b.placement_id.tag);
                return a.placement_id.id < b.placement_id.id;
            }
        }.lessThan);
        for (keys) |key| {
            const p = storage.placements.getPtr(key).?;
            try d.print("  placement ", .{});
            try d.any(key);
            try d.print(" at ", .{});
            switch (p.location) {
                .pin => |pin| try d.any(s.pages.pointFromPin(.screen, pin.*)),
                .virtual => try d.print("virtual", .{}),
                .relative => |rel| try d.any(rel),
            }
            try d.print(" offset={d},{d} source={d},{d},{d}x{d} grid={d}x{d} z={d}\n", .{
                p.x_offset,     p.y_offset,
                p.source_x,     p.source_y,
                p.source_width, p.source_height,
                p.columns,      p.rows,
                p.z,
            });
        }

        if (storage.loading) |loading| {
            try d.image("  loading", &loading.image);
            try d.print("    received {d} bytes hash {x} quiet={t} temp_dir=", .{
                loading.data.items.len,
                std.hash.Wyhash.hash(0, loading.data.items),
                loading.quiet,
            });
            try d.any(loading.temporary_directory);
            try d.print(" display ", .{});
            try d.any(loading.display);
            try d.print(" response ", .{});
            try d.any(loading.response);
            try d.print(" frame ", .{});
            // The image generation a frame load started against is a
            // process-local stamp, so only its command is state.
            try d.any(if (loading.frame) |f| f.cmd else null);
            try d.w.writeByte('\n');
        }
    }

    fn image(d: *Dumper, label: []const u8, img: *const vt.kitty.graphics.Image) Error!void {
        try d.print("{s} id={d} number={d} {d}x{d} format={t} compression={t} metadata=", .{
            label,
            img.id,
            img.number,
            img.width,
            img.height,
            img.format,
            img.compression,
        });
        try d.any(img.metadata);
        switch (img.data) {
            .complete => |bytes| try d.print(" data {d} bytes hash {x}", .{ bytes.len, std.hash.Wyhash.hash(0, bytes) }),
            .pending => |len| try d.print(" data pending {d}", .{len}),
        }
        if (img.animation) |a| {
            // When the shown frame last changed is the client's clock.
            try d.print(" animation state={t} loops={d}/{d} frame={d} root_gap={d}", .{
                a.state,
                a.current_loop,
                a.max_loops,
                a.current_index,
                a.root_gap_ms,
            });
            for (a.frames.items) |f| try d.print(" [gap={d} pending={d} hash {x}]", .{
                f.gap_ms,
                f.pending_len,
                std.hash.Wyhash.hash(0, f.data),
            });
        }
        try d.w.writeByte('\n');
    }
};

const testing = std.testing;

fn testDump(t: *const Terminal) ![]u8 {
    return dumpAlloc(testing.allocator, t);
}

/// Each entry changes one piece of state from a terminal that has already
/// been through `base`, and the dump must notice.
const changes = [_]struct { []const u8, []const u8 }{
    .{ "primary text", "x" },
    .{ "a wide character", "\u{4E2D}" },
    .{ "a grapheme cluster", "e\u{301}" },
    .{ "a ZWJ sequence", "\u{1F469}\u{200D}\u{1F4BB}" },
    .{ "a style", "\x1b[1mx" },
    .{ "a 256-color style", "\x1b[38;5;123mx" },
    .{ "a truecolor style", "\x1b[48;2;1;2;3mx" },
    .{ "a background-only cell", "\x1b[41m\x1b[K" },
    .{ "a hyperlink", "\x1b]8;id=a;https://a.example\x1b\\x" },
    .{ "the cursor pen", "\x1b[3m" },
    .{ "the cursor hyperlink", "\x1b]8;;https://b.example\x1b\\" },
    .{ "the cursor position", "\x1b[3;4H" },
    .{ "pending wrap", "\x1b[1;20Hx" },
    .{ "the cursor style", "\x1b[5 q" },
    .{ "the saved cursor", "\x1b[2;2H\x1b7" },
    .{ "a mode", "\x1b[?2004h" },
    .{ "a saved mode", "\x1b[?2004h\x1b[?2004s\x1b[?2004l" },
    .{ "insert mode", "\x1b[4h" },
    .{ "origin mode", "\x1b[?6h" },
    .{ "the alternate screen", "\x1b[?1049h" },
    .{ "legacy alternate screen", "\x1b[?47h" },
    .{ "alternate screen text", "\x1b[?1049hx\x1b[?1049l" },
    .{ "kitty keyboard push", "\x1b[>1u" },
    .{ "kitty keyboard set", "\x1b[=3u" },
    .{ "kitty keyboard stack below the top", "\x1b[>1u\x1b[>2u\x1b[<1u\x1b[=0;1u\x1b[>2u" },
    .{ "a charset", "\x1b(0" },
    .{ "the shifted charset", "\x0e" },
    .{ "a G1 charset", "\x1b)0" },
    .{ "the scrolling region", "\x1b[2;4r" },
    .{ "a tabstop set", "\x1b[1;3H\x1bH" },
    .{ "a tabstop cleared", "\x1b[1;9H\x1b[g" },
    .{ "all tabstops cleared", "\x1b[3g" },
    .{ "a palette entry", "\x1b]4;1;rgb:12/34/56\x1b\\" },
    .{ "the foreground color", "\x1b]10;rgb:12/34/56\x1b\\" },
    .{ "the title", "\x1b]2;title\x1b\\" },
    .{ "the pwd", "\x1b]7;file://host/tmp\x1b\\" },
    .{ "scrollback", "\r\n\r\n\r\n\r\n\r\n\r\n" },
    .{ "a wrapped row", "\x1b[1;20Hxy" },
    .{ "a semantic prompt", "\x1b]133;A\x1b\\" },
    .{ "protected mode", "\x1b[1\"qx" },
    .{ "mouse tracking", "\x1b[?1003h\x1b[?1006h" },
    .{ "modifyOtherKeys", "\x1b[>4;2m" },
    .{ "the previous char", "z" },
    .{ "the mouse shape", "\x1b]22;pointer\x1b\\" },
    .{ "a kitty image", "\x1b_Ga=t,f=32,s=1,v=1,i=5;AAAAAA==\x1b\\" },
    .{ "a kitty placement", "\x1b_Ga=T,f=32,s=1,v=1,i=5;AAAAAA==\x1b\\" },
    .{ "a kitty chunked load", "\x1b_Ga=t,f=32,s=1,v=1,i=5,m=1;AAAA\x1b\\" },
    .{ "a kitty virtual placement", "\x1b_Ga=t,f=32,s=1,v=1,i=5;AAAAAA==\x1b\\\x1b_Ga=p,i=5,p=2,U=1\x1b\\" },
    .{ "a kitty relative placement", "\x1b_Ga=T,f=32,s=1,v=1,i=5,p=1;AAAAAA==\x1b\\\x1b_Ga=p,i=5,p=2,P=5,Q=1,H=2\x1b\\" },
    .{ "a kitty animation frame", "\x1b_Ga=t,f=32,s=1,v=1,i=5;AAAAAA==\x1b\\\x1b_Ga=f,i=5,f=32,s=1,v=1;/wAA/w==\x1b\\" },
    .{ "the kitty image ID counter", "\x1b_Ga=T,f=32,s=2,v=2,q=2;AAAAAA==\x1b\\" },
    .{ "a wide character split by the line end", "\x1b[1;20H\u{4E2D}" },
    .{ "a semantic click mode", "\x1b]133;A;cl=line\x1b\\" },
    .{ "the status display", "\x1b[1$}" },
    .{ "a glyph registration", "\x1b_25a1;r;cp=e0a0;AAAAAAAAAAAAAA==\x1b\\" },
    .{ "a drag and drop registration", "\x1b]72;t=a;text/plain\x1b\\" },
};

test "the dump changes with every piece of state" {
    testing.log_level = .err;
    const base = "ab\r\n";
    var t: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer t.deinit(testing.allocator);
    var stream = t.vtStream();
    defer stream.deinit();
    stream.nextSlice(base);
    const before = try testDump(&t);
    defer testing.allocator.free(before);

    for (changes) |change| {
        var changed: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
        defer changed.deinit(testing.allocator);
        var changed_stream = changed.vtStream();
        defer changed_stream.deinit();
        changed_stream.nextSlice(base);
        changed_stream.nextSlice(change[1]);
        const after = try testDump(&changed);
        defer testing.allocator.free(after);
        if (std.mem.eql(u8, before, after)) {
            std.debug.print("the dump missed {s}\n", .{change[0]});
            return error.TestUnexpectedResult;
        }
    }
}

test "the dump changes with a resize and pixel size" {
    var t: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer t.deinit(testing.allocator);
    const before = try testDump(&t);
    defer testing.allocator.free(before);

    try t.resize(testing.allocator, .{ .cols = 20, .rows = 5, .cell_size_px = .{ .width = 8, .height = 16 } });
    const pixels = try testDump(&t);
    defer testing.allocator.free(pixels);
    try testing.expect(!std.mem.eql(u8, before, pixels));

    try t.resize(testing.allocator, .{ .cols = 21, .rows = 5 });
    const cols = try testDump(&t);
    defer testing.allocator.free(cols);
    try testing.expect(!std.mem.eql(u8, pixels, cols));
}

test "the dump ignores how state is stored" {
    // The same text through different paths: a print, and an erase and
    // reprint that leaves a freed style and hyperlink behind in the page.
    var a: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer a.deinit(testing.allocator);
    var a_stream = a.vtStream();
    defer a_stream.deinit();
    a_stream.nextSlice("\x1b[1mab\x1b[0m");

    var b: Terminal = try .init(testing.io, testing.allocator, .{ .cols = 20, .rows = 5 });
    defer b.deinit(testing.allocator);
    var b_stream = b.vtStream();
    defer b_stream.deinit();
    b_stream.nextSlice("\x1b[4m\x1b]8;id=q;https://x\x1b\\zz\x1b]8;;\x1b\\\x1b[0m\x1b[H\x1b[2K\x1b[1mab\x1b[0m");

    const a_dump = try testDump(&a);
    defer testing.allocator.free(a_dump);
    const b_dump = try testDump(&b);
    defer testing.allocator.free(b_dump);
    try testing.expectEqualStrings(a_dump, b_dump);
}
