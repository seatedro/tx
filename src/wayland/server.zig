const std = @import("std");
const Allocator = std.mem.Allocator;
const c = std.c;
const fd_t = std.posix.fd_t;
const wire = @import("wire.zig");
const protocol = @import("protocol.zig");

const display = protocol.display;
const data_control = protocol.data_control;
const Protocol = data_control.Protocol;

const log = std.log.scoped(.wayland);

/// The user holds only .clipboard. A program can hold either.
pub const Selection = enum { clipboard, primary };

/// The user's side of the clipboard. The Server calls it while it handles a
/// request or a disconnect.
pub const Backend = struct {
    context: ?*anyopaque = null,
    /// A program reads the user's clipboard as mime. The callee owns fd, and
    /// writes the data to it and closes it. mime is borrowed for the call.
    fetch: *const fn (context: ?*anyopaque, mime: []const u8, fd: fd_t) void,
    /// A program set selection to a source with these types, or the selection
    /// was cleared (null) by a program or by its source going away. mimes are
    /// borrowed for the call.
    copied: *const fn (context: ?*anyopaque, selection: Selection, mimes: ?[]const []const u8) void,
};

pub const max_mimes = 64;
pub const max_mime_len = 255;
const max_objects = 16 * 1024;
/// Received descriptors a connection holds before requests take them.
/// socket.zig closes a program that sends more.
pub const max_pending_fds = 64;

// A global's registry name is its index plus one. bind switches on the name.
const globals = [_]struct { name: []const u8, version: u32 }{
    .{ .name = protocol.seat.name, .version = 7 },
    .{ .name = protocol.compositor.name, .version = 6 },
    .{ .name = protocol.output.name, .version = 4 },
    .{ .name = Protocol.wlr.names().manager, .version = 2 },
    .{ .name = Protocol.ext.names().manager, .version = 1 },
};

const seat_name = "seat0";

const Owner = union(enum) {
    none,
    user: Mimes,
    source: *Source,
};

const Mimes = std.ArrayList([]u8);

fn freeMimes(gpa: Allocator, mimes: *Mimes) void {
    for (mimes.items) |m| gpa.free(m);
    mimes.deinit(gpa);
}

pub const Server = struct {
    gpa: Allocator,
    backend: Backend,
    connections: std.ArrayList(*Connection) = .empty,
    selections: std.EnumArray(Selection, Owner) = .initFill(.none),
    /// Counts the changes to each selection. An offer can be read only while
    /// its generation is current.
    generations: std.EnumArray(Selection, u64) = .initFill(0),

    pub fn init(gpa: Allocator, backend: Backend) Server {
        return .{ .gpa = gpa, .backend = backend };
    }

    pub fn deinit(s: *Server) void {
        if (s.selections.getPtr(.clipboard).* == .user) freeMimes(s.gpa, &s.selections.getPtr(.clipboard).user);
        // With no owners, the disconnects below report no changes.
        s.selections = .initFill(.none);
        while (s.connections.items.len > 0) s.disconnect(s.connections.items[s.connections.items.len - 1]);
        s.connections.deinit(s.gpa);
        s.* = undefined;
    }

    pub fn connect(s: *Server) Allocator.Error!*Connection {
        const conn = try s.gpa.create(Connection);
        errdefer s.gpa.destroy(conn);
        conn.* = .{ .server = s };
        try conn.objects.put(s.gpa, display.id, .{ .version = 1, .kind = .display });
        errdefer conn.objects.deinit(s.gpa);
        try s.connections.append(s.gpa, conn);
        return conn;
    }

    /// Frees conn and closes the descriptors it holds. A selection held by one
    /// of its sources is cleared and reported to Backend.copied.
    pub fn disconnect(s: *Server, conn: *Connection) void {
        const index = std.mem.indexOfScalar(*Connection, s.connections.items, conn).?;
        // Removed first, so the selection changes below skip conn.
        _ = s.connections.swapRemove(index);

        var it = conn.objects.valueIterator();
        while (it.next()) |object| switch (object.kind) {
            .source => |source| {
                s.dropSource(source);
                freeMimes(s.gpa, &source.mimes);
                s.gpa.destroy(source);
            },
            else => {},
        };
        conn.objects.deinit(s.gpa);
        conn.devices.deinit(s.gpa);
        while (conn.fds.popFront()) |fd| close(fd);
        conn.fds.deinit(s.gpa);
        for (conn.out.fds.items) |fd| close(fd);
        conn.out.deinit(s.gpa);
        s.gpa.destroy(conn);
    }

    /// Gives the clipboard to the user with these types, or to no one when
    /// mimes is null, and cancels a source that held it. A type with a NUL is
    /// skipped.
    pub fn setClipboard(s: *Server, mimes: ?[]const []const u8) Allocator.Error!void {
        var owned: Mimes = .empty;
        errdefer freeMimes(s.gpa, &owned);
        if (mimes) |list| for (list) |m| {
            if (owned.items.len == max_mimes) break;
            if (m.len > max_mime_len or std.mem.indexOfScalar(u8, m, 0) != null) continue;
            try owned.append(s.gpa, try s.gpa.dupe(u8, m));
        };
        s.set(.clipboard, if (mimes != null) .{ .user = owned } else .none);
    }

    /// Asks the program whose source holds selection to write mime to fd.
    /// Takes fd. Returns false, with fd closed, when no source holds the
    /// selection with that type or the source's connection has failed.
    pub fn read(s: *Server, selection: Selection, mime: []const u8, fd: fd_t) bool {
        switch (s.selections.get(selection)) {
            .source => |source| if (source.offers(mime) and !source.conn.failed) {
                source.conn.send(source.id, @backingInt(data_control.source.Event.send), &.{ .{ .string = mime }, .{ .fd = fd } });
                if (!source.conn.failed) return true;
            },
            else => {},
        }
        close(fd);
        return false;
    }

    fn set(s: *Server, selection: Selection, owner: Owner) void {
        switch (s.selections.get(selection)) {
            .none => {},
            .user => |mimes| {
                var list = mimes;
                freeMimes(s.gpa, &list);
            },
            .source => |source| if (owner != .source or owner.source != source) {
                source.conn.send(source.id, @backingInt(data_control.source.Event.cancelled), &.{});
            },
        }
        s.changed(selection, owner);
    }

    fn changed(s: *Server, selection: Selection, owner: Owner) void {
        s.selections.set(selection, owner);
        s.generations.getPtr(selection).* += 1;
        for (s.connections.items) |conn| {
            for (conn.devices.items) |id| conn.sendSelection(id, selection);
        }
    }

    fn copied(s: *Server, selection: Selection) void {
        switch (s.selections.get(selection)) {
            .none => s.backend.copied(s.backend.context, selection, null),
            .user => unreachable,
            .source => |source| {
                const mimes: []const []const u8 = @ptrCast(source.mimes.items);
                s.backend.copied(s.backend.context, selection, mimes);
            },
        }
    }

    fn dropSource(s: *Server, source: *Source) void {
        for ([_]Selection{ .clipboard, .primary }) |selection| {
            const owner = s.selections.get(selection);
            if (owner == .source and owner.source == source) {
                s.changed(selection, .none);
                s.copied(selection);
            }
        }
    }

    fn receive(s: *Server, offer: Offer, mime: []const u8, fd: fd_t) void {
        if (offer.generation != s.generations.get(offer.selection)) return close(fd);
        switch (s.selections.get(offer.selection)) {
            .none => close(fd),
            .user => |mimes| {
                for (mimes.items) |m| if (std.mem.eql(u8, m, mime)) return s.backend.fetch(s.backend.context, mime, fd);
                close(fd);
            },
            .source => _ = s.read(offer.selection, mime, fd),
        }
    }
};

const Source = struct {
    conn: *Connection,
    id: u32,
    mimes: Mimes = .empty,
    // Set by set_selection or set_primary_selection. A used source takes no
    // more types and can't be set again.
    used: bool = false,

    fn offers(source: *const Source, mime: []const u8) bool {
        for (source.mimes.items) |m| if (std.mem.eql(u8, m, mime)) return true;
        return false;
    }
};

const Object = struct {
    version: u32,
    kind: union(enum) {
        display,
        registry,
        callback,
        seat,
        compositor,
        surface,
        region,
        output,
        manager: Protocol,
        device: Protocol,
        source: *Source,
        offer: Offer,
    },
};

const Offer = struct {
    selection: Selection,
    generation: u64,
};

pub const Connection = struct {
    server: *Server,
    objects: std.AutoHashMapUnmanaged(u32, Object) = .empty,
    devices: std.ArrayList(u32) = .empty,
    fds: std.Deque(fd_t) = .empty,
    /// Events to send. The sender closes the descriptors it sends.
    out: wire.Outbox = .{},
    next_server_id: u32 = protocol.server_id_start,
    /// Set after a protocol error, or when an event couldn't be queued. No
    /// more requests are handled and no more events are queued.
    failed: bool = false,

    /// Handles each complete request in bytes and returns the bytes used. The
    /// rest must be passed again, with the bytes that follow it.
    pub fn receive(conn: *Connection, bytes: []const u8) usize {
        var used: usize = 0;
        while (!conn.failed) {
            const message, const len = (wire.next(bytes[used..]) catch {
                conn.fail(display.id, display.Error.invalid_method, "bad message size");
                break;
            }) orelse break;
            used += len;
            conn.dispatch(message) catch |err| switch (err) {
                error.OutOfMemory => conn.fail(display.id, display.Error.no_memory, "out of memory"),
                error.ProtocolError => {},
            };
        }
        return used;
    }

    const Error = Allocator.Error || error{
        ProtocolError,
    };

    fn dispatch(conn: *Connection, message: wire.Message) Error!void {
        const id = message.header.object;
        const object = conn.objects.get(id) orelse
            return conn.failWith(display.id, display.Error.invalid_object, "unknown object");
        var r: wire.Reader = .init(message, &conn.fds);
        const opcode = message.header.opcode;

        conn.handle(id, object, opcode, &r) catch |err| switch (err) {
            error.Truncated, error.BadString, error.MissingFd, error.TrailingBytes, error.BadSize => return conn.failWith(id, display.Error.invalid_method, "bad arguments"),
            error.UnknownOpcode => return conn.failWith(id, display.Error.invalid_method, "unknown request"),
            error.OutOfMemory, error.ProtocolError => |e| return e,
        };
    }

    const HandleError = Error || wire.DecodeError || error{UnknownOpcode};

    fn handle(conn: *Connection, id: u32, object: Object, opcode: u16, r: *wire.Reader) HandleError!void {
        switch (object.kind) {
            .display => switch (try request(display.Request, opcode)) {
                .sync => {
                    // done destroys the callback, so it is never stored.
                    const callback = try conn.newId(r);
                    try r.end();
                    conn.send(callback, @backingInt(protocol.callback.Event.done), &.{.{ .uint = 0 }});
                    conn.deleted(callback);
                },
                .get_registry => {
                    const registry = try conn.newId(r);
                    try r.end();
                    try conn.add(registry, .{ .version = 1, .kind = .registry });
                    for (globals, 1..) |global, name| {
                        conn.send(registry, @backingInt(protocol.registry.Event.global), &.{
                            .{ .uint = @intCast(name) },
                            .{ .string = global.name },
                            .{ .uint = global.version },
                        });
                    }
                },
            },

            .registry => switch (try request(protocol.registry.Request, opcode)) {
                .bind => try conn.bind(id, r),
            },

            .callback => return error.UnknownOpcode,

            .seat => switch (try request(protocol.seat.Request, opcode)) {
                .get_pointer, .get_keyboard, .get_touch => return conn.failWith(id, protocol.seat.Error.missing_capability, "the seat has no input devices"),
                .release => {
                    if (object.version < 5) return error.UnknownOpcode;
                    try r.end();
                    conn.destroy(id);
                },
            },

            .compositor => switch (try request(protocol.compositor.Request, opcode)) {
                .create_surface => {
                    const surface = try conn.newId(r);
                    try r.end();
                    try conn.add(surface, .{ .version = object.version, .kind = .surface });
                },
                .create_region => {
                    const region = try conn.newId(r);
                    try r.end();
                    try conn.add(region, .{ .version = object.version, .kind = .region });
                },
                // From version 7, above the one offered.
                .release => return error.UnknownOpcode,
            },

            // Surfaces are never shown, and frame callbacks never receive done.
            // get_release is from version 7, above the one offered. The other
            // requests are ignored.
            .surface => switch (try request(protocol.surface.Request, opcode)) {
                .destroy => conn.destroy(id),
                .frame => {
                    const callback = try conn.newId(r);
                    try conn.add(callback, .{ .version = 1, .kind = .callback });
                },
                .get_release => return error.UnknownOpcode,
                else => {},
            },

            .region => switch (try request(protocol.region.Request, opcode)) {
                .destroy => conn.destroy(id),
                .add, .subtract => {},
            },

            .output => switch (try request(protocol.output.Request, opcode)) {
                .release => {
                    if (object.version < 3) return error.UnknownOpcode;
                    try r.end();
                    conn.destroy(id);
                },
            },

            .manager => |p| switch (try request(data_control.manager.Request, opcode)) {
                .create_data_source => {
                    const new = try conn.newId(r);
                    try r.end();
                    const source = try conn.server.gpa.create(Source);
                    errdefer conn.server.gpa.destroy(source);
                    source.* = .{ .conn = conn, .id = new };
                    try conn.add(new, .{ .version = object.version, .kind = .{ .source = source } });
                },
                .get_data_device => {
                    const new = try conn.newId(r);
                    _ = try r.object();
                    try r.end();
                    // Reserved before add, so a device object is never missing
                    // from devices.
                    try conn.devices.ensureUnusedCapacity(conn.server.gpa, 1);
                    try conn.add(new, .{ .version = object.version, .kind = .{ .device = p } });
                    conn.devices.appendAssumeCapacity(new);

                    conn.sendSelection(new, .clipboard);
                    conn.sendSelection(new, .primary);
                },
                .destroy => {
                    try r.end();
                    conn.destroy(id);
                },
            },

            .device => |p| switch (try request(data_control.device.Request, opcode)) {
                .set_selection => try conn.setSelection(id, r, .clipboard),
                .set_primary_selection => {
                    if (!hasPrimary(p, object.version)) return error.UnknownOpcode;
                    try conn.setSelection(id, r, .primary);
                },
                .destroy => {
                    try r.end();
                    conn.destroy(id);
                },
            },

            .source => |source| switch (try request(data_control.source.Request, opcode)) {
                .offer => {
                    const mime = (try r.string()) orelse return error.BadString;
                    try r.end();
                    if (source.used) return conn.failWith(id, data_control.source.Error.invalid_offer, "offer after set_selection");
                    if (source.mimes.items.len == max_mimes or mime.len > max_mime_len or source.offers(mime)) return;
                    const owned = try conn.server.gpa.dupe(u8, mime);
                    errdefer conn.server.gpa.free(owned);
                    try source.mimes.append(conn.server.gpa, owned);
                },
                .destroy => {
                    try r.end();
                    conn.destroy(id);
                },
            },

            .offer => |offer| switch (try request(data_control.offer.Request, opcode)) {
                .receive => {
                    const mime = (try r.string()) orelse return error.BadString;
                    const fd = try r.fd();
                    r.end() catch |err| {
                        close(fd);
                        return err;
                    };
                    conn.server.receive(offer, mime, fd);
                },
                .destroy => {
                    try r.end();
                    conn.destroy(id);
                },
            },
        }
    }

    fn bind(conn: *Connection, registry: u32, r: *wire.Reader) HandleError!void {
        const name = try r.uint();
        const interface = (try r.string()) orelse return error.BadString;
        const version = try r.uint();
        const new = try conn.newId(r);
        try r.end();

        if (name == 0 or name > globals.len or !std.mem.eql(u8, globals[name - 1].name, interface))
            return conn.failWith(registry, display.Error.invalid_object, "no such global");
        const global = globals[name - 1];
        if (version == 0 or version > global.version)
            return conn.failWith(registry, display.Error.invalid_object, "invalid version for global");

        switch (name) {
            1 => {
                try conn.add(new, .{ .version = version, .kind = .seat });
                const Event = protocol.seat.Event;
                if (version >= 2) conn.send(new, @backingInt(Event.name), &.{.{ .string = seat_name }});
                conn.send(new, @backingInt(Event.capabilities), &.{.{ .uint = 0 }});
            },
            2 => try conn.add(new, .{ .version = version, .kind = .compositor }),
            3 => {
                try conn.add(new, .{ .version = version, .kind = .output });
                conn.sendOutput(new, version);
            },
            4 => try conn.add(new, .{ .version = version, .kind = .{ .manager = .wlr } }),
            5 => try conn.add(new, .{ .version = version, .kind = .{ .manager = .ext } }),
            else => unreachable,
        }
    }

    fn sendOutput(conn: *Connection, id: u32, version: u32) void {
        const Event = protocol.output.Event;
        conn.send(id, @backingInt(Event.geometry), &.{
            .{ .int = 0 },              .{ .int = 0 },
            .{ .int = 0 },              .{ .int = 0 },
            .{ .int = 0 },              .{ .string = "tx" },
            .{ .string = "clipboard" }, .{ .int = 0 },
        });
        // A 1x1 mode at 60 Hz. The refresh rate is in mHz.
        const mode = protocol.output.Mode.current | protocol.output.Mode.preferred;
        conn.send(id, @backingInt(Event.mode), &.{ .{ .uint = mode }, .{ .int = 1 }, .{ .int = 1 }, .{ .int = 60_000 } });
        if (version >= 2) conn.send(id, @backingInt(Event.scale), &.{.{ .int = 1 }});
        if (version >= 4) {
            conn.send(id, @backingInt(Event.name), &.{.{ .string = "TX-1" }});
            conn.send(id, @backingInt(Event.description), &.{.{ .string = "tx clipboard server, no display" }});
        }
        if (version >= 2) conn.send(id, @backingInt(Event.done), &.{});
    }

    fn setSelection(conn: *Connection, device: u32, r: *wire.Reader, selection: Selection) HandleError!void {
        const source_id = try r.object();
        try r.end();
        const s = conn.server;
        const id = source_id orelse {
            s.set(selection, .none);
            return s.copied(selection);
        };
        const object = conn.objects.get(id) orelse return conn.failWith(id, display.Error.invalid_object, "unknown object");
        if (object.kind != .source) return conn.failWith(id, display.Error.invalid_object, "not a data source");
        const source = object.kind.source;
        if (source.used) return conn.failWith(device, data_control.device.Error.used_source, "source already used");
        source.used = true;
        s.set(selection, .{ .source = source });
        s.copied(selection);
    }

    fn sendSelection(conn: *Connection, id: u32, selection: Selection) void {
        if (conn.failed) return;
        const p = conn.objects.get(id).?.kind.device;
        const version = conn.objects.get(id).?.version;
        const Event = data_control.device.Event;
        if (selection == .primary and !hasPrimary(p, version)) return;
        const event: Event = if (selection == .clipboard) .selection else .primary_selection;

        const s = conn.server;
        const mimes: []const []u8 = switch (s.selections.get(selection)) {
            .none => return conn.send(id, @backingInt(event), &.{.{ .uint = 0 }}),
            .user => |list| list.items,
            .source => |source| source.mimes.items,
        };

        const offer = conn.next_server_id;
        if (offer == std.math.maxInt(u32)) return conn.fail(display.id, display.Error.no_memory, "out of object IDs");
        conn.next_server_id += 1;
        conn.add(offer, .{ .version = 1, .kind = .{ .offer = .{ .selection = selection, .generation = s.generations.get(selection) } } }) catch
            return conn.fail(display.id, display.Error.no_memory, "out of memory");

        conn.send(id, @backingInt(Event.data_offer), &.{.{ .uint = offer }});
        for (mimes) |m| conn.send(offer, @backingInt(data_control.offer.Event.offer), &.{.{ .string = m }});
        conn.send(id, @backingInt(event), &.{.{ .uint = offer }});
    }

    fn newId(conn: *Connection, r: *wire.Reader) HandleError!u32 {
        const id = try r.uint();
        if (id == 0 or id >= protocol.server_id_start or conn.objects.contains(id))
            return conn.failWith(display.id, display.Error.invalid_object, "invalid new ID");
        return id;
    }

    fn add(conn: *Connection, id: u32, object: Object) HandleError!void {
        if (conn.objects.count() >= max_objects) return conn.failWith(display.id, display.Error.no_memory, "too many objects");
        try conn.objects.put(conn.server.gpa, id, object);
    }

    fn destroy(conn: *Connection, id: u32) void {
        const object = conn.objects.fetchRemove(id).?.value;
        switch (object.kind) {
            .source => |source| {
                conn.server.dropSource(source);
                freeMimes(conn.server.gpa, &source.mimes);
                conn.server.gpa.destroy(source);
            },
            .device => {
                const index = std.mem.indexOfScalar(u32, conn.devices.items, id).?;
                _ = conn.devices.orderedRemove(index);
            },
            else => {},
        }
        // delete_id is for ids the program allocated. libwayland frees the
        // server's ids without it.
        if (id < protocol.server_id_start) conn.deleted(id);
    }

    fn deleted(conn: *Connection, id: u32) void {
        conn.send(display.id, @backingInt(display.Event.delete_id), &.{.{ .uint = id }});
    }

    fn send(conn: *Connection, object: u32, opcode: u16, args: []const wire.Arg) void {
        if (conn.failed) return;
        conn.out.event(conn.server.gpa, object, opcode, args) catch |err| switch (err) {
            error.OutOfMemory => conn.failed = true,
            // Strings sent are fixed text, or types that passed max_mime_len
            // and the NUL checks on the way in.
            error.MessageTooLong, error.BadString => unreachable,
        };
    }

    fn fail(conn: *Connection, object: u32, code: anytype, message: []const u8) void {
        if (conn.failed) return;
        log.debug("protocol error on object {d}: {s}", .{ object, message });
        conn.send(display.id, @backingInt(display.Event.@"error"), &.{ .{ .uint = object }, .{ .uint = @backingInt(code) }, .{ .string = message } });
        conn.failed = true;
    }

    fn failWith(conn: *Connection, object: u32, code: anytype, message: []const u8) error{ProtocolError} {
        conn.fail(object, code, message);
        return error.ProtocolError;
    }
};

fn hasPrimary(p: Protocol, version: u32) bool {
    return p == .ext or version >= 2;
}

fn request(comptime Request: type, opcode: u16) error{UnknownOpcode}!Request {
    return std.enums.fromInt(Request, opcode) orelse error.UnknownOpcode;
}

fn close(fd: fd_t) void {
    _ = c.close(fd);
}

const testing = std.testing;

const TestBackend = struct {
    fetched: std.ArrayList(u8) = .empty,
    fetch_fds: std.ArrayList(fd_t) = .empty,
    copies: std.ArrayList(u8) = .empty,

    fn backend(b: *TestBackend) Backend {
        return .{ .context = b, .fetch = fetch, .copied = copied };
    }

    fn deinit(b: *TestBackend) void {
        for (b.fetch_fds.items) |fd| close(fd);
        b.fetch_fds.deinit(testing.allocator);
        b.fetched.deinit(testing.allocator);
        b.copies.deinit(testing.allocator);
    }

    fn fetch(context: ?*anyopaque, mime: []const u8, fd: fd_t) void {
        const b: *TestBackend = @ptrCast(@alignCast(context.?));
        b.fetched.print(testing.allocator, "{s}\n", .{mime}) catch unreachable;
        b.fetch_fds.append(testing.allocator, fd) catch unreachable;
    }

    fn copied(context: ?*anyopaque, selection: Selection, mimes: ?[]const []const u8) void {
        const b: *TestBackend = @ptrCast(@alignCast(context.?));
        b.copies.print(testing.allocator, "{t}:", .{selection}) catch unreachable;
        if (mimes) |list| {
            for (list) |m| b.copies.print(testing.allocator, " {s}", .{m}) catch unreachable;
        } else b.copies.appendSlice(testing.allocator, " cleared") catch unreachable;
        b.copies.append(testing.allocator, '\n') catch unreachable;
    }
};

const TestProgram = struct {
    conn: *Connection,
    interfaces: std.AutoHashMapUnmanaged(u32, Interface) = .empty,
    next_id: u32 = 2,
    fds: std.ArrayList(fd_t) = .empty,
    offers: std.ArrayList(u32) = .empty,

    const Interface = enum { display, registry, callback, seat, output, manager, device, source, offer };

    // Event arguments: u uint, i int, s string, f fd, o an object, and n a
    // new offer.
    fn signature(interface: Interface, opcode: u16) []const u8 {
        const table: []const []const u8 = switch (interface) {
            .display => &.{ "uus", "u" },
            .registry => &.{ "usu", "u" },
            .callback => &.{"u"},
            .seat => &.{ "u", "s" },
            .output => &.{ "iiiiissi", "uiii", "", "i", "s", "s" },
            .manager => &.{},
            .device => &.{ "n", "o", "", "o" },
            .source => &.{ "sf", "" },
            .offer => &.{"s"},
        };
        return table[opcode];
    }

    fn eventName(interface: Interface, opcode: u16) []const u8 {
        const table: []const []const u8 = switch (interface) {
            .display => &.{ "error", "delete_id" },
            .registry => &.{ "global", "global_remove" },
            .callback => &.{"done"},
            .seat => &.{ "capabilities", "name" },
            .output => &.{ "geometry", "mode", "done", "scale", "name", "description" },
            .manager => &.{},
            .device => &.{ "data_offer", "selection", "finished", "primary_selection" },
            .source => &.{ "send", "cancelled" },
            .offer => &.{"offer"},
        };
        return table[opcode];
    }

    fn init(server: *Server) !TestProgram {
        var p: TestProgram = .{ .conn = try server.connect() };
        try p.interfaces.put(testing.allocator, display.id, .display);
        return p;
    }

    fn deinit(p: *TestProgram) void {
        for (p.fds.items) |fd| close(fd);
        p.fds.deinit(testing.allocator);
        p.offers.deinit(testing.allocator);
        p.interfaces.deinit(testing.allocator);
    }

    fn offer(p: *const TestProgram, n: usize) u32 {
        return p.offers.items[n - 1];
    }

    fn new(p: *TestProgram, interface: Interface) !u32 {
        const id = p.next_id;
        p.next_id += 1;
        try p.interfaces.put(testing.allocator, id, interface);
        return id;
    }

    fn request(p: *TestProgram, object: u32, opcode: u16, args: []const wire.Arg) !void {
        var out: wire.Outbox = .{};
        defer out.deinit(testing.allocator);
        try out.event(testing.allocator, object, opcode, args);
        try p.conn.fds.pushBackSlice(testing.allocator, out.fds.items);
        try testing.expectEqual(out.bytes.items.len, p.conn.receive(out.bytes.items));
    }

    fn registry(p: *TestProgram) !u32 {
        const id = try p.new(.registry);
        try p.request(display.id, @backingInt(display.Request.get_registry), &.{.{ .uint = id }});
        p.discard();
        return id;
    }

    fn bind(p: *TestProgram, registry_id: u32, name: u32, interface: Interface, version: u32) !u32 {
        const id = try p.new(interface);
        try p.request(registry_id, @backingInt(protocol.registry.Request.bind), &.{
            .{ .uint = name },
            .{ .string = globals[name - 1].name },
            .{ .uint = version },
            .{ .uint = id },
        });
        return id;
    }

    fn discard(p: *TestProgram) void {
        p.conn.out.bytes.clearRetainingCapacity();
        for (p.conn.out.fds.items) |fd| close(fd);
        p.conn.out.fds.clearRetainingCapacity();
    }

    fn events(p: *TestProgram) ![]u8 {
        var text: std.ArrayList(u8) = .empty;
        errdefer text.deinit(testing.allocator);
        var fds: std.Deque(fd_t) = .empty;
        defer fds.deinit(testing.allocator);
        try fds.pushBackSlice(testing.allocator, p.conn.out.fds.items);
        try p.fds.appendSlice(testing.allocator, p.conn.out.fds.items);
        p.conn.out.fds.clearRetainingCapacity();

        var rest = p.conn.out.bytes.items;
        while (try wire.next(rest)) |entry| {
            const message, const len = entry;
            rest = rest[len..];
            const interface = p.interfaces.get(message.header.object).?;
            try text.print(testing.allocator, "{t}.{s}", .{ interface, eventName(interface, message.header.opcode) });
            var r: wire.Reader = .init(message, &fds);
            for (signature(interface, message.header.opcode)) |t| switch (t) {
                'u' => try text.print(testing.allocator, " {d}", .{try r.uint()}),
                'o' => {
                    const id = try r.uint();
                    if (std.mem.indexOfScalar(u32, p.offers.items, id)) |i|
                        try text.print(testing.allocator, " o{d}", .{i + 1})
                    else
                        try text.print(testing.allocator, " {d}", .{id});
                },
                'i' => try text.print(testing.allocator, " {d}", .{try r.int()}),
                's' => try text.print(testing.allocator, " \"{s}\"", .{(try r.string()).?}),
                'f' => {
                    _ = try r.fd();
                    try text.appendSlice(testing.allocator, " fd");
                },
                'n' => {
                    const id = try r.uint();
                    try p.interfaces.put(testing.allocator, id, .offer);
                    try p.offers.append(testing.allocator, id);
                    try text.print(testing.allocator, " o{d}", .{p.offers.items.len});
                },
                else => unreachable,
            };
            try r.end();
            try text.append(testing.allocator, '\n');
        }
        p.conn.out.bytes.clearRetainingCapacity();
        return text.toOwnedSlice(testing.allocator);
    }

    fn expectEvents(p: *TestProgram, want: []const u8) !void {
        const got = try p.events();
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(want, got);
    }

    fn device(p: *TestProgram, manager: u32, seat_id: u32) !u32 {
        const id = try p.new(.device);
        try p.request(manager, @backingInt(data_control.manager.Request.get_data_device), &.{ .{ .uint = id }, .{ .uint = seat_id } });
        return id;
    }

    fn source(p: *TestProgram, manager: u32, mimes: []const []const u8) !u32 {
        const id = try p.new(.source);
        try p.request(manager, @backingInt(data_control.manager.Request.create_data_source), &.{.{ .uint = id }});
        for (mimes) |m| try p.request(id, @backingInt(data_control.source.Request.offer), &.{.{ .string = m }});
        return id;
    }
};

fn pipe() ![2]fd_t {
    var fds: [2]fd_t = undefined;
    if (c.pipe(&fds) != 0) return error.Unexpected;
    return fds;
}

fn closedEmpty(fd: fd_t) bool {
    var buf: [1]u8 = undefined;
    return c.read(fd, &buf, 1) == 0;
}

test "the registry lists the globals, and binding them sends their state" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();
    var p: TestProgram = try .init(&server);
    defer p.deinit();

    const registry = try p.new(.registry);
    try p.request(display.id, @backingInt(display.Request.get_registry), &.{.{ .uint = registry }});
    try p.expectEvents(
        \\registry.global 1 "wl_seat" 7
        \\registry.global 2 "wl_compositor" 6
        \\registry.global 3 "wl_output" 4
        \\registry.global 4 "zwlr_data_control_manager_v1" 2
        \\registry.global 5 "ext_data_control_manager_v1" 1
        \\
    );

    _ = try p.bind(registry, 1, .seat, 2);
    _ = try p.bind(registry, 3, .output, 4);
    try p.expectEvents(
        \\seat.name "seat0"
        \\seat.capabilities 0
        \\output.geometry 0 0 0 0 0 "tx" "clipboard" 0
        \\output.mode 3 1 1 60000
        \\output.scale 1
        \\output.name "TX-1"
        \\output.description "tx clipboard server, no display"
        \\output.done
        \\
    );

    const callback = try p.new(.callback);
    try p.request(display.id, @backingInt(display.Request.sync), &.{.{ .uint = callback }});
    try p.expectEvents(
        \\callback.done 0
        \\display.delete_id 5
        \\
    );
}

test "a program's copy reaches the backend and other programs, and their reads reach it" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();

    var copier: TestProgram = try .init(&server);
    defer copier.deinit();
    var registry = try copier.registry();
    var seat_id = try copier.bind(registry, 1, .seat, 2);
    var manager = try copier.bind(registry, 4, .manager, 2);
    const copier_device = try copier.device(manager, seat_id);
    const source = try copier.source(manager, &.{ "text/plain", "text/plain;charset=utf-8" });
    copier.discard();
    try copier.request(copier_device, @backingInt(data_control.device.Request.set_selection), &.{.{ .uint = source }});
    try testing.expectEqualStrings("clipboard: text/plain text/plain;charset=utf-8\n", backend.copies.items);

    try copier.expectEvents(
        \\device.data_offer o1
        \\offer.offer "text/plain"
        \\offer.offer "text/plain;charset=utf-8"
        \\device.selection o1
        \\
    );

    var paster: TestProgram = try .init(&server);
    defer paster.deinit();
    registry = try paster.registry();
    seat_id = try paster.bind(registry, 1, .seat, 2);
    manager = try paster.bind(registry, 5, .manager, 1);
    paster.discard();
    _ = try paster.device(manager, seat_id);
    try paster.expectEvents(
        \\device.data_offer o1
        \\offer.offer "text/plain"
        \\offer.offer "text/plain;charset=utf-8"
        \\device.selection o1
        \\device.primary_selection 0
        \\
    );

    const fds = try pipe();
    defer close(fds[0]);
    try paster.request(paster.offer(1), @backingInt(data_control.offer.Request.receive), &.{ .{ .string = "text/plain" }, .{ .fd = fds[1] } });
    try copier.expectEvents("source.send \"text/plain\" fd\n");
    try testing.expectEqual(fds[1], copier.fds.items[0]);

    const other = try pipe();
    defer close(other[0]);
    try paster.request(paster.offer(1), @backingInt(data_control.offer.Request.receive), &.{ .{ .string = "image/png" }, .{ .fd = other[1] } });
    try testing.expect(closedEmpty(other[0]));
    try copier.expectEvents("");

    const mirror = try pipe();
    defer close(mirror[0]);
    try testing.expect(server.read(.clipboard, "text/plain;charset=utf-8", mirror[1]));
    try copier.expectEvents("source.send \"text/plain;charset=utf-8\" fd\n");
}

test "the user's clipboard replaces a program's copy, and reads of it reach the backend" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();

    var p: TestProgram = try .init(&server);
    defer p.deinit();
    const registry = try p.registry();
    const seat_id = try p.bind(registry, 1, .seat, 2);
    const manager = try p.bind(registry, 4, .manager, 2);
    p.discard();
    const device = try p.device(manager, seat_id);
    const source = try p.source(manager, &.{"text/plain"});
    try p.request(device, @backingInt(data_control.device.Request.set_selection), &.{.{ .uint = source }});
    try p.expectEvents(
        \\device.selection 0
        \\device.primary_selection 0
        \\device.data_offer o1
        \\offer.offer "text/plain"
        \\device.selection o1
        \\
    );

    try server.setClipboard(&.{ "image/png", "bad\x00type", "text/plain" });
    try p.expectEvents(
        \\source.cancelled
        \\device.data_offer o2
        \\offer.offer "image/png"
        \\offer.offer "text/plain"
        \\device.selection o2
        \\
    );
    try testing.expectEqualStrings("clipboard: text/plain\n", backend.copies.items);

    const fds = try pipe();
    defer close(fds[0]);
    try p.request(p.offer(2), @backingInt(data_control.offer.Request.receive), &.{ .{ .string = "image/png" }, .{ .fd = fds[1] } });
    try testing.expectEqualStrings("image/png\n", backend.fetched.items);
    try testing.expectEqual(fds[1], backend.fetch_fds.items[0]);

    try server.setClipboard(null);
    try p.expectEvents("device.selection 0\n");
    const stale = try pipe();
    defer close(stale[0]);
    try p.request(p.offer(2), @backingInt(data_control.offer.Request.receive), &.{ .{ .string = "image/png" }, .{ .fd = stale[1] } });
    try testing.expect(closedEmpty(stale[0]));
    try testing.expectEqual(1, backend.fetch_fds.items.len);
}

test "a copy goes when its program does" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();

    var copier: TestProgram = try .init(&server);
    var registry = try copier.registry();
    var seat_id = try copier.bind(registry, 1, .seat, 2);
    var manager = try copier.bind(registry, 5, .manager, 1);
    const device = try copier.device(manager, seat_id);
    const source = try copier.source(manager, &.{"text/plain"});
    try copier.request(device, @backingInt(data_control.device.Request.set_primary_selection), &.{.{ .uint = source }});

    var watcher: TestProgram = try .init(&server);
    defer watcher.deinit();
    registry = try watcher.registry();
    seat_id = try watcher.bind(registry, 1, .seat, 2);
    manager = try watcher.bind(registry, 5, .manager, 1);
    _ = try watcher.device(manager, seat_id);
    watcher.discard();

    copier.deinit();
    server.disconnect(copier.conn);
    try watcher.expectEvents("device.primary_selection 0\n");
    try testing.expectEqualStrings("primary: text/plain\nprimary: cleared\n", backend.copies.items);
}

test "zwlr data control has no primary selection before version 2" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();
    var p: TestProgram = try .init(&server);
    defer p.deinit();

    const registry = try p.registry();
    const seat_id = try p.bind(registry, 1, .seat, 2);
    const manager = try p.bind(registry, 4, .manager, 1);
    p.discard();
    const device = try p.device(manager, seat_id);
    try p.expectEvents("device.selection 0\n");

    const source = try p.source(manager, &.{"text/plain"});
    try p.request(device, @backingInt(data_control.device.Request.set_primary_selection), &.{.{ .uint = source }});
    try p.expectEvents("display.error 5 1 \"unknown request\"\n");
    try testing.expect(p.conn.failed);
}

test "protocol errors" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();

    const Case = struct {
        run: *const fn (p: *TestProgram, registry: u32) anyerror!void,
        want: []const u8,
    };
    const cases = [_]Case{
        .{ .run = struct {
            fn f(p: *TestProgram, _: u32) !void {
                try p.request(99, 0, &.{});
            }
        }.f, .want = "display.error 1 0 \"unknown object\"\n" },
        .{ .run = struct {
            fn f(p: *TestProgram, registry: u32) !void {
                _ = try p.bind(registry, 1, .seat, 8);
            }
        }.f, .want = "display.error 2 0 \"invalid version for global\"\n" },
        .{ .run = struct {
            fn f(p: *TestProgram, registry: u32) !void {
                const id = try p.new(.seat);
                try p.request(registry, 0, &.{ .{ .uint = 1 }, .{ .string = "wl_output" }, .{ .uint = 1 }, .{ .uint = id } });
            }
        }.f, .want = "display.error 2 0 \"no such global\"\n" },
        .{ .run = struct {
            fn f(p: *TestProgram, registry: u32) !void {
                const seat_id = try p.bind(registry, 1, .seat, 2);
                p.discard();
                try p.request(seat_id, @backingInt(protocol.seat.Request.get_keyboard), &.{.{ .uint = 9 }});
            }
        }.f, .want = "display.error 3 0 \"the seat has no input devices\"\n" },
        .{ .run = struct {
            fn f(p: *TestProgram, registry: u32) !void {
                const seat_id = try p.bind(registry, 1, .seat, 2);
                const manager = try p.bind(registry, 4, .manager, 2);
                const device = try p.device(manager, seat_id);
                const source = try p.source(manager, &.{"text/plain"});
                try p.request(device, 0, &.{.{ .uint = source }});
                p.discard();
                try p.request(source, @backingInt(data_control.source.Request.offer), &.{.{ .string = "text/html" }});
            }
        }.f, .want = "display.error 6 1 \"offer after set_selection\"\n" },
        .{ .run = struct {
            fn f(p: *TestProgram, registry: u32) !void {
                const seat_id = try p.bind(registry, 1, .seat, 2);
                const manager = try p.bind(registry, 4, .manager, 2);
                const device = try p.device(manager, seat_id);
                const source = try p.source(manager, &.{"text/plain"});
                try p.request(device, 0, &.{.{ .uint = source }});
                p.discard();
                try p.request(device, 0, &.{.{ .uint = source }});
            }
        }.f, .want = "display.error 5 1 \"source already used\"\n" },
        .{
            .run = struct {
                fn f(p: *TestProgram, _: u32) !void {
                    try p.request(display.id, @backingInt(display.Request.get_registry), &.{.{ .uint = 2 }});
                }
            }.f,
            .want = "display.error 1 0 \"invalid new ID\"\n",
        },
        .{
            .run = struct {
                fn f(p: *TestProgram, registry: u32) !void {
                    const manager = try p.bind(registry, 4, .manager, 2);
                    const id = try p.new(.offer);
                    _ = id;
                    try p.request(manager, 0, &.{});
                }
            }.f,
            .want = "display.error 3 1 \"bad arguments\"\n",
        },
    };

    for (cases) |case| {
        var p: TestProgram = try .init(&server);
        defer {
            p.deinit();
            server.disconnect(p.conn);
        }
        const registry = try p.registry();
        try case.run(&p, registry);
        try p.expectEvents(case.want);
        try testing.expect(p.conn.failed);

        var out: wire.Outbox = .{};
        defer out.deinit(testing.allocator);
        try out.event(testing.allocator, display.id, @backingInt(display.Request.sync), &.{.{ .uint = 50 }});
        try testing.expectEqual(0, p.conn.receive(out.bytes.items));
        try p.expectEvents("");
    }
}

test "only complete requests are handled" {
    var backend: TestBackend = .{};
    defer backend.deinit();
    var server: Server = .init(testing.allocator, backend.backend());
    defer server.deinit();
    var p: TestProgram = try .init(&server);
    defer p.deinit();

    var out: wire.Outbox = .{};
    defer out.deinit(testing.allocator);
    try out.event(testing.allocator, display.id, @backingInt(display.Request.sync), &.{.{ .uint = 2 }});
    try out.event(testing.allocator, display.id, @backingInt(display.Request.sync), &.{.{ .uint = 3 }});
    try testing.expectEqual(12, p.conn.receive(out.bytes.items[0..20]));
    try testing.expectEqual(12, p.conn.receive(out.bytes.items[12..]));
    try testing.expectEqual(0, p.conn.receive(out.bytes.items[0..0]));
    try p.interfaces.put(testing.allocator, 2, .callback);
    try p.interfaces.put(testing.allocator, 3, .callback);
    try p.expectEvents(
        \\callback.done 0
        \\display.delete_id 2
        \\callback.done 0
        \\display.delete_id 3
        \\
    );
}

const fuzz = @import("fuzz");

test "fuzz: any requests from two programs" {
    try fuzz.run({}, struct {
        fn one(_: void, in: fuzz.Input) !void {
            const open_before = openFds();
            defer std.debug.assert(openFds() == open_before);

            var server: Server = .init(testing.allocator, .{ .fetch = closeFetch, .copied = ignoreCopy });
            defer server.deinit();
            var programs = [2]*Connection{ try server.connect(), try server.connect() };

            // Both programs start with a registry (2), the globals (3 to 7), a
            // device from each manager (8, 9) and a source from each (10, 11).
            for (programs) |conn| {
                var out: wire.Outbox = .{};
                defer out.deinit(testing.allocator);
                try out.event(testing.allocator, display.id, 1, &.{.{ .uint = 2 }});
                for (globals, 1..) |global, name| try out.event(testing.allocator, 2, 0, &.{
                    .{ .uint = @intCast(name) }, .{ .string = global.name }, .{ .uint = global.version }, .{ .uint = @intCast(2 + name) },
                });
                try out.event(testing.allocator, 6, 1, &.{ .{ .uint = 8 }, .{ .uint = 3 } });
                try out.event(testing.allocator, 7, 1, &.{ .{ .uint = 9 }, .{ .uint = 3 } });
                try out.event(testing.allocator, 6, 0, &.{.{ .uint = 10 }});
                try out.event(testing.allocator, 7, 0, &.{.{ .uint = 11 }});
                try testing.expectEqual(out.bytes.items.len, conn.receive(out.bytes.items));
            }

            const mimes = [_][]const u8{ "text/plain", "image/png", "UTF8_STRING" };
            while (!in.done()) {
                const which = in.index(programs.len);
                const conn = programs[which];

                if (in.chance(1, 15)) {
                    if (in.chance(1, 1)) {
                        try server.setClipboard(if (in.chance(1, 3)) null else mimes[0..in.index(mimes.len + 1)]);
                    } else {
                        const fds = try pipe();
                        defer close(fds[0]);
                        _ = server.read(in.enumValue(Selection), mimes[in.index(mimes.len)], fds[1]);
                    }
                    continue;
                }

                if (conn.failed or in.chance(1, 30)) {
                    server.disconnect(conn);
                    programs[which] = try server.connect();
                    continue;
                }

                var out: wire.Outbox = .{};
                defer out.deinit(testing.allocator);
                var args: [4]wire.Arg = undefined;
                const count = in.int(usize, 0, args.len);
                for (args[0..count]) |*arg| arg.* = switch (in.int(u8, 0, 3)) {
                    0 => .{ .uint = if (in.chance(1, 1)) in.int(u32, 0, 12) else protocol.server_id_start + in.int(u32, 0, 8) },
                    1 => .{ .string = if (in.chance(1, 7)) null else mimes[in.index(mimes.len)] },
                    2 => .{ .fd = writeEnd: {
                        const fds = try pipe();
                        close(fds[0]);
                        break :writeEnd fds[1];
                    } },
                    else => .{ .uint = in.any(u32) },
                };
                const object = if (in.chance(3, 1)) in.int(u32, 1, 12) else protocol.server_id_start + in.int(u32, 0, 8);
                try out.event(testing.allocator, object, in.int(u16, 0, 4), args[0..count]);
                try conn.fds.pushBackSlice(testing.allocator, out.fds.items);
                _ = conn.receive(out.bytes.items);

                while (conn.fds.popFront()) |fd| close(fd);
                for (conn.out.fds.items) |fd| close(fd);
                conn.out.fds.clearRetainingCapacity();
                conn.out.bytes.clearRetainingCapacity();
            }
        }

        fn openFds() usize {
            var count: usize = 0;
            for (0..1024) |fd| {
                if (c.fcntl(@intCast(fd), std.posix.F.GETFD) != -1) count += 1;
            }
            return count;
        }

        fn closeFetch(_: ?*anyopaque, _: []const u8, fd: fd_t) void {
            close(fd);
        }

        fn ignoreCopy(_: ?*anyopaque, _: Selection, _: ?[]const []const u8) void {}
    }.one, .{});
}
