//! The clipboard server's protocol state, with no I/O.
//!
//! Each program's connection gets its bytes through `Connection.receive`
//! and its file descriptors through `Connection.fds`, and answers go to
//! `Connection.out`. The server offers:
//!
//! - one `wl_seat`, with no capabilities, which data control works through;
//! - data control, as both `zwlr_data_control_manager_v1` and
//!   `ext_data_control_manager_v1`, for the clipboard and the primary
//!   selection;
//! - a `wl_compositor` that ignores its surfaces, and one `wl_output`.
//!   Chromium waits until a compositor and a ready output exist before it
//!   looks for what it needs to draw. With them, it finds no `wl_shm` and
//!   no shell, and fails as it does on a server with no display.
//!
//! The clipboard holds the user's clipboard, which `Backend` reads, or a
//! program's data source. The primary selection is only ever a program's.
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

pub const Selection = enum { clipboard, primary };

/// What the server needs from the rest of txd.
pub const Backend = struct {
    context: ?*anyopaque = null,
    /// A program asked for the user's clipboard as `mime`. Takes `fd`, the
    /// pipe to write the data to; closing it ends the data.
    fetch: *const fn (context: ?*anyopaque, mime: []const u8, fd: fd_t) void,
    /// A program set `selection` to its own data, offered as `mimes`, or
    /// cleared it (null). `mimes` is valid until the callback returns.
    copied: *const fn (context: ?*anyopaque, selection: Selection, mimes: ?[]const []const u8) void,
};

/// The most MIME types a selection offers. Programs offer a handful.
pub const max_mimes = 64;
/// The longest MIME type. Longer ones are left out of an offer.
pub const max_mime_len = 255;
/// The most objects a connection may hold.
const max_objects = 16 * 1024;
/// The most file descriptors a connection may send ahead of the requests
/// that take them.
pub const max_pending_fds = 64;

/// The globals, in the order of their registry names, from 1.
const globals = [_]struct { name: []const u8, version: u32 }{
    .{ .name = protocol.seat.name, .version = 7 },
    .{ .name = protocol.compositor.name, .version = 6 },
    .{ .name = protocol.output.name, .version = 4 },
    .{ .name = Protocol.wlr.names().manager, .version = 2 },
    .{ .name = Protocol.ext.names().manager, .version = 1 },
};

const seat_name = "seat0";

/// What a selection holds.
const Owner = union(enum) {
    none,
    /// The user's clipboard. Only the clipboard holds it.
    user: Mimes,
    source: *Source,
};

/// Owned MIME types.
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
    /// Counts each selection's changes. An offer stays valid until its
    /// selection's generation moves on.
    generations: std.EnumArray(Selection, u64) = .initFill(0),

    pub fn init(gpa: Allocator, backend: Backend) Server {
        return .{ .gpa = gpa, .backend = backend };
    }

    /// Closes every connection, without calling the backend.
    pub fn deinit(s: *Server) void {
        if (s.selections.getPtr(.clipboard).* == .user) freeMimes(s.gpa, &s.selections.getPtr(.clipboard).user);
        s.selections = .initFill(.none);
        while (s.connections.items.len > 0) s.disconnect(s.connections.items[s.connections.items.len - 1]);
        s.connections.deinit(s.gpa);
        s.* = undefined;
    }

    /// A program connected.
    pub fn connect(s: *Server) Allocator.Error!*Connection {
        const conn = try s.gpa.create(Connection);
        errdefer s.gpa.destroy(conn);
        conn.* = .{ .server = s };
        try conn.objects.put(s.gpa, display.id, .{ .version = 1, .kind = .display });
        errdefer conn.objects.deinit(s.gpa);
        try s.connections.append(s.gpa, conn);
        return conn;
    }

    /// A program's connection closed, or is being closed. Its data sources
    /// leave the selections they held, and its file descriptors close.
    pub fn disconnect(s: *Server, conn: *Connection) void {
        const index = std.mem.indexOfScalar(*Connection, s.connections.items, conn).?;
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

    /// Sets the clipboard to the user's, offered as `mimes`, or clears it
    /// (null). A program's source that held it is cancelled. MIME types
    /// that are too long or have a NUL are left out.
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

    /// Asks the program whose source holds `selection` to write it as
    /// `mime` to `fd`. Takes `fd`. False, with `fd` closed, if no program's
    /// source holds the selection or it doesn't offer `mime`.
    pub fn read(s: *Server, selection: Selection, mime: []const u8, fd: fd_t) bool {
        switch (s.selections.get(selection)) {
            .source => |source| if (source.offers(mime) and !source.conn.failed) {
                source.conn.send(source.id, @backingInt(data_control.source.Event.send), &.{ .{ .string = mime }, .{ .fd = fd } });
                // Out of memory fails the connection, and the event, with
                // its descriptor, isn't queued.
                if (!source.conn.failed) return true;
            },
            else => {},
        }
        close(fd);
        return false;
    }

    /// Replaces what `selection` holds, and cancels a source it replaces.
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

    /// Stores what `selection` holds now, and tells every data device.
    fn changed(s: *Server, selection: Selection, owner: Owner) void {
        s.selections.set(selection, owner);
        s.generations.getPtr(selection).* += 1;
        for (s.connections.items) |conn| {
            for (conn.devices.items) |id| conn.sendSelection(id, selection);
        }
    }

    /// Tells the backend what a program set `selection` to.
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

    /// A source is going away: it stops holding any selection, without
    /// being told.
    fn dropSource(s: *Server, source: *Source) void {
        for ([_]Selection{ .clipboard, .primary }) |selection| {
            const owner = s.selections.get(selection);
            if (owner == .source and owner.source == source) {
                s.changed(selection, .none);
                s.copied(selection);
            }
        }
    }

    /// `receive` on an offer.
    fn receive(s: *Server, offer: Offer, mime: []const u8, fd: fd_t) void {
        // An offer of what the selection held before gets no data.
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

/// A program's data source.
const Source = struct {
    conn: *Connection,
    id: u32,
    mimes: Mimes = .empty,
    /// A selection has been set to it. It can't be set again, and offers
    /// no more types.
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

/// An offer of what a selection held when the offer was made.
const Offer = struct {
    selection: Selection,
    generation: u64,
};

pub const Connection = struct {
    server: *Server,
    objects: std.AutoHashMapUnmanaged(u32, Object) = .empty,
    /// The IDs of the connection's data devices, in the order they were
    /// made.
    devices: std.ArrayList(u32) = .empty,
    /// Received descriptors that no request has taken yet. The caller adds
    /// to the back; at most `max_pending_fds`.
    fds: std.Deque(fd_t) = .empty,
    /// Events to send. Its descriptors close once they are sent.
    out: wire.Outbox = .{},
    /// The next ID for an object the server makes.
    next_server_id: u32 = protocol.server_id_start,
    /// A protocol error was sent, and the connection takes no more
    /// requests. It closes once `out` is sent.
    failed: bool = false,

    /// Handles the complete requests at the start of `bytes`, and returns
    /// the bytes they took. The rest is the start of a request.
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
        /// The error is sent, and the connection has failed.
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

            // wl_callback has no requests.
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
                .release => return error.UnknownOpcode,
            },

            // A surface is never shown. Its requests are ignored, except
            // that the callbacks it makes are kept, and never called.
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
                    try conn.devices.ensureUnusedCapacity(conn.server.gpa, 1);
                    try conn.add(new, .{ .version = object.version, .kind = .{ .device = p } });
                    conn.devices.appendAssumeCapacity(new);

                    // The device starts with what the selections hold.
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

    /// `wl_registry.bind`: a global's name, its interface's name, the
    /// version, and the new object's ID.
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

    /// An output of one pixel, which no surface is ever shown on.
    fn sendOutput(conn: *Connection, id: u32, version: u32) void {
        const Event = protocol.output.Event;
        conn.send(id, @backingInt(Event.geometry), &.{
            .{ .int = 0 },              .{ .int = 0 },
            .{ .int = 0 },              .{ .int = 0 },
            .{ .int = 0 },              .{ .string = "tx" },
            .{ .string = "clipboard" }, .{ .int = 0 },
        });
        const mode = protocol.output.Mode.current | protocol.output.Mode.preferred;
        conn.send(id, @backingInt(Event.mode), &.{ .{ .uint = mode }, .{ .int = 1 }, .{ .int = 1 }, .{ .int = 60_000 } });
        if (version >= 2) conn.send(id, @backingInt(Event.scale), &.{.{ .int = 1 }});
        if (version >= 4) {
            conn.send(id, @backingInt(Event.name), &.{.{ .string = "TX-1" }});
            conn.send(id, @backingInt(Event.description), &.{.{ .string = "tx clipboard server, no display" }});
        }
        if (version >= 2) conn.send(id, @backingInt(Event.done), &.{});
    }

    /// `set_selection` or `set_primary_selection` on a device.
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

    /// Tells data device `id` what `selection` holds, with a new offer.
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

    /// A new_id argument: a free ID in the program's range.
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

    /// A destructor request: the object goes, and its ID is free again.
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
        // A program reuses an ID it made only after the server says it's
        // done with it. The server's own IDs aren't the program's to reuse.
        if (id < protocol.server_id_start) conn.deleted(id);
    }

    fn deleted(conn: *Connection, id: u32) void {
        conn.send(display.id, @backingInt(display.Event.delete_id), &.{.{ .uint = id }});
    }

    /// Queues an event. Out of memory fails the connection.
    fn send(conn: *Connection, object: u32, opcode: u16, args: []const wire.Arg) void {
        if (conn.failed) return;
        conn.out.event(conn.server.gpa, object, opcode, args) catch |err| switch (err) {
            error.OutOfMemory => conn.failed = true,
            // MIME types are checked when they arrive.
            error.MessageTooLong, error.BadString => unreachable,
        };
    }

    /// Sends a protocol error, with `code` from the interface's `Error`
    /// or `display.Error`. The connection takes no more requests.
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

/// zwlr data control has the primary selection from version 2, ext from
/// version 1.
fn hasPrimary(p: Protocol, version: u32) bool {
    return p == .ext or version >= 2;
}

/// The request with `opcode` in `Request`.
fn request(comptime Request: type, opcode: u16) error{UnknownOpcode}!Request {
    return std.enums.fromInt(Request, opcode) orelse error.UnknownOpcode;
}

fn close(fd: fd_t) void {
    _ = c.close(fd);
}

const testing = std.testing;

/// What the backend saw.
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

/// A program on a connection. It sends requests, and reads the events
/// it gets as lines of text, such as `registry.global 1 "wl_seat" 7`,
/// using what it knows of each object's interface.
const TestProgram = struct {
    conn: *Connection,
    interfaces: std.AutoHashMapUnmanaged(u32, Interface) = .empty,
    next_id: u32 = 2,
    /// Descriptors from events, which the test owns.
    fds: std.ArrayList(fd_t) = .empty,
    /// The server's offers, in the order they came. Events show them as
    /// `o1`, `o2` and so on.
    offers: std.ArrayList(u32) = .empty,

    const Interface = enum { display, registry, callback, seat, output, manager, device, source, offer };

    /// Each event's arguments, by interface and opcode: `u` uint, `i`
    /// int, `s` string, `f` fd, `o` object, `n` a new offer.
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

    /// The ID of offer `o{n}`.
    fn offer(p: *const TestProgram, n: usize) u32 {
        return p.offers.items[n - 1];
    }

    /// A new object of `interface`, for a new_id argument.
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

    /// The registry, with the globals' events read.
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

    /// The events since the last call, one per line. Descriptors are
    /// shown as `fd`, and kept in `fds`.
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

    /// A data device on the given manager.
    fn device(p: *TestProgram, manager: u32, seat_id: u32) !u32 {
        const id = try p.new(.device);
        try p.request(manager, @backingInt(data_control.manager.Request.get_data_device), &.{ .{ .uint = id }, .{ .uint = seat_id } });
        return id;
    }

    /// A source offering `mimes`.
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

/// Whether the write end of the pipe whose read end is `fd` is closed,
/// and nothing was written.
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

    // sync answers at once, and frees the callback's ID.
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

    // wl-copy, on zwlr data control.
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

    // The copier's own device sees its copy too.
    try copier.expectEvents(
        \\device.data_offer o1
        \\offer.offer "text/plain"
        \\offer.offer "text/plain;charset=utf-8"
        \\device.selection o1
        \\
    );

    // wl-paste, on ext data control, starts with the copy.
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

    // Its read goes to the copier with the pipe it sent.
    const fds = try pipe();
    defer close(fds[0]);
    try paster.request(paster.offer(1), @backingInt(data_control.offer.Request.receive), &.{ .{ .string = "text/plain" }, .{ .fd = fds[1] } });
    try copier.expectEvents("source.send \"text/plain\" fd\n");
    try testing.expectEqual(fds[1], copier.fds.items[0]);

    // A type that wasn't offered gets no data.
    const other = try pipe();
    defer close(other[0]);
    try paster.request(paster.offer(1), @backingInt(data_control.offer.Request.receive), &.{ .{ .string = "image/png" }, .{ .fd = other[1] } });
    try testing.expect(closedEmpty(other[0]));
    try copier.expectEvents("");

    // The backend reads it the same way.
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

    // The copy is cancelled, so a background wl-copy exits.
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

    // An offer made before the clipboard changed gets no data.
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
        /// Sends the requests that end in the error.
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
                    // An ID the program already uses.
                    try p.request(display.id, @backingInt(display.Request.get_registry), &.{.{ .uint = 2 }});
                }
            }.f,
            .want = "display.error 1 0 \"invalid new ID\"\n",
        },
        .{
            .run = struct {
                fn f(p: *TestProgram, registry: u32) !void {
                    const manager = try p.bind(registry, 4, .manager, 2);
                    // receive with no descriptor.
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

        // Nothing more is handled.
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
            // Every descriptor the programs send is closed in the end.
            const open_before = openFds();
            defer std.debug.assert(openFds() == open_before);

            var server: Server = .init(testing.allocator, .{ .fetch = closeFetch, .copied = ignoreCopy });
            defer server.deinit();
            var programs = [2]*Connection{ try server.connect(), try server.connect() };

            // Each program starts as wl-paste and wl-copy do, so that
            // random requests mostly reach real objects: the registry is
            // 2, the globals 3 to 7, devices 8 and 9, and sources 10
            // and 11.
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

                // The backend's side.
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

                // A program that failed is closed and replaced.
                if (conn.failed or in.chance(1, 30)) {
                    server.disconnect(conn);
                    programs[which] = try server.connect();
                    continue;
                }

                // A request to a likely object, with arguments of random
                // types: words that are often IDs, MIME types and pipes.
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

                // What the program didn't take, and the events' descriptors,
                // as the I/O layer would close them.
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
