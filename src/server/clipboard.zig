//! The user's clipboard, for programs on the host. Linux only, with the
//! clipboard server (see `wayland`).
//!
//! Programs read the clipboard of the provider: the attached client that
//! sent input last, or before any did, the first to offer. A read asks the
//! provider for the type (`proto.ClipboardRequest`). Reads of one type
//! share one request, and the answer is kept until the clipboard changes.
//! The client decides whether to answer: it does only just after the user
//! pasted.
//!
//! A program's copy is read at once, in full, since the program may exit
//! before anyone pastes. txd then holds it: the program's source is
//! cancelled, so a `wl-copy` waiting in the background exits, and txd
//! serves the copy to other programs itself. The provider gets it for the
//! user's clipboard. The primary selection stays among the programs.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const xev = @import("xev");
const proto = @import("proto");
const wayland = @import("wayland");

const Blob = wayland.pipe.Blob;
const fd_t = posix.fd_t;

const log = std.log.scoped(.clipboard);

/// How long a read waits for the provider to start answering. arboard,
/// which Codex uses, gives up after 4 seconds.
const answer_timeout_ms = 1500;
/// How long an answer may take once it has started.
const transfer_timeout_ms = 30_000;
/// How long reading a program's copy may take.
const copy_timeout_ms = 2000;
/// The most a program's copy holds, in all its types.
pub const max_copy_len = 64 << 20;
/// The most types of a copy that are read.
const max_copy_types = 16;
/// How often the deadlines are checked, while any are pending.
const sweep_ms = 250;

/// A client, as the clipboard sees it.
pub const Peer = struct {
    /// Sends the client `proto.ClipboardRequest`.
    request: *const fn (peer: *Peer, m: proto.ClipboardRequest) void,
    /// Sends the client a program's copy: its types and their data.
    copy: *const fn (peer: *Peer, mimes: []const []const u8, data: []const *Blob) void,
    /// The client's last offer.
    offer: ?Offer = null,

    pub const Offer = struct {
        change: u64,
        mimes: [][]u8,
    };

    /// Frees the offer. `gpa` is the clipboard's.
    pub fn dropOffer(peer: *Peer, gpa: Allocator) void {
        const offer = peer.offer orelse return;
        for (offer.mimes) |m| gpa.free(m);
        gpa.free(offer.mimes);
        peer.offer = null;
    }
};

pub const Clipboard = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    listener: *wayland.Listener,
    provider: ?*Peer = null,
    /// What programs read: the provider's offer, or a program's copy txd
    /// read.
    holding: enum { nothing, offer, copy } = .nothing,
    /// A program's copy, read in full.
    copy: Copy = .{},
    /// Reading a program's copy.
    reading: ?Reading = null,
    /// Answers to the provider's current offer, by type.
    answers: std.StringArrayHashMapUnmanaged(*Blob) = .empty,
    requests: std.ArrayList(*Request) = .empty,
    next_id: u64 = 1,
    timer: xev.Timer,
    timer_c: xev.Completion = .{},
    closing: bool = false,

    const Copy = struct {
        mimes: std.ArrayList([]u8) = .empty,
        data: std.ArrayList(*Blob) = .empty,

        fn deinit(copy: *Copy, gpa: Allocator) void {
            for (copy.mimes.items) |m| gpa.free(m);
            for (copy.data.items) |blob| blob.unref();
            copy.mimes.deinit(gpa);
            copy.data.deinit(gpa);
            copy.* = .{};
        }
    };

    /// Reading a program's copy, one type at a time.
    const Reading = struct {
        /// The types to read. `copy` collects what has been read.
        mimes: std.ArrayList([]u8),
        next: usize = 0,
        copy: Copy = .{},
        reader: ?*wayland.pipe.Reader = null,
        deadline: i64,
    };

    /// A read waiting for the provider.
    const Request = struct {
        id: u64,
        peer: *Peer,
        change: u64,
        mime: []u8,
        /// The pipes waiting for the data.
        fds: std.ArrayList(fd_t) = .empty,
        /// The answer has started.
        started: bool = false,
        deadline: i64,
    };

    /// Starts the clipboard server at `path`.
    pub fn create(gpa: Allocator, io: Io, loop: *xev.Loop, path: []const u8) !*Clipboard {
        const cb = try gpa.create(Clipboard);
        errdefer gpa.destroy(cb);
        cb.* = .{ .gpa = gpa, .io = io, .loop = loop, .listener = undefined, .timer = try .init() };
        errdefer cb.timer.deinit();
        cb.listener = try wayland.Listener.create(gpa, loop, path, .{ .context = cb, .fetch = fetch, .copied = copied });
        return cb;
    }

    /// Stops the server. Pending reads get no data. It's freed now, or by
    /// the deadline timer when that's running, which ends within
    /// `sweep_ms`.
    pub fn close(cb: *Clipboard) void {
        cb.closing = true;
        cb.listener.close();
        while (cb.requests.pop()) |req| cb.endRequest(req);
        cb.stopReading();
        cb.provider = null;
        cb.dropAnswers();
        cb.copy.deinit(cb.gpa);
        if (cb.timer_c.state() != .active) cb.destroy();
    }

    fn destroy(cb: *Clipboard) void {
        cb.answers.deinit(cb.gpa);
        cb.requests.deinit(cb.gpa);
        cb.timer.deinit();
        cb.gpa.destroy(cb);
    }

    /// The client sent input. It provides the clipboard from now on, with
    /// its last offer.
    pub fn input(cb: *Clipboard, peer: *Peer) void {
        if (cb.provider == peer) return;
        cb.provider = peer;
        if (peer.offer != null) cb.useOffer();
    }

    /// The client's clipboard changed. Takes nothing: `mimes` is copied.
    pub fn offer(cb: *Clipboard, peer: *Peer, change: u64, mimes: []const []const u8) void {
        peer.dropOffer(cb.gpa);
        const owned = cb.gpa.alloc([]u8, mimes.len) catch return;
        for (mimes, 0..) |m, i| owned[i] = cb.gpa.dupe(u8, m) catch {
            for (owned[0..i]) |done| cb.gpa.free(done);
            cb.gpa.free(owned);
            return;
        };
        peer.offer = .{ .change = change, .mimes = owned };

        if (cb.provider == null) cb.provider = peer;
        if (cb.provider == peer) cb.useOffer();
    }

    /// The client is gone, or no longer attached.
    pub fn gone(cb: *Clipboard, peer: *Peer) void {
        var i: usize = cb.requests.items.len;
        while (i > 0) {
            i -= 1;
            if (cb.requests.items[i].peer == peer) cb.endRequest(cb.requests.swapRemove(i));
        }
        peer.dropOffer(cb.gpa);
        if (cb.provider != peer) return;
        cb.provider = null;
        if (cb.holding == .offer) {
            cb.holding = .nothing;
            cb.dropAnswers();
            cb.listener.setClipboard(null) catch {};
        }
    }

    /// The client's answer to request `id` began.
    pub fn answerStarted(cb: *Clipboard, peer: *Peer, id: u64) void {
        const req = cb.findRequest(peer, id) orelse return;
        req.started = true;
        req.deadline = cb.now() + transfer_timeout_ms;
    }

    /// The client's answer to request `id`: its data, which this takes, or
    /// null if it refused.
    pub fn answer(cb: *Clipboard, peer: *Peer, id: u64, data: ?[]u8) void {
        const req = cb.findRequest(peer, id) orelse {
            if (data) |d| cb.gpa.free(d);
            return;
        };
        _ = cb.requests.swapRemove(std.mem.indexOfScalar(*Request, cb.requests.items, req).?);
        defer cb.endRequest(req);
        const bytes = data orelse return;
        const blob = Blob.create(cb.gpa, bytes) catch return;
        defer blob.unref();

        // Kept for later reads while the offer is current.
        const current = cb.provider == peer and cb.holding == .offer and peer.offer != null and peer.offer.?.change == req.change;
        if (current) cb.keepAnswer(req.mime, blob);
        for (req.fds.items) |fd| wayland.pipe.write(cb.gpa, cb.loop, fd, blob.ref());
        req.fds.clearRetainingCapacity();
    }

    /// The provider's offer is what programs read now.
    fn useOffer(cb: *Clipboard) void {
        const peer = cb.provider.?;
        const o = peer.offer.?;
        cb.stopReading();
        cb.copy.deinit(cb.gpa);
        cb.dropAnswers();
        cb.holding = .offer;
        const mimes: []const []const u8 = @ptrCast(o.mimes);
        cb.listener.setClipboard(if (mimes.len == 0) null else mimes) catch {
            cb.holding = .nothing;
        };
    }

    // The clipboard server's backend.

    fn fetch(context: ?*anyopaque, mime: []const u8, fd: fd_t) void {
        const cb: *Clipboard = @ptrCast(@alignCast(context.?));
        switch (cb.holding) {
            .nothing => closeFd(fd),
            .copy => {
                for (cb.copy.mimes.items, cb.copy.data.items) |m, blob| {
                    if (std.mem.eql(u8, m, mime)) return wayland.pipe.write(cb.gpa, cb.loop, fd, blob.ref());
                }
                closeFd(fd);
            },
            .offer => cb.fetchFromProvider(mime, fd),
        }
    }

    fn fetchFromProvider(cb: *Clipboard, mime: []const u8, fd: fd_t) void {
        const peer = cb.provider orelse return closeFd(fd);
        const change = (peer.offer orelse return closeFd(fd)).change;
        if (cb.answers.get(mime)) |blob| return wayland.pipe.write(cb.gpa, cb.loop, fd, blob.ref());

        // A read of the same type waiting already takes this one too.
        for (cb.requests.items) |req| {
            if (req.peer == peer and req.change == change and std.mem.eql(u8, req.mime, mime)) {
                req.fds.append(cb.gpa, fd) catch closeFd(fd);
                return;
            }
        }

        const req = cb.newRequest(peer, change, mime, fd) catch return closeFd(fd);
        peer.request(peer, .{ .id = req.id, .change = change, .mime = mime });
        cb.armTimer();
    }

    fn newRequest(cb: *Clipboard, peer: *Peer, change: u64, mime: []const u8, fd: fd_t) Allocator.Error!*Request {
        const req = try cb.gpa.create(Request);
        errdefer cb.gpa.destroy(req);
        req.* = .{ .id = cb.next_id, .peer = peer, .change = change, .mime = try cb.gpa.dupe(u8, mime), .deadline = cb.now() + answer_timeout_ms };
        errdefer cb.gpa.free(req.mime);
        try req.fds.append(cb.gpa, fd);
        errdefer req.fds.deinit(cb.gpa);
        try cb.requests.append(cb.gpa, req);
        cb.next_id += 1;
        return req;
    }

    /// Frees a request that has been removed from `requests`. Pipes still
    /// waiting get no data.
    fn endRequest(cb: *Clipboard, req: *Request) void {
        for (req.fds.items) |fd| closeFd(fd);
        req.fds.deinit(cb.gpa);
        cb.gpa.free(req.mime);
        cb.gpa.destroy(req);
    }

    fn findRequest(cb: *Clipboard, peer: *Peer, id: u64) ?*Request {
        for (cb.requests.items) |req| if (req.peer == peer and req.id == id) return req;
        return null;
    }

    fn keepAnswer(cb: *Clipboard, mime: []const u8, blob: *Blob) void {
        if (cb.answers.contains(mime)) return;
        const key = cb.gpa.dupe(u8, mime) catch return;
        cb.answers.put(cb.gpa, key, blob.ref()) catch {
            cb.gpa.free(key);
            blob.unref();
        };
    }

    fn dropAnswers(cb: *Clipboard) void {
        var it = cb.answers.iterator();
        while (it.next()) |entry| {
            cb.gpa.free(entry.key_ptr.*);
            entry.value_ptr.*.unref();
        }
        cb.answers.clearRetainingCapacity();
    }

    /// A program copied, or cleared the clipboard. Its copy is read, and
    /// held once read.
    fn copied(context: ?*anyopaque, selection: wayland.Selection, mimes: ?[]const []const u8) void {
        const cb: *Clipboard = @ptrCast(@alignCast(context.?));
        if (selection != .clipboard or cb.closing) return;
        cb.stopReading();
        const list = mimes orelse return;
        if (list.len == 0) return;

        var reading: Reading = .{ .mimes = .empty, .deadline = cb.now() + copy_timeout_ms };
        for (list[0..@min(list.len, max_copy_types)]) |m| {
            const owned = cb.gpa.dupe(u8, m) catch break;
            reading.mimes.append(cb.gpa, owned) catch {
                cb.gpa.free(owned);
                break;
            };
        }
        cb.reading = reading;
        cb.readNext();
        cb.armTimer();
    }

    /// Asks the program for the next type of its copy, or holds the copy
    /// once all are read.
    fn readNext(cb: *Clipboard) void {
        const r = if (cb.reading) |*r| r else return;
        while (r.next < r.mimes.items.len) {
            const mime = r.mimes.items[r.next];
            const fds = pipe() catch return cb.finishReading();
            if (!cb.listener.read(.clipboard, mime, fds[1])) {
                // The program's source is gone.
                closeFd(fds[0]);
                return cb.finishReading();
            }
            var used: usize = 0;
            for (r.copy.data.items) |blob| used += blob.bytes.len;
            r.reader = wayland.pipe.Reader.start(cb.gpa, cb.loop, fds[0], max_copy_len - used, .{ .context = cb, .done = onCopyRead }) catch return cb.finishReading();
            return;
        }
        cb.finishReading();
    }

    fn onCopyRead(context: ?*anyopaque, _: *wayland.pipe.Reader, result: wayland.pipe.Reader.Result) void {
        const cb: *Clipboard = @ptrCast(@alignCast(context.?));
        const r = if (cb.reading) |*r| r else {
            if (result == .done) cb.gpa.free(result.done);
            return;
        };
        r.reader = null;
        switch (result) {
            .done => |bytes| {
                const mime = cb.gpa.dupe(u8, r.mimes.items[r.next]) catch {
                    cb.gpa.free(bytes);
                    return cb.finishReading();
                };
                r.next += 1;
                r.copy.mimes.append(cb.gpa, mime) catch {
                    cb.gpa.free(mime);
                    cb.gpa.free(bytes);
                    return cb.finishReading();
                };
                const blob = Blob.create(cb.gpa, bytes) catch {
                    cb.gpa.free(r.copy.mimes.pop().?);
                    return cb.finishReading();
                };
                r.copy.data.append(cb.gpa, blob) catch {
                    blob.unref();
                    cb.gpa.free(r.copy.mimes.pop().?);
                    return cb.finishReading();
                };
                cb.readNext();
            },
            // What was read is kept.
            .too_long, .failed => cb.finishReading(),
        }
    }

    /// Holds what was read of the program's copy, and sends it to the
    /// provider. With nothing read, the program keeps serving its copy.
    fn finishReading(cb: *Clipboard) void {
        var r = cb.reading orelse return;
        cb.reading = null;
        defer {
            for (r.mimes.items) |m| cb.gpa.free(m);
            r.mimes.deinit(cb.gpa);
        }
        if (r.reader) |reader| abandon(reader);
        if (r.copy.mimes.items.len == 0) return r.copy.deinit(cb.gpa);

        cb.copy.deinit(cb.gpa);
        cb.copy = r.copy;
        cb.dropAnswers();
        cb.holding = .copy;
        const mimes: []const []const u8 = @ptrCast(cb.copy.mimes.items);
        cb.listener.setClipboard(mimes) catch {};
        if (cb.provider) |peer| peer.copy(peer, mimes, cb.copy.data.items);
    }

    /// Drops a copy being read: another replaced it.
    fn stopReading(cb: *Clipboard) void {
        var r = cb.reading orelse return;
        cb.reading = null;
        if (r.reader) |reader| abandon(reader);
        for (r.mimes.items) |m| cb.gpa.free(m);
        r.mimes.deinit(cb.gpa);
        r.copy.deinit(cb.gpa);
    }

    // Deadlines.

    fn now(cb: *const Clipboard) i64 {
        return Io.Clock.awake.now(cb.io).toMilliseconds();
    }

    fn armTimer(cb: *Clipboard) void {
        if (cb.timer_c.state() == .active) return;
        cb.timer.run(cb.loop, &cb.timer_c, sweep_ms, Clipboard, cb, onTimer);
    }

    fn onTimer(cb_: ?*Clipboard, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const cb = cb_.?;
        if (cb.closing) {
            cb.destroy();
            return .disarm;
        }
        result catch return .disarm;
        const t = cb.now();

        var i: usize = cb.requests.items.len;
        while (i > 0) {
            i -= 1;
            const req = cb.requests.items[i];
            if (t < req.deadline) continue;
            log.debug("a read of {s} timed out", .{req.mime});
            cb.endRequest(cb.requests.swapRemove(i));
        }
        if (cb.reading) |r| if (t >= r.deadline) cb.finishReading();

        if (cb.requests.items.len > 0 or cb.reading != null) {
            cb.timer.run(cb.loop, &cb.timer_c, sweep_ms, Clipboard, cb, onTimer);
        }
        return .disarm;
    }
};

/// Cancels a read whose result nobody wants any more. The reader may
/// outlive the clipboard, so it no longer calls it.
fn abandon(reader: *wayland.pipe.Reader) void {
    reader.handler = .{ .context = null, .done = dropRead };
    reader.cancel();
}

fn dropRead(_: ?*anyopaque, reader: *wayland.pipe.Reader, result: wayland.pipe.Reader.Result) void {
    if (result == .done) reader.gpa.free(result.done);
}

fn pipe() ![2]fd_t {
    var fds: [2]fd_t = undefined;
    if (std.os.linux.errno(std.os.linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.SystemResources;
    return fds;
}

fn closeFd(fd: fd_t) void {
    _ = std.os.linux.close(fd);
}
