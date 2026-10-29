//! Clipboard data through the pipes programs pass, on the loop.
//!
//! Linux only, as `socket` is: the loop says when a pipe is ready, and the
//! reads and writes are plain, non-blocking ones.
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const linux = std.os.linux;
const xev = @import("xev");

const fd_t = posix.fd_t;

/// Bytes that several writers may be sending at once. Freed with the last
/// reference.
pub const Blob = struct {
    gpa: Allocator,
    refs: usize = 1,
    bytes: []u8,

    /// Takes `bytes`, which `gpa` allocated. On error they are freed.
    pub fn create(gpa: Allocator, bytes: []u8) Allocator.Error!*Blob {
        errdefer gpa.free(bytes);
        const blob = try gpa.create(Blob);
        blob.* = .{ .gpa = gpa, .bytes = bytes };
        return blob;
    }

    pub fn ref(blob: *Blob) *Blob {
        blob.refs += 1;
        return blob;
    }

    pub fn unref(blob: *Blob) void {
        blob.refs -= 1;
        if (blob.refs > 0) return;
        blob.gpa.free(blob.bytes);
        blob.gpa.destroy(blob);
    }
};

/// Writes `blob` to `fd`, then closes it. Takes `fd` and a reference to
/// `blob`. A program that closes its end, or never reads, ends the write
/// when it exits.
pub fn write(gpa: Allocator, loop: *xev.Loop, fd: fd_t, blob: *Blob) void {
    setNonblocking(fd);
    const w = gpa.create(Writer) catch {
        close(fd);
        return blob.unref();
    };
    w.* = .{ .gpa = gpa, .loop = loop, .fd = fd, .blob = blob };
    if (w.writeSome()) w.wait() else w.destroy();
}

const Writer = struct {
    gpa: Allocator,
    loop: *xev.Loop,
    fd: fd_t,
    blob: *Blob,
    written: usize = 0,
    c: xev.Completion = .{},

    /// Writes as much as the pipe takes. True if there's more to write
    /// once it has room.
    fn writeSome(w: *Writer) bool {
        while (w.written < w.blob.bytes.len) {
            const rest = w.blob.bytes[w.written..];
            const rc = linux.write(w.fd, rest.ptr, rest.len);
            switch (linux.errno(rc)) {
                .SUCCESS => w.written += rc,
                .INTR => {},
                .AGAIN => return true,
                else => return false,
            }
        }
        return false;
    }

    fn wait(w: *Writer) void {
        w.c = .{
            .op = .{ .poll = .{ .fd = w.fd, .events = posix.POLL.OUT } },
            .userdata = w,
            .callback = onWritable,
        };
        w.loop.add(&w.c);
    }

    fn onWritable(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, result: xev.Result) xev.CallbackAction {
        const w: *Writer = @ptrCast(@alignCast(ud.?));
        _ = result.poll catch {
            w.destroy();
            return .disarm;
        };
        if (w.writeSome()) return .rearm;
        w.destroy();
        return .disarm;
    }

    fn destroy(w: *Writer) void {
        close(w.fd);
        w.blob.unref();
        w.gpa.destroy(w);
    }
};

/// Reads a pipe to its end, up to `limit` bytes, then calls `done`.
/// `cancel` ends it sooner. It frees itself once the loop is done with it.
pub const Reader = struct {
    gpa: Allocator,
    loop: *xev.Loop,
    fd: fd_t,
    limit: usize,
    bytes: std.ArrayList(u8) = .empty,
    handler: Handler,
    c: xev.Completion = .{},
    cancel_c: xev.Completion = .{},
    /// The poll is in flight, or its callback is running.
    polling: bool = true,
    /// So is the cancel.
    canceling: bool = false,

    pub const Result = union(enum) {
        /// The pipe's end came. The caller owns the bytes.
        done: []u8,
        /// More than `limit` bytes.
        too_long,
        /// The read failed, or was canceled.
        failed,
    };

    pub const Handler = struct {
        context: ?*anyopaque,
        /// Called once. The reader can't be canceled after.
        done: *const fn (context: ?*anyopaque, reader: *Reader, result: Result) void,
    };

    /// Takes `fd`.
    pub fn start(gpa: Allocator, loop: *xev.Loop, fd: fd_t, limit: usize, handler: Handler) Allocator.Error!*Reader {
        errdefer close(fd);
        setNonblocking(fd);
        const r = try gpa.create(Reader);
        r.* = .{ .gpa = gpa, .loop = loop, .fd = fd, .limit = limit, .handler = handler };
        r.c = .{
            .op = .{ .poll = .{ .fd = fd, .events = posix.POLL.IN } },
            .userdata = r,
            .callback = onReadable,
        };
        loop.add(&r.c);
        return r;
    }

    /// Ends the read. `done` follows, with `failed`, from the loop.
    pub fn cancel(r: *Reader) void {
        if (r.canceling or !r.polling) return;
        r.canceling = true;
        r.cancel_c = .{
            .op = .{ .cancel = .{ .c = &r.c } },
            .userdata = r,
            .callback = onCanceled,
        };
        r.loop.add(&r.cancel_c);
    }

    fn onReadable(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, result: xev.Result) xev.CallbackAction {
        const r: *Reader = @ptrCast(@alignCast(ud.?));
        _ = result.poll catch return r.finish(.failed);

        var buf: [64 << 10]u8 = undefined;
        while (true) {
            const rc = linux.read(r.fd, &buf, buf.len);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return .rearm,
                else => return r.finish(.failed),
            }
            if (rc == 0) {
                const bytes = r.bytes.toOwnedSlice(r.gpa) catch return r.finish(.failed);
                return r.finish(.{ .done = bytes });
            }
            if (r.bytes.items.len + rc > r.limit) return r.finish(.too_long);
            r.bytes.appendSlice(r.gpa, buf[0..rc]) catch return r.finish(.failed);
        }
    }

    fn onCanceled(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, _: xev.Result) xev.CallbackAction {
        const r: *Reader = @ptrCast(@alignCast(ud.?));
        r.canceling = false;
        r.freeIfDone();
        return .disarm;
    }

    fn finish(r: *Reader, result: Result) xev.CallbackAction {
        close(r.fd);
        r.bytes.deinit(r.gpa);
        r.polling = false;
        r.handler.done(r.handler.context, r, result);
        r.freeIfDone();
        return .disarm;
    }

    fn freeIfDone(r: *Reader) void {
        if (r.polling or r.canceling) return;
        r.gpa.destroy(r);
    }
};

fn setNonblocking(fd: fd_t) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return;
    const nonblock: u32 = @bitCast(linux.O{ .NONBLOCK = true });
    _ = linux.fcntl(fd, linux.F.SETFL, flags | nonblock);
}

fn close(fd: fd_t) void {
    _ = linux.close(fd);
}
