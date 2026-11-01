const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const linux = std.os.linux;
const xev = @import("xev");
const wire = @import("wire.zig");
const server_pkg = @import("server.zig");

const Server = server_pkg.Server;
const Connection = server_pkg.Connection;
const Backend = server_pkg.Backend;
const Selection = server_pkg.Selection;
const fd_t = posix.fd_t;

const log = std.log.scoped(.wayland);

// libwayland's MAX_FDS_OUT. libwayland sends at most this many descriptors
// per sendmsg, and has room for this many in a recvmsg.
const max_fds_per_send = 28;

// CMSG_SPACE for count descriptors.
fn controlLen(count: usize) usize {
    return @sizeOf(linux.cmsghdr) + std.mem.alignForward(usize, count * @sizeOf(fd_t), linux.cmsg_align);
}

pub const Error = error{
    NameTooLong,
    AddressInUse,
    SystemResources,
    Unexpected,
} || Allocator.Error;

pub const Listener = struct {
    gpa: Allocator,
    loop: *xev.Loop,
    server: Server,
    fd: fd_t,
    accept_c: xev.Completion = .{},
    accepting: bool = false,
    clients: std.ArrayList(*Client) = .empty,
    closing: bool = false,

    /// Listens at path and starts accepting. A socket file there that refuses
    /// connections is removed first.
    pub fn create(gpa: Allocator, loop: *xev.Loop, path: []const u8, backend: Backend) Error!*Listener {
        const fd = try listen(path);
        errdefer closeFd(fd);
        const l = try gpa.create(Listener);
        l.* = .{ .gpa = gpa, .loop = loop, .server = .init(gpa, backend), .fd = fd };
        l.startAccept();
        return l;
    }

    /// Stops accepting and closes every connection. The backend isn't called
    /// after close. The Listener frees itself on the loop once its polls end.
    pub fn close(l: *Listener) void {
        if (l.closing) return;
        l.closing = true;
        l.server.backend = .{ .fetch = closeFetch, .copied = ignoreCopy };
        _ = linux.shutdown(l.fd, linux.SHUT.RDWR);
        for (l.clients.items) |client| client.close();
        l.freeIfDone();
    }

    pub fn setClipboard(l: *Listener, mimes: ?[]const []const u8) Allocator.Error!void {
        defer l.flush();
        return l.server.setClipboard(mimes);
    }

    pub fn read(l: *Listener, selection: Selection, mime: []const u8, fd: fd_t) bool {
        defer l.flush();
        return l.server.read(selection, mime, fd);
    }

    fn flush(l: *Listener) void {
        for (l.clients.items) |client| client.flush();
    }

    fn startAccept(l: *Listener) void {
        l.accepting = true;
        l.accept_c = .{
            .op = .{ .poll = .{ .fd = l.fd, .events = posix.POLL.IN } },
            .userdata = l,
            .callback = onAcceptable,
        };
        l.loop.add(&l.accept_c);
    }

    fn onAcceptable(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, result: xev.Result) xev.CallbackAction {
        const l: *Listener = @ptrCast(@alignCast(ud.?));
        _ = result.poll catch {};
        if (!l.closing) {
            while (l.acceptOne()) {}
            if (!l.closing) return .rearm;
        }
        l.accepting = false;
        l.freeIfDone();
        return .disarm;
    }

    fn acceptOne(l: *Listener) bool {
        const rc = linux.accept4(l.fd, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .CONNABORTED => return true,
            .AGAIN => return false,
            else => |err| {
                log.warn("accepting a program failed: {t}", .{err});
                return false;
            },
        }
        const fd: fd_t = @intCast(rc);

        if (!sameUser(fd)) {
            log.warn("refused a program of another user", .{});
            closeFd(fd);
            return true;
        }
        Client.create(l, fd) catch {
            closeFd(fd);
            return false;
        };
        return true;
    }

    fn freeIfDone(l: *Listener) void {
        if (!l.closing or l.accepting or l.clients.items.len > 0) return;
        closeFd(l.fd);
        l.server.deinit();
        l.clients.deinit(l.gpa);
        l.gpa.destroy(l);
    }
};

fn closeFetch(_: ?*anyopaque, _: []const u8, fd: fd_t) void {
    closeFd(fd);
}

fn ignoreCopy(_: ?*anyopaque, _: Selection, _: ?[]const []const u8) void {}

// One program's socket. It is freed by freeIfDone, from a poll callback, once
// it is closing and neither poll is pending.
const Client = struct {
    listener: *Listener,
    conn: *Connection,
    fd: fd_t,
    // The bytes the Connection leaves are part of one message, under
    // max_message_len, and recvmsg always has room after them. With no room it
    // would return 0, which reads as EOF.
    in: [2 * wire.max_message_len]u8 = undefined,
    in_len: usize = 0,
    read_c: xev.Completion = .{},
    write_c: xev.Completion = .{},
    reading: bool = false,
    writing: bool = false,
    closing: bool = false,

    fn create(l: *Listener, fd: fd_t) Allocator.Error!void {
        const client = try l.gpa.create(Client);
        errdefer l.gpa.destroy(client);
        try l.clients.ensureUnusedCapacity(l.gpa, 1);
        client.* = .{ .listener = l, .conn = try l.server.connect(), .fd = fd };
        l.clients.appendAssumeCapacity(client);
        client.startRead();
    }

    fn startRead(client: *Client) void {
        if (client.reading) return;
        client.reading = true;
        client.read_c = .{
            .op = .{ .poll = .{ .fd = client.fd, .events = posix.POLL.IN } },
            .userdata = client,
            .callback = onReadable,
        };
        client.listener.loop.add(&client.read_c);
    }

    fn onReadable(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, result: xev.Result) xev.CallbackAction {
        const client: *Client = @ptrCast(@alignCast(ud.?));
        const l = client.listener;
        _ = result.poll catch client.close();

        while (!client.closing and !client.conn.failed) {
            if (!client.receive()) break;
        }

        const again = !client.closing and !client.conn.failed;
        if (!again) client.reading = false;
        // Requests can queue events on any connection.
        l.flush();
        if (!again) client.freeIfDone();
        return if (again) .rearm else .disarm;
    }

    fn receive(client: *Client) bool {
        var iov = [_]posix.iovec{.{ .base = client.in[client.in_len..].ptr, .len = client.in.len - client.in_len }};
        var control: [controlLen(max_fds_per_send)]u8 align(@alignOf(linux.cmsghdr)) = undefined;
        var msg: linux.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &control,
            .controllen = control.len,
            .flags = 0,
        };
        const rc = linux.recvmsg(client.fd, &msg, linux.MSG.CMSG_CLOEXEC | linux.MSG.DONTWAIT);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => return true,
            .AGAIN => return false,
            else => {
                client.close();
                return false;
            },
        }

        if (!client.takeFds(&msg)) {
            client.close();
            return false;
        }
        if (rc == 0) {
            client.close();
            return false;
        }

        client.in_len += rc;
        const used = client.conn.receive(client.in[0..client.in_len]);
        std.mem.copyForwards(u8, &client.in, client.in[used..client.in_len]);
        client.in_len -= used;
        return true;
    }

    // Queues the received descriptors on the Connection, up to
    // max_pending_fds. Returns false if any was lost, after closing those it
    // didn't queue.
    fn takeFds(client: *Client, msg: *const linux.msghdr) bool {
        var ok = msg.flags & linux.MSG.CTRUNC == 0;
        const control: [*]align(@alignOf(linux.cmsghdr)) const u8 = @ptrCast(@alignCast(msg.control.?));

        // CMSG_FIRSTHDR and CMSG_NXTHDR.
        var offset: usize = 0;
        while (offset + @sizeOf(linux.cmsghdr) <= msg.controllen) {
            const header: *const linux.cmsghdr = @ptrCast(@alignCast(control + offset));
            if (header.len < @sizeOf(linux.cmsghdr) or offset + header.len > msg.controllen) break;
            if (header.level == linux.SOL.SOCKET and header.type == linux.SCM.RIGHTS) {
                const data = control[offset + @sizeOf(linux.cmsghdr) .. offset + header.len];
                const count = data.len / @sizeOf(fd_t);
                for (0..count) |i| {
                    const fd = std.mem.readInt(fd_t, data[i * @sizeOf(fd_t) ..][0..@sizeOf(fd_t)], .native);
                    if (!ok or client.conn.fds.len >= server_pkg.max_pending_fds) {
                        closeFd(fd);
                        ok = false;
                        continue;
                    }
                    client.conn.fds.pushBack(client.listener.gpa, fd) catch {
                        closeFd(fd);
                        ok = false;
                    };
                }
            }
            offset += std.mem.alignForward(usize, header.len, linux.cmsg_align);
        }
        return ok;
    }

    fn flush(client: *Client) void {
        if (client.closing or client.writing) return;
        const out = &client.conn.out;
        while (out.bytes.items.len > 0) {
            if (!client.sendSome()) return;
        }
        if (client.conn.failed) client.close();
    }

    fn sendSome(client: *Client) bool {
        const out = &client.conn.out;
        const iov = [_]posix.iovec_const{.{ .base = out.bytes.items.ptr, .len = out.bytes.items.len }};

        const count = @min(out.fds.items.len, max_fds_per_send);
        var control: [controlLen(max_fds_per_send)]u8 align(@alignOf(linux.cmsghdr)) = undefined;
        var control_len: usize = 0;
        if (count > 0) {
            const header: *linux.cmsghdr = @ptrCast(&control);
            header.* = .{ .len = @sizeOf(linux.cmsghdr) + count * @sizeOf(fd_t), .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
            @memcpy(control[@sizeOf(linux.cmsghdr)..][0 .. count * @sizeOf(fd_t)], std.mem.sliceAsBytes(out.fds.items[0..count]));
            control_len = controlLen(count);
        }
        const msg: linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = if (count > 0) &control else null,
            .controllen = control_len,
            .flags = 0,
        };
        const rc = linux.sendmsg(client.fd, &msg, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => return true,
            .AGAIN => {
                client.startWrite();
                return false;
            },
            else => {
                client.close();
                return false;
            },
        }

        // The program has its own copies now.
        for (out.fds.items[0..count]) |fd| closeFd(fd);
        out.fds.replaceRangeAssumeCapacity(0, count, &.{});
        out.bytes.replaceRangeAssumeCapacity(0, rc, &.{});
        return true;
    }

    fn startWrite(client: *Client) void {
        client.writing = true;
        client.write_c = .{
            .op = .{ .poll = .{ .fd = client.fd, .events = posix.POLL.OUT } },
            .userdata = client,
            .callback = onWritable,
        };
        client.listener.loop.add(&client.write_c);
    }

    fn onWritable(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, result: xev.Result) xev.CallbackAction {
        const client: *Client = @ptrCast(@alignCast(ud.?));
        _ = result.poll catch client.close();
        client.writing = false;
        client.flush();
        client.freeIfDone();
        return .disarm;
    }

    fn close(client: *Client) void {
        if (client.closing) return;
        client.closing = true;
        // shutdown ends the pending polls. With none pending, a read poll is
        // started, so the client is freed from its callback after the caller
        // returns.
        _ = linux.shutdown(client.fd, linux.SHUT.RDWR);
        if (!client.reading and !client.writing) client.startRead();
    }

    fn freeIfDone(client: *Client) void {
        if (!client.closing or client.reading or client.writing) return;
        const l = client.listener;
        const index = std.mem.indexOfScalar(*Client, l.clients.items, client).?;
        _ = l.clients.swapRemove(index);

        l.server.disconnect(client.conn);
        closeFd(client.fd);
        l.gpa.destroy(client);
        // Disconnecting can clear a selection, which queues events on the
        // other connections.
        l.flush();
        l.freeIfDone();
    }
};

fn listen(path: []const u8) Error!fd_t {
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..path.len], path);

    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
    const fd: fd_t = @intCast(rc);
    errdefer closeFd(fd);

    for (0..2) |_| {
        switch (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un)))) {
            .SUCCESS => break,
            // A socket file that refuses connections is left by a server that
            // is gone. It is removed and bound again.
            .ADDRINUSE => {
                if (listening(&address)) return error.AddressInUse;
                var buf: [std.fs.max_path_bytes:0]u8 = undefined;
                @memcpy(buf[0..path.len], path);
                buf[path.len] = 0;
                _ = linux.unlink(&buf);
            },
            .NAMETOOLONG => return error.NameTooLong,
            else => |err| return posix.unexpectedErrno(err),
        }
    } else return error.AddressInUse;

    if (linux.errno(linux.listen(fd, 64)) != .SUCCESS) return error.SystemResources;
    return fd;
}

fn listening(address: *const linux.sockaddr.un) bool {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return true;
    const fd: fd_t = @intCast(rc);
    defer closeFd(fd);
    return linux.errno(linux.connect(fd, @ptrCast(address), @sizeOf(linux.sockaddr.un))) != .CONNREFUSED;
}

fn sameUser(fd: fd_t) bool {
    // struct ucred from <sys/socket.h>.
    const Ucred = extern struct { pid: linux.pid_t, uid: linux.uid_t, gid: linux.gid_t };
    var cred: Ucred = undefined;
    var len: linux.socklen_t = @sizeOf(Ucred);
    if (linux.errno(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &len)) != .SUCCESS) return false;
    return cred.uid == linux.getuid();
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

const testing = std.testing;
const Io = std.Io;

const TestServer = struct {
    loop: xev.Loop,
    listener: *Listener = undefined,
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    thread: std.Thread = undefined,
    pending: std.atomic.Value(?*const Call) = .init(null),
    done: std.atomic.Value(bool) = .init(false),
    stopping: bool = false,
    text: []const u8 = "",
    copied: std.ArrayList(u8) = .empty,

    const Call = struct {
        run: *const fn (ts: *TestServer, arg: ?*anyopaque) void,
        arg: ?*anyopaque = null,
    };

    fn start(ts: *TestServer, path: []const u8) !void {
        ts.* = .{ .loop = try .init(.{}), .wake = try .init() };
        ts.listener = try Listener.create(testing.allocator, &ts.loop, path, .{ .context = ts, .fetch = fetch, .copied = onCopied });
        ts.wake.wait(&ts.loop, &ts.wake_c, TestServer, ts, onWake);
        ts.thread = try std.Thread.spawn(.{}, run, .{ts});
    }

    fn run(ts: *TestServer) void {
        ts.loop.run(.until_done) catch |err| std.debug.panic("loop: {t}", .{err});
    }

    fn onWake(ts_: ?*TestServer, _: *xev.Loop, _: *xev.Completion, _: xev.Async.WaitError!void) xev.CallbackAction {
        const ts = ts_.?;
        if (ts.pending.swap(null, .acq_rel)) |c| {
            c.run(ts, c.arg);
            ts.done.store(true, .release);
        }
        return if (ts.stopping) .disarm else .rearm;
    }

    fn call(ts: *TestServer, c: Call) void {
        ts.done.store(false, .release);
        ts.pending.store(&c, .release);
        ts.wake.notify() catch {};
        while (!ts.done.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    }

    fn stop(ts: *TestServer) void {
        ts.call(.{ .run = struct {
            fn f(s: *TestServer, _: ?*anyopaque) void {
                s.stopping = true;
                s.listener.close();
            }
        }.f });
        ts.thread.join();
        ts.wake.deinit();
        ts.loop.deinit();
        ts.copied.deinit(testing.allocator);
    }

    fn fetch(context: ?*anyopaque, _: []const u8, fd: fd_t) void {
        const ts: *TestServer = @ptrCast(@alignCast(context.?));
        _ = linux.write(fd, ts.text.ptr, ts.text.len);
        closeFd(fd);
    }

    fn onCopied(context: ?*anyopaque, selection: Selection, mimes: ?[]const []const u8) void {
        const ts: *TestServer = @ptrCast(@alignCast(context.?));
        if (selection != .clipboard) return;
        ts.copied.clearRetainingCapacity();
        for (mimes orelse &.{}) |m| ts.copied.print(testing.allocator, "{s}\n", .{m}) catch unreachable;
    }
};

fn tool(environ: *const std.process.Environ.Map, argv: []const []const u8) ![]u8 {
    const result = std.process.run(testing.allocator, testing.io, .{
        .argv = argv,
        .environ_map = environ,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
    }) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer testing.allocator.free(result.stderr);
    errdefer testing.allocator.free(result.stdout);
    if (!result.term.success()) {
        std.debug.print("{s} failed: {s}\n", .{ argv[0], result.stderr });
        return error.ToolFailed;
    }
    return result.stdout;
}

fn copy(environ: *const std.process.Environ.Map, argv: []const []const u8) !void {
    var child = std.process.spawn(testing.io, .{
        .argv = argv,
        .environ_map = environ,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    if (!(try child.wait(testing.io)).success()) return error.ToolFailed;
}

fn expectTool(environ: *const std.process.Environ.Map, argv: []const []const u8, want: []const u8) !void {
    const out = try tool(environ, argv);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(want, out);
}

test "wl-paste reads the user's clipboard, and wl-copy's copies reach the user and other programs" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/wayland-1", .{dir});

    var environ: std.process.Environ.Map = .init(testing.allocator);
    defer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    try environ.put("XDG_RUNTIME_DIR", dir);
    try environ.put("WAYLAND_DISPLAY", path);

    var ts: TestServer = undefined;
    try ts.start(path);
    defer ts.stop();

    ts.call(.{ .run = struct {
        fn f(s: *TestServer, _: ?*anyopaque) void {
            s.text = "from the laptop";
            s.listener.setClipboard(&.{ "text/plain;charset=utf-8", "text/plain" }) catch unreachable;
        }
    }.f });
    try expectTool(&environ, &.{ "wl-paste", "--list-types" }, "text/plain;charset=utf-8\ntext/plain\n");
    try expectTool(&environ, &.{ "wl-paste", "--no-newline" }, "from the laptop");

    try copy(&environ, &.{ "wl-copy", "from a program" });
    try testing.expect(std.mem.indexOf(u8, ts.copied.items, "text/plain\n") != null);
    try expectTool(&environ, &.{ "wl-paste", "--no-newline" }, "from a program");

    const fds = try pipe();
    defer closeFd(fds[0]);
    const Read = struct {
        fd: fd_t,
        ok: bool = false,
        fn f(s: *TestServer, arg: ?*anyopaque) void {
            const r: *@This() = @ptrCast(@alignCast(arg.?));
            r.ok = s.listener.read(.clipboard, "text/plain", r.fd);
        }
    };
    var r: Read = .{ .fd = fds[1] };
    ts.call(.{ .run = Read.f, .arg = &r });
    try testing.expect(r.ok);
    var got: [64]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const n = linux.read(fds[0], got[len..].ptr, got.len - len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        len += n;
    }
    try testing.expectEqualStrings("from a program", got[0..len]);

    try copy(&environ, &.{ "wl-copy", "--primary", "selected" });
    try expectTool(&environ, &.{ "wl-paste", "--primary", "--no-newline" }, "selected");

    ts.call(.{ .run = struct {
        fn f(s: *TestServer, _: ?*anyopaque) void {
            s.text = "newer";
            s.listener.setClipboard(&.{"text/plain"}) catch unreachable;
        }
    }.f });
    try expectTool(&environ, &.{ "wl-paste", "--no-newline" }, "newer");
}

fn pipe() ![2]fd_t {
    var fds: [2]fd_t = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
    return fds;
}
