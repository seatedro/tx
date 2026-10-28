//! A command a client runs with `proto.Exec`: the user's shell runs it with
//! `-c`, its stdin, stdout and stderr on sockets (`session.pty.Pipes`).
//!
//! Its stdout and stderr go to the client on two unidirectional streams,
//! each ended at its socket's end of file. The client's side of a
//! bidirectional stream is its stdin, and that side's end shuts the stdin
//! socket. An output socket isn't read while its stream has more than
//! `high_water` bytes the client hasn't acknowledged, and stdin's flow
//! control credit returns once the command has taken the bytes.
//!
//! A thread waits for the command to exit. The loop then reaps it, closes
//! its stdin, and reports `Exit`. If the connection closes first, the
//! sockets are shut down: the command sees the end of its stdin, and EPIPE
//! when it writes. An `Exec` frees itself once the command has exited and
//! its sockets are closed.
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const xev = @import("xev");
const proto = @import("proto");
const session = @import("session");
const transport = @import("transport");

const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const Pipes = session.pty.Pipes;
const Term = session.pty.Term;

const log = std.log.scoped(.exec);

/// Bytes an output stream may have unacknowledged before its socket waits,
/// and the level it reads again at.
const high_water = 1 << 20;
const low_water = 256 << 10;

/// The most bytes read from an output socket at once.
const read_size = 64 << 10;

pub const Options = struct {
    /// The user's shell, which runs `command` with `-c`.
    shell: []const u8,
    command: []const u8,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    handler: Handler,
};

pub const Handler = struct {
    /// The client's, until `detach`.
    client: *anyopaque,
    /// The command exited. Not called after `detach`.
    exited: *const fn (client: *anyopaque, exit: proto.Exit) void,
    /// The server's.
    server: *anyopaque,
    /// The `Exec` frees itself when this returns. `client` is null after
    /// `detach`.
    freed: *const fn (server: *anyopaque, client: ?*anyopaque, exec: *Exec) void,
};

pub const Exec = struct {
    gpa: Allocator,
    loop: *xev.Loop,
    handler: Handler,
    /// False once `detach` is called.
    attached: bool = true,
    pipes: Pipes,
    stdout: Output,
    stderr: Output,
    stdin: Input,
    /// Waits for the command to exit, then notifies `exited`.
    waiter: std.Thread,
    exited: xev.Async,
    exited_c: xev.Completion = .{},
    /// Set once the command is reaped.
    term: ?Term = null,

    /// Starts the command, and opens its streams on `conn` in the order
    /// `proto.Exec` gives.
    pub fn start(gpa: Allocator, loop: *xev.Loop, conn: *Conn, options: Options) !*Exec {
        const e = try gpa.create(Exec);
        errdefer gpa.destroy(e);

        // As sshd runs a command: argv[0] is the shell's name.
        var pipes: Pipes = try .spawn(gpa, .{
            .argv = &.{ std.fs.path.basename(options.shell), "-c", options.command },
            .program = options.shell,
            .environ = options.environ,
            .cwd = options.cwd,
        });
        errdefer pipes.deinit();

        const stdout = try conn.openStream(.uni);
        const stderr = try conn.openStream(.uni);
        const stdin = try conn.openStream(.bidi);
        // The server's side of the stdin stream carries nothing.
        stdin.finish();

        const stdout_buf = try gpa.alloc(u8, read_size);
        errdefer gpa.free(stdout_buf);
        const stderr_buf = try gpa.alloc(u8, read_size);
        errdefer gpa.free(stderr_buf);
        var exited: xev.Async = try .init();
        errdefer exited.deinit();

        e.* = .{
            .gpa = gpa,
            .loop = loop,
            .handler = options.handler,
            .pipes = pipes,
            .stdout = .{ .exec = e, .fd = &e.pipes.stdout, .socket = .initFd(pipes.stdout), .stream = stdout, .buf = stdout_buf },
            .stderr = .{ .exec = e, .fd = &e.pipes.stderr, .socket = .initFd(pipes.stderr), .stream = stderr, .buf = stderr_buf },
            .stdin = .{ .exec = e, .fd = &e.pipes.stdin, .socket = .initFd(pipes.stdin), .stream = stdin },
            .waiter = undefined,
            .exited = exited,
        };
        e.waiter = try std.Thread.spawn(.{}, waitMain, .{e});
        e.exited.wait(loop, &e.exited_c, Exec, e, onExited);
        e.stdout.startRead();
        e.stderr.startRead();
        return e;
    }

    /// Whether `stream` is one of the command's.
    pub fn owns(e: *const Exec, stream: *const Stream) bool {
        return e.stdout.stream == stream or e.stderr.stream == stream or e.stdin.stream == stream;
    }

    /// Bytes from the client on a stream `owns`.
    pub fn received(e: *Exec, stream: *Stream, bytes: []const u8, fin: bool) void {
        // Nothing is expected on the output streams.
        if (stream != e.stdin.stream) return stream.consume(bytes.len);
        e.stdin.receive(bytes, fin);
        e.freeIfDone();
    }

    /// The client acknowledged output.
    pub fn acked(e: *Exec, stream: *Stream) void {
        if (stream == e.stdout.stream) e.stdout.resume_();
        if (stream == e.stderr.stream) e.stderr.resume_();
    }

    /// `stream` is about to be freed.
    pub fn streamClosed(e: *Exec, stream: *Stream) void {
        for ([_]*?*Stream{ &e.stdout.stream, &e.stderr.stream, &e.stdin.stream }) |s| {
            if (s.* == stream) s.* = null;
        }
    }

    /// The connection is closing. The command keeps running, without its
    /// sockets.
    pub fn detach(e: *Exec) void {
        e.attached = false;
        e.stdout.detach();
        e.stderr.detach();
        e.stdin.detach();
        e.freeIfDone();
    }

    /// Kills the command and every process in its session, for a server
    /// that is stopping.
    pub fn kill(e: *Exec) void {
        if (e.pipes.pid) |pid| _ = std.c.kill(-pid, .KILL);
    }

    /// Kills the command and frees the `Exec` at once, for a server whose
    /// loop won't run again.
    pub fn destroy(e: *Exec) void {
        e.kill();
        e.waiter.join();
        e.finalize();
    }

    fn waitMain(e: *Exec) void {
        e.pipes.waitExited() catch |err| log.warn("waiting for a command failed: {t}", .{err});
        e.exited.notify() catch {};
    }

    fn onExited(e_: ?*Exec, _: *xev.Loop, _: *xev.Completion, _: xev.Async.WaitError!void) xev.CallbackAction {
        const e = e_.?;
        e.waiter.join();
        e.term = (e.pipes.tryWait() catch null) orelse .{ .unknown = 0 };

        // Nothing reads the command's stdin now.
        e.stdin.end();
        if (e.attached) e.handler.exited(e.handler.client, session.session.exitMessage(e.term.?));
        e.freeIfDone();
        return .disarm;
    }

    fn freeIfDone(e: *Exec) void {
        if (e.term == null) return;
        if (!e.stdout.idle() or !e.stderr.idle() or !e.stdin.idle()) return;
        e.finalize();
    }

    fn finalize(e: *Exec) void {
        e.handler.freed(e.handler.server, if (e.attached) e.handler.client else null, e);
        e.pipes.deinit();
        e.exited.deinit();
        e.gpa.free(e.stdout.buf);
        e.gpa.free(e.stderr.buf);
        e.stdin.queue.deinit(e.gpa);
        e.stdin.writing.deinit(e.gpa);
        e.gpa.destroy(e);
    }
};

/// The command's stdout or stderr.
const Output = struct {
    exec: *Exec,
    /// In `exec.pipes`.
    fd: *posix.fd_t,
    socket: xev.TCP,
    /// Null once freed, or once detached.
    stream: ?*Stream,
    buf: []u8,
    read_c: xev.Completion = .{},
    /// A read is in flight, or its callback is running.
    reading: bool = false,
    /// The stream is above `high_water`.
    paused: bool = false,
    /// The socket reached its end, or was shut down, and is closed.
    ended: bool = false,

    fn idle(o: *const Output) bool {
        return o.ended and !o.reading;
    }

    fn startRead(o: *Output) void {
        if (o.reading or o.paused or o.ended) return;
        o.reading = true;
        o.socket.read(o.exec.loop, &o.read_c, .{ .slice = o.buf }, Output, o, onRead);
    }

    fn onRead(o_: ?*Output, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, result: xev.ReadError!usize) xev.CallbackAction {
        const o = o_.?;
        const n = result catch {
            // The end of the output, or a shutdown by `detach`.
            o.reading = false;
            o.end();
            o.exec.freeIfDone();
            return .disarm;
        };

        // After `detach`, output is dropped.
        if (o.stream) |stream| {
            stream.write(o.buf[0..n]) catch stream.conn.close(0);
            if (stream.buffered() > high_water) o.paused = true;
        }
        if (!o.paused) return .rearm;
        o.reading = false;
        return .disarm;
    }

    fn resume_(o: *Output) void {
        const stream = o.stream orelse return;
        if (!o.paused or stream.buffered() > low_water) return;
        o.paused = false;
        o.startRead();
    }

    /// Finishes the stream, and closes the socket.
    fn end(o: *Output) void {
        if (o.ended) return;
        o.ended = true;
        if (o.stream) |stream| stream.finish();
        o.exec.pipes.close(o.fd);
    }

    fn detach(o: *Output) void {
        o.stream = null;
        if (o.ended) return;
        // A read in flight ends with the shutdown, and ends the output.
        if (o.reading) {
            _ = std.c.shutdown(o.fd.*, posix.SHUT.RDWR);
        } else o.end();
    }
};

/// The command's stdin.
const Input = struct {
    exec: *Exec,
    /// In `exec.pipes`.
    fd: *posix.fd_t,
    socket: xev.TCP,
    /// Null once freed, or once detached.
    stream: ?*Stream,
    /// Bytes received and not yet written.
    queue: std.ArrayList(u8) = .empty,
    /// The bytes of the write in flight, from `written` on.
    writing: std.ArrayList(u8) = .empty,
    written: usize = 0,
    write_c: xev.Completion = .{},
    /// A write is in flight, or its callback is running.
    write_active: bool = false,
    /// The client finished its side of the stream.
    fin: bool = false,
    /// What arrives is dropped. The socket closes once no write is in
    /// flight.
    ended: bool = false,

    fn idle(i: *const Input) bool {
        return i.ended and !i.write_active;
    }

    fn receive(i: *Input, bytes: []const u8, fin: bool) void {
        if (i.ended) {
            if (i.stream) |stream| stream.consume(bytes.len);
            return;
        }
        i.queue.appendSlice(i.exec.gpa, bytes) catch return i.end();
        if (fin) i.fin = true;
        i.startWrite();
    }

    fn startWrite(i: *Input) void {
        if (i.write_active or i.ended) return;
        if (i.written == i.writing.items.len) {
            // All of stdin was written: the command sees its end.
            if (i.queue.items.len == 0) {
                if (i.fin) i.end();
                return;
            }
            i.writing.clearRetainingCapacity();
            i.written = 0;
            std.mem.swap(std.ArrayList(u8), &i.queue, &i.writing);
        }
        i.write_active = true;
        i.socket.write(i.exec.loop, &i.write_c, .{ .slice = i.writing.items[i.written..] }, Input, i, onWrite);
    }

    fn onWrite(i_: ?*Input, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, result: xev.WriteError!usize) xev.CallbackAction {
        const i = i_.?;
        i.write_active = false;
        if (result) |n| {
            i.written += n;
            // The credit returns once the command has the bytes.
            if (i.stream) |stream| stream.consume(n);
            i.startWrite();
        } else |_| {
            // The command closed its stdin, or exited.
            i.end();
        }
        i.closeIfIdle();
        i.exec.freeIfDone();
        return .disarm;
    }

    /// Drops what wasn't written, returning its credit, and closes the
    /// socket once no write is in flight. A write in flight ends with the
    /// shutdown.
    fn end(i: *Input) void {
        if (i.ended) return;
        i.ended = true;
        if (i.stream) |stream| stream.consume(i.queue.items.len + i.writing.items.len - i.written);
        i.queue.clearRetainingCapacity();
        i.writing.clearRetainingCapacity();
        i.written = 0;
        if (i.write_active) {
            _ = std.c.shutdown(i.fd.*, posix.SHUT.RDWR);
        } else i.closeIfIdle();
    }

    fn closeIfIdle(i: *Input) void {
        if (i.idle()) i.exec.pipes.close(i.fd);
    }

    fn detach(i: *Input) void {
        i.stream = null;
        i.end();
    }
};
