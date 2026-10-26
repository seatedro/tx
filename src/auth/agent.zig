//! A client for the SSH agent protocol (draft-ietf-sshm-ssh-agent), over
//! the socket in `SSH_AUTH_SOCK`.
//!
//! Each message is a u32 length, a type byte and a body. Calls block until
//! the agent answers, which can take as long as the user takes to approve a
//! signature.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Writer = Io.Writer;
const ssh = @import("ssh.zig");

const request_identities = 11;
const identities_answer = 12;
const sign_request = 13;
const sign_response = 14;
const failure = 5;

/// OpenSSH's limit on an agent message (AGENT_MAX_LEN).
const max_message = 256 * 1024;

pub const Error = error{
    /// The agent answered with a malformed or unexpected message.
    Protocol,
    /// The agent refused, for example a key added with `ssh-add -h`
    /// destination constraints or a signature the user declined.
    Refused,
} || Allocator.Error || Io.net.Stream.Reader.Error || Io.net.Stream.Writer.Error;

pub const Agent = struct {
    io: Io,
    stream: Io.net.Stream,

    pub const ConnectError = Io.net.UnixAddress.InitError || Io.net.UnixAddress.ConnectError;

    pub fn connect(io: Io, path: []const u8) ConnectError!Agent {
        const address: Io.net.UnixAddress = try .init(path);
        return .{ .io = io, .stream = try address.connect(io) };
    }

    pub fn close(a: *Agent) void {
        a.stream.close(a.io);
    }

    /// The agent's public key blobs. Keys of every type are included.
    pub fn identities(a: *Agent, gpa: Allocator) Error!Identities {
        const answer = try a.call(gpa, request_identities, &.{});
        errdefer gpa.free(answer);

        // uint32 nkeys, then a key blob and a comment for each.
        var r: ssh.Reader = .init(answer);
        const count = r.uint32() catch return error.Protocol;
        var blobs: std.ArrayList([]const u8) = .empty;
        errdefer blobs.deinit(gpa);
        for (0..count) |_| {
            const blob = r.string() catch return error.Protocol;
            _ = r.string() catch return error.Protocol;
            try blobs.append(gpa, blob);
        }
        r.end() catch return error.Protocol;

        return .{ .answer = answer, .blobs = try blobs.toOwnedSlice(gpa) };
    }

    /// Signs `data` with the key whose blob is `key_blob`. Returns the
    /// signature blob, owned by the caller.
    pub fn sign(a: *Agent, gpa: Allocator, key_blob: []const u8, data: []const u8) Error![]u8 {
        var body: Writer.Allocating = .init(gpa);
        defer body.deinit();
        // string key_blob, string data, uint32 flags. No flags are needed
        // for Ed25519.
        ssh.writeString(&body.writer, key_blob) catch return error.OutOfMemory;
        ssh.writeString(&body.writer, data) catch return error.OutOfMemory;
        body.writer.writeInt(u32, 0, .big) catch return error.OutOfMemory;

        const answer = try a.call(gpa, sign_request, body.written());
        defer gpa.free(answer);

        var r: ssh.Reader = .init(answer);
        const sig = r.string() catch return error.Protocol;
        r.end() catch return error.Protocol;
        return gpa.dupe(u8, sig);
    }

    /// Sends a request and returns the body of a successful answer, owned
    /// by the caller.
    fn call(a: *Agent, gpa: Allocator, request: u8, body: []const u8) Error![]u8 {
        var write_buf: [256]u8 = undefined;
        var sw = a.stream.writer(a.io, &write_buf);
        const w = &sw.interface;
        w.writeInt(u32, @intCast(body.len + 1), .big) catch return sw.err.?;
        w.writeByte(request) catch return sw.err.?;
        w.writeAll(body) catch return sw.err.?;
        w.flush() catch return sw.err.?;

        var read_buf: [256]u8 = undefined;
        var sr = a.stream.reader(a.io, &read_buf);
        const r = &sr.interface;
        const len = r.takeInt(u32, .big) catch |err| return readError(&sr, err);
        if (len == 0 or len > max_message) return error.Protocol;
        const kind = r.takeByte() catch |err| return readError(&sr, err);
        const answer = try gpa.alloc(u8, len - 1);
        errdefer gpa.free(answer);
        r.readSliceAll(answer) catch |err| return readError(&sr, err);

        // Each request has one success type. Anything else is a refusal
        // or an error.
        const expected: u8 = switch (request) {
            request_identities => identities_answer,
            sign_request => sign_response,
            else => unreachable,
        };
        if (kind == failure) return error.Refused;
        if (kind != expected) return error.Protocol;
        return answer;
    }

    fn readError(sr: *Io.net.Stream.Reader, err: Io.Reader.Error) Error {
        return switch (err) {
            // The agent closed the socket mid-answer.
            error.EndOfStream => error.Protocol,
            error.ReadFailed => sr.err.?,
        };
    }
};

pub const Identities = struct {
    /// The agent's answer. `blobs` point into it.
    answer: []u8,
    blobs: []const []const u8,

    pub fn deinit(ids: *Identities, gpa: Allocator) void {
        gpa.free(ids.blobs);
        gpa.free(ids.answer);
        ids.* = undefined;
    }
};

/// An agent holding Ed25519 keys in memory, for tests. It serves one
/// connection at a time on its own thread.
pub const TestAgent = struct {
    io: Io,
    server: Io.net.Server,
    thread: std.Thread,
    keys: []const std.crypto.sign.Ed25519.KeyPair,
    /// Refuses sign requests while set.
    refuse: std.atomic.Value(bool) = .init(false),
    signatures: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn start(agent: *TestAgent, io: Io, path: []const u8, keys: []const std.crypto.sign.Ed25519.KeyPair) !void {
        const address: Io.net.UnixAddress = try .init(path);
        agent.* = .{ .io = io, .server = try address.listen(io, .{}), .thread = undefined, .keys = keys };
        errdefer agent.server.deinit(io);
        agent.thread = try std.Thread.spawn(.{}, serve, .{agent});
    }

    /// Wakes the thread with a connection that sends nothing.
    pub fn stop(agent: *TestAgent, path: []const u8) void {
        agent.stopping.store(true, .release);
        const address = Io.net.UnixAddress.init(path) catch unreachable;
        if (address.connect(agent.io)) |s| s.close(agent.io) else |_| {}
        agent.thread.join();
        agent.server.deinit(agent.io);
    }

    fn serve(agent: *TestAgent) void {
        while (true) {
            const stream = agent.server.accept(agent.io) catch return;
            defer stream.close(agent.io);
            if (agent.stopping.load(.acquire)) return;
            agent.serveConnection(stream) catch {};
        }
    }

    fn serveConnection(agent: *TestAgent, stream: Io.net.Stream) !void {
        var read_buf: [4096]u8 = undefined;
        var write_buf: [4096]u8 = undefined;
        var sr = stream.reader(agent.io, &read_buf);
        var sw = stream.writer(agent.io, &write_buf);
        const r = &sr.interface;
        const w = &sw.interface;

        while (true) {
            const len = r.takeInt(u32, .big) catch return;
            const request = try r.take(len);
            var answer: [4096]u8 = undefined;
            var aw: Writer = .fixed(&answer);

            switch (request[0]) {
                request_identities => {
                    try aw.writeByte(identities_answer);
                    try aw.writeInt(u32, @intCast(agent.keys.len), .big);
                    for (agent.keys) |kp| {
                        try ssh.writeString(&aw, &ssh.keyBlob(kp.public_key.toBytes()));
                        try ssh.writeString(&aw, "test");
                    }
                },
                sign_request => {
                    var req: ssh.Reader = .init(request[1..]);
                    const blob = try req.string();
                    const data = try req.string();
                    const kp = for (agent.keys) |kp| {
                        if (std.mem.eql(u8, blob, &ssh.keyBlob(kp.public_key.toBytes()))) break kp;
                    } else null;

                    if (kp == null or agent.refuse.load(.acquire)) {
                        try aw.writeByte(failure);
                    } else {
                        const sig = try kp.?.sign(data, null);
                        try aw.writeByte(sign_response);
                        try ssh.writeString(&aw, &@import("sshsig.zig").signatureBlob(sig.toBytes()));
                        _ = agent.signatures.fetchAdd(1, .monotonic);
                    }
                },
                else => try aw.writeByte(failure),
            }

            try w.writeInt(u32, @intCast(aw.end), .big);
            try w.writeAll(aw.buffered());
            try w.flush();
        }
    }
};

const testing = std.testing;

fn testSocketPath(buf: []u8, tmp: *testing.TmpDir) ![]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(testing.io, &dir_buf);
    return std.fmt.bufPrint(buf, "{s}/agent.sock", .{dir_buf[0..n]});
}

test "identities and signatures from an agent" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try testSocketPath(&path_buf, &tmp);

    const keys = [_]std.crypto.sign.Ed25519.KeyPair{ .generate(testing.io), .generate(testing.io) };
    var test_agent: TestAgent = undefined;
    try test_agent.start(testing.io, path, &keys);
    defer test_agent.stop(path);

    var agent: Agent = try .connect(testing.io, path);
    defer agent.close();

    var ids = try agent.identities(testing.allocator);
    defer ids.deinit(testing.allocator);
    try testing.expectEqual(2, ids.blobs.len);
    try testing.expectEqual(keys[1].public_key.toBytes(), try ssh.parseKeyBlob(ids.blobs[1]));

    const sig = try agent.sign(testing.allocator, ids.blobs[1], "data");
    defer testing.allocator.free(sig);
    const bytes = try ssh.parseSignatureBlob(sig);
    try std.crypto.sign.Ed25519.Signature.fromBytes(bytes).verify("data", keys[1].public_key);

    test_agent.refuse.store(true, .release);
    try testing.expectError(error.Refused, agent.sign(testing.allocator, ids.blobs[0], "data"));
}
