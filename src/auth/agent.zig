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

/// Sign request flags. RSA keys sign with SHA-1 unless asked for SHA-2.
pub const rsa_sha2_256: u32 = 2;
pub const rsa_sha2_512: u32 = 4;

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

    /// Signs `data` with the key whose blob is `key_blob`, an RSA key with
    /// SHA-512. Returns the signature blob, owned by the caller.
    pub fn sign(a: *Agent, gpa: Allocator, key_blob: []const u8, data: []const u8) Error![]u8 {
        var body: Writer.Allocating = .init(gpa);
        defer body.deinit();

        // string key_blob, string data, uint32 flags. Ed25519 ignores the
        // flags.
        ssh.writeString(&body.writer, key_blob) catch return error.OutOfMemory;
        ssh.writeString(&body.writer, data) catch return error.OutOfMemory;
        body.writer.writeInt(u32, rsa_sha2_512, .big) catch return error.OutOfMemory;

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

/// An agent holding Ed25519 keys, and RSA keys from `test_rsa_key`, in
/// memory, for tests. It serves one connection at a time on its own thread.
pub const TestAgent = struct {
    io: Io,
    server: Io.net.Server,
    thread: std.Thread,
    keys: []const std.crypto.sign.Ed25519.KeyPair,
    rsa_keys: []const TestRsaKey = &.{},
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
                    try aw.writeInt(u32, @intCast(agent.keys.len + agent.rsa_keys.len), .big);
                    for (agent.keys) |kp| {
                        try ssh.writeString(&aw, &ssh.keyBlob(kp.public_key.toBytes()));
                        try ssh.writeString(&aw, "test");
                    }
                    for (agent.rsa_keys) |k| {
                        try ssh.writeString(&aw, k.public().blob());
                        try ssh.writeString(&aw, "test");
                    }
                },
                sign_request => {
                    var req: ssh.Reader = .init(request[1..]);
                    const blob = try req.string();
                    const data = try req.string();
                    const flags = try req.uint32();
                    const kp = for (agent.keys) |kp| {
                        if (std.mem.eql(u8, blob, &ssh.keyBlob(kp.public_key.toBytes()))) break kp;
                    } else null;
                    const rsa_key = for (agent.rsa_keys) |k| {
                        if (std.mem.eql(u8, blob, k.public().blob())) break k;
                    } else null;

                    if (agent.refuse.load(.acquire) or (kp == null and rsa_key == null)) {
                        try aw.writeByte(failure);
                    } else if (rsa_key) |k| {
                        // Without the SHA-512 flag a real agent signs with
                        // SHA-1. This one refuses.
                        if (flags & rsa_sha2_512 == 0) {
                            try aw.writeByte(failure);
                        } else {
                            var sig_buf: [600]u8 = undefined;
                            try aw.writeByte(sign_response);
                            try ssh.writeString(&aw, try k.sign(data, &sig_buf));
                            _ = agent.signatures.fetchAdd(1, .monotonic);
                        }
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

/// An RSA key for tests, from `ssh-keygen -t rsa -b 2048`: the private
/// exponent signs, the rest is `ssh.test_rsa_text`.
pub const TestRsaKey = struct {
    /// Big-endian.
    n: []const u8,
    d: []const u8,

    pub fn public(_: *const TestRsaKey) ssh.PublicKey {
        return ssh.parsePublicKeyText(ssh.rsa, ssh.test_rsa_text) catch unreachable;
    }

    /// An `rsa-sha2-512` signature blob over `data` (RFC 8332): EM =
    /// 0x00 0x01 0xff... 0x00 DigestInfo(SHA-512) H, raised to d mod n.
    fn sign(k: *const TestRsaKey, data: []const u8, out: []u8) ![]const u8 {
        const Sha512 = std.crypto.hash.sha2.Sha512;
        const M = std.crypto.ff.Modulus(4096);
        const len = k.n.len;

        const digest_info = [_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
        var em_buf: [512]u8 = undefined;
        const em = em_buf[0..len];
        @memset(em, 0xff);
        em[0] = 0x00;
        em[1] = 0x01;
        const t_start = len - digest_info.len - Sha512.digest_length;
        em[t_start - 1] = 0x00;
        @memcpy(em[t_start..][0..digest_info.len], &digest_info);
        Sha512.hash(data, em[len - Sha512.digest_length ..][0..Sha512.digest_length], .{});

        const n: M = try .fromBytes(k.n, .big);
        const m: M.Fe = try .fromBytes(n, em, .big);
        const s = try n.powWithEncodedExponent(m, k.d, .big);
        var sig: [512]u8 = undefined;
        try s.toBytes(sig[0..len], .big);

        var w: Writer = .fixed(out);
        try ssh.writeString(&w, "rsa-sha2-512");
        try ssh.writeString(&w, sig[0..len]);
        return w.buffered();
    }
};

pub const test_rsa_key: TestRsaKey = .{
    .n = &hexBytes("b70d5f197bce1405a465114168297ca967826b9f84407f9261436a8a7d52aae63f3467476b37c2b6c7e41c78bc0a24c99d5d8d215ad9c8552334828f63e9e08daac7c421ea4a66c12309b2a27e85c4d13489947dabb3ff6dea4906132d94307a31c21d383bf579e3ee67ba420d885b87ef200d688f3edf16a4ef7475f4e3e0db257dc1a060e5e8e17e2b505f32aeb3eea6604a18f2c8f4e7c85528a8487aeab79eea995fa6d2746537ea5e2205b8f744fce58c6542d29919d07530a25d506c37f3ddf5f5dff06378b234c78da546505dcf8c51191617a611dfff6bab7b587b64c968317db892110837748a0d9dc1a54141bb6a7244097a552e7b69a6afd7981d"),
    .d = &hexBytes("09089ba61c0e443e3009fdd342c2f3603fd7b79c78701f6b97a9b64f0dd6bfd0db93283aa5cfab680e4ed359e0fbc62b7dfce12b617aa8708d2b78faff150a6c2b5eaeeef68b43ed699f7fa595c55fbc6c5192d6addbd4f1f573339dcc2cc944aa8278232f90527add67d8910c6e6b87f694d81c8e1f2deec5e67c529aea890cea2dd64fb4b1b58e9ed28d7faad23733c3bb185c7ac077ad6bdce054ec2e63840195b0ddab86d802c7d31f6d321b5eed75e7415d798f98458a1eaa992044873172bc3d495f9dec923a5cefafcbd4fdffa6f63e87ae34a73369c4df93cf5818376454042d041393a940903adab422dd1586672fbacc6045925302e10f6130bea9"),
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(10 * hex.len);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

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

test "an RSA key signs with SHA-512" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try testSocketPath(&path_buf, &tmp);

    var test_agent: TestAgent = undefined;
    try test_agent.start(testing.io, path, &.{});
    test_agent.rsa_keys = (&test_rsa_key)[0..1];
    defer test_agent.stop(path);

    var agent: Agent = try .connect(testing.io, path);
    defer agent.close();
    var ids = try agent.identities(testing.allocator);
    defer ids.deinit(testing.allocator);
    const key = try ssh.PublicKey.parse(ids.blobs[0]);
    try testing.expectEqual(.rsa, key.kind);

    const data: @import("sshsig.zig").SignedData = .init("ns", "message");
    const sig = try agent.sign(testing.allocator, key.blob(), data.slice());
    defer testing.allocator.free(sig);
    try @import("sshsig.zig").verify(&key, sig, &data);
}
