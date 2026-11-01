const std = @import("std");
const posix = std.posix;
const c = std.c;
const tty = @import("tty.zig");

pub const Error = error{
    NoTerminal,
};

/// Returns the passphrase as a slice of buf, which the caller wipes after
/// use. Bytes past buf.len are dropped. Returns null, with buf wiped, when
/// the user cancels or cancel_fd becomes readable.
pub fn ask(prompt: []const u8, buf: []u8, cancel_fd: posix.fd_t) Error!?[]u8 {
    const fd = c.open("/dev/tty", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true });
    if (fd == -1) return error.NoTerminal;
    defer _ = c.close(fd);

    var saved: posix.termios = undefined;
    tty.getAttrs(fd, &saved) catch return error.NoTerminal;
    // Without ICANON and ISIG, the editing keys and Ctrl-C arrive as bytes
    // and the switch below handles them.
    var attrs = saved;
    attrs.lflag.ECHO = false;
    attrs.lflag.ICANON = false;
    attrs.lflag.ISIG = false;
    attrs.cc[@backingInt(posix.V.MIN)] = 1;
    attrs.cc[@backingInt(posix.V.TIME)] = 0;
    _ = tty.setAttrs(fd, &attrs);
    defer {
        _ = tty.setAttrs(fd, &saved);
        writeAll(fd, "\r\n");
    }

    writeAll(fd, prompt);

    var len: usize = 0;
    while (true) {
        var fds = [_]posix.pollfd{
            .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = cancel_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        if (c.poll(&fds, fds.len, -1) == -1) {
            if (posix.errno(-1) == .INTR) continue;
            return wipe(buf, null);
        }
        if (fds[1].revents != 0) return wipe(buf, null);

        var byte: [1]u8 = undefined;
        if (c.read(fd, &byte, 1) != 1) return wipe(buf, null);

        switch (byte[0]) {
            '\r', '\n' => return buf[0..len],
            0x03, 0x04 => return wipe(buf, null),
            0x08, 0x7f => len -|= 1,
            0x15 => len = 0,
            else => |b| {
                if (len < buf.len) {
                    buf[len] = b;
                    len += 1;
                }
            },
        }
    }
}

fn wipe(buf: []u8, result: ?[]u8) ?[]u8 {
    std.crypto.secureZero(u8, buf);
    return result;
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) void {
    var rest = bytes;
    while (rest.len > 0) {
        const n = c.write(fd, rest.ptr, rest.len);
        if (n <= 0) return;
        rest = rest[@intCast(n)..];
    }
}
