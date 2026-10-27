//! Writes a gzip-compressed tarball of files in one directory. Every
//! timestamp is 0, so the same files make the same tarball.
//!
//! Usage: tarball OUT ROOT [NAME MODE PATH]...
//!
//! MODE is octal, such as 755.
const std = @import("std");
const Io = std.Io;
const flate = std.compress.flate;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or (args.len - 3) % 3 != 0) return error.Usage;

    const out = try Io.Dir.cwd().createFile(io, args[1], .{});
    defer out.close(io);
    var out_buf: [64 << 10]u8 = undefined;
    var out_writer = out.writerStreaming(io, &out_buf);

    var window: [flate.max_window_len]u8 = undefined;
    var gzip: flate.Compress = try .init(&out_writer.interface, &window, .gzip, .best);
    var tar: std.tar.Writer = .{ .underlying_writer = &gzip.writer };
    try tar.writeDir(args[2], .{ .mode = 0o755 });
    tar.prefix = args[2];

    var i: usize = 3;
    while (i < args.len) : (i += 3) {
        const bytes = try Io.Dir.cwd().readFileAlloc(io, args[i + 2], gpa, .limited(256 << 20));
        defer gpa.free(bytes);
        try tar.writeFileBytes(args[i], bytes, .{ .mode = try std.fmt.parseInt(u32, args[i + 1], 8) });
    }

    try tar.finishPedantically();
    try gzip.finish();
    try out_writer.interface.flush();
}
