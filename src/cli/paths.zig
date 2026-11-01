const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;

pub const Error = Allocator.Error || error{NoHome};

pub fn config(gpa: Allocator, environ: *const Environ.Map, name: []const u8) Error![]u8 {
    return xdg(gpa, environ, "XDG_CONFIG_HOME", ".config", name);
}

pub fn cache(gpa: Allocator, environ: *const Environ.Map, name: []const u8) Error![]u8 {
    return xdg(gpa, environ, "XDG_CACHE_HOME", ".cache", name);
}

pub fn state(gpa: Allocator, environ: *const Environ.Map, name: []const u8) Error![]u8 {
    return xdg(gpa, environ, "XDG_STATE_HOME", ".local/state", name);
}

pub fn runtime(gpa: Allocator, environ: *const Environ.Map) Error![]u8 {
    if (builtin.os.tag.isDarwin()) {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = confstr(cs_darwin_user_temp_dir, &buf, buf.len);
        if (n > 1 and n <= buf.len) return std.fs.path.join(gpa, &.{ buf[0 .. n - 1], "tx" });
    } else if (environ.get("XDG_RUNTIME_DIR")) |dir| {
        if (std.fs.path.isAbsolute(dir)) return std.fs.path.join(gpa, &.{ dir, "tx" });
    }
    return state(gpa, environ, "run");
}

extern "c" fn confstr(name: c_int, buf: [*]u8, len: usize) usize;
const cs_darwin_user_temp_dir = 65537;

pub fn home(gpa: Allocator, environ: *const Environ.Map, sub_path: []const u8) Error![]u8 {
    const dir = environ.get("HOME") orelse return error.NoHome;
    return std.fs.path.join(gpa, &.{ dir, sub_path });
}

fn xdg(gpa: Allocator, environ: *const Environ.Map, variable: []const u8, default: []const u8, name: []const u8) Error![]u8 {
    if (environ.get(variable)) |dir| if (std.fs.path.isAbsolute(dir)) return std.fs.path.join(gpa, &.{ dir, "tx", name });

    const dir = environ.get("HOME") orelse return error.NoHome;
    return std.fs.path.join(gpa, &.{ dir, default, "tx", name });
}

pub fn userName(environ: *const Environ.Map) ?[]const u8 {
    if (std.c.getpwuid(std.c.geteuid())) |pw| if (pw.name) |name| return std.mem.span(name);
    return environ.get("USER");
}
