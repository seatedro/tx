//! File locations tx and txd share. Each XDG base directory gets a tx
//! subdirectory, and the runtime directory holds txd's sockets. Returned
//! paths are allocated with gpa, and the caller frees them.

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

/// tx in the per-user temporary directory on macOS, or in $XDG_RUNTIME_DIR
/// elsewhere. Without either, run in the state directory.
/// server/runtime_dir.zig refuses a directory that is another user's or open
/// to group or others.
pub fn runtime(gpa: Allocator, environ: *const Environ.Map) Error![]u8 {
    if (builtin.os.tag.isDarwin()) {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = confstr(cs_darwin_user_temp_dir, &buf, buf.len);

        // n counts the terminating NUL; above buf.len, buf was too small.
        if (n > 1 and n <= buf.len) return std.fs.path.join(gpa, &.{ buf[0 .. n - 1], "tx" });
    } else if (environ.get("XDG_RUNTIME_DIR")) |dir| {
        if (std.fs.path.isAbsolute(dir)) return std.fs.path.join(gpa, &.{ dir, "tx" });
    }
    return state(gpa, environ, "run");
}

extern "c" fn confstr(name: c_int, buf: [*]u8, len: usize) usize;

/// _CS_DARWIN_USER_TEMP_DIR in Darwin's <unistd.h>.
const cs_darwin_user_temp_dir = 65537;

pub fn home(gpa: Allocator, environ: *const Environ.Map, sub_path: []const u8) Error![]u8 {
    const dir = environ.get("HOME") orelse return error.NoHome;
    return std.fs.path.join(gpa, &.{ dir, sub_path });
}

fn xdg(gpa: Allocator, environ: *const Environ.Map, variable: []const u8, default: []const u8, name: []const u8) Error![]u8 {
    // The XDG Base Directory spec says to ignore a relative path in these
    // variables.
    if (environ.get(variable)) |dir| if (std.fs.path.isAbsolute(dir)) return std.fs.path.join(gpa, &.{ dir, "tx", name });

    const dir = environ.get("HOME") orelse return error.NoHome;
    return std.fs.path.join(gpa, &.{ dir, default, "tx", name });
}

/// The effective user's login name from the password database, else $USER.
/// A name from the database lives in libc's passwd buffer, which the next
/// getpwuid or getpwnam call overwrites.
pub fn userName(environ: *const Environ.Map) ?[]const u8 {
    if (std.c.getpwuid(std.c.geteuid())) |pw| if (pw.name) |name| return std.mem.span(name);
    return environ.get("USER");
}
