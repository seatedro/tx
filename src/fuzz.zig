const std = @import("std");
const Smith = std.testing.Smith;

pub const Options = struct {
    count: usize = 1000,
};

pub fn run(
    context: anytype,
    comptime testOne: fn (context: @TypeOf(context), input: Input) anyerror!void,
    options: Options,
) !void {
    const Run = struct {
        context: @TypeOf(context),
        count: usize,

        fn one(r: @This(), smith: *Smith) anyerror!void {
            if (smith.in == null) return testOne(r.context, .{ .source = .{ .smith = smith } });

            var prng: std.Random.DefaultPrng = .init(0x7478_6675_7a7a);
            for (0..r.count) |i| {
                testOne(r.context, .{ .source = .{ .random = prng.random() } }) catch |err| {
                    std.debug.print("fuzz: input {d} failed\n", .{i});
                    return err;
                };
            }
        }
    };
    return std.testing.fuzz(Run{ .context = context, .count = options.count }, Run.one, .{});
}

pub const Input = struct {
    source: union(enum) {
        smith: *Smith,
        random: std.Random,
    },

    pub inline fn int(in: Input, comptime T: type, at_least: T, at_most: T) T {
        return switch (in.source) {
            .smith => |s| @intCast(s.valueRangeAtMost(Fixed(T), at_least, at_most)),
            .random => |r| r.intRangeAtMost(T, at_least, at_most),
        };
    }

    fn Fixed(comptime T: type) type {
        return switch (T) {
            usize => u64,
            isize => i64,
            else => T,
        };
    }

    pub inline fn any(in: Input, comptime T: type) T {
        return switch (in.source) {
            .smith => |s| s.value(T),
            .random => |r| if (T == bool) r.boolean() else r.int(T),
        };
    }

    pub inline fn enumValue(in: Input, comptime T: type) T {
        return switch (in.source) {
            .smith => |s| s.value(T),
            .random => |r| r.enumValue(T),
        };
    }

    pub inline fn index(in: Input, len: usize) usize {
        return switch (in.source) {
            .smith => |s| s.index(len),
            .random => |r| r.uintLessThan(usize, len),
        };
    }

    pub inline fn chance(in: Input, true_weight: u64, false_weight: u64) bool {
        return switch (in.source) {
            .smith => |s| s.boolWeighted(false_weight, true_weight),
            .random => |r| r.uintLessThan(u64, true_weight + false_weight) < true_weight,
        };
    }

    pub inline fn bytes(in: Input, buf: []u8) []u8 {
        const len = switch (in.source) {
            .smith => |s| s.slice(buf),
            .random => |r| r.uintAtMost(usize, buf.len),
        };
        if (in.source == .random) in.source.random.bytes(buf[0..len]);
        return buf[0..len];
    }

    pub inline fn fill(in: Input, buf: []u8) void {
        switch (in.source) {
            .smith => |s| s.bytes(buf),
            .random => |r| r.bytes(buf),
        }
    }

    pub inline fn done(in: Input) bool {
        return switch (in.source) {
            .smith => |s| s.eos(),
            .random => |r| r.uintLessThan(u8, 8) == 0,
        };
    }
};
