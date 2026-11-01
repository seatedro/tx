//! The harness for tx's fuzz tests. A test passes `run` a function that draws
//! the values of one input from an `Input` and checks the code under test with
//! them. Under `zig build fuzz --fuzz` the values come from the fuzzer through
//! std.testing.Smith. In an ordinary test run they come from a PRNG with a
//! fixed seed, `Options.count` inputs per test.

const std = @import("std");
const Smith = std.testing.Smith;

pub const Options = struct {
    /// Inputs per test in an ordinary test run. Fuzzing ignores it.
    count: usize = 1000,
};

/// Runs `testOne` on fuzz inputs. Call it from a test block.
pub fn run(
    context: anytype,
    comptime testOne: fn (context: @TypeOf(context), input: Input) anyerror!void,
    options: Options,
) !void {
    const Run = struct {
        context: @TypeOf(context),
        count: usize,

        fn one(r: @This(), smith: *Smith) anyerror!void {
            // The fuzzer calls once per input, with a null `in`.
            if (smith.in == null) return testOne(r.context, .{ .source = .{ .smith = smith } });

            // An ordinary test run calls once, with an empty `in`. The seed is
            // fixed, so the input a failure names is the same on the next run.
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

/// The values of one fuzz input, from the fuzzer or from the PRNG. The methods
/// are inline so that each call site in a test reaches Smith from a different
/// return address, which Smith uses to tell a test's choices apart.
pub const Input = struct {
    source: union(enum) {
        smith: *Smith,
        random: std.Random,
    },

    /// An integer from `at_least` to `at_most`, inclusive.
    pub inline fn int(in: Input, comptime T: type, at_least: T, at_most: T) T {
        return switch (in.source) {
            .smith => |s| @intCast(s.valueRangeAtMost(Fixed(T), at_least, at_most)),
            .random => |r| r.intRangeAtMost(T, at_least, at_most),
        };
    }

    /// Smith rejects integer types without a fixed size, such as usize.
    fn Fixed(comptime T: type) type {
        return switch (T) {
            usize => u64,
            isize => i64,
            else => T,
        };
    }

    /// Any value of T. With the PRNG, T must be an integer or bool.
    pub inline fn any(in: Input, comptime T: type) T {
        return switch (in.source) {
            .smith => |s| s.value(T),
            .random => |r| if (T == bool) r.boolean() else r.int(T),
        };
    }

    /// One of T's named values.
    pub inline fn enumValue(in: Input, comptime T: type) T {
        return switch (in.source) {
            .smith => |s| s.value(T),
            .random => |r| r.enumValue(T),
        };
    }

    /// An index less than `len`, which must be nonzero.
    pub inline fn index(in: Input, len: usize) usize {
        return switch (in.source) {
            .smith => |s| s.index(len),
            .random => |r| r.uintLessThan(usize, len),
        };
    }

    /// True with odds of `true_weight` to `false_weight`. Both must be nonzero.
    pub inline fn chance(in: Input, true_weight: u64, false_weight: u64) bool {
        return switch (in.source) {
            .smith => |s| s.boolWeighted(false_weight, true_weight),
            .random => |r| r.uintLessThan(u64, true_weight + false_weight) < true_weight,
        };
    }

    /// Fills a prefix of `buf`, from empty to all of it, and returns the prefix.
    pub inline fn bytes(in: Input, buf: []u8) []u8 {
        const len = switch (in.source) {
            .smith => |s| s.slice(buf),
            .random => |r| r.uintAtMost(usize, buf.len),
        };
        if (in.source == .random) in.source.random.bytes(buf[0..len]);
        return buf[0..len];
    }

    /// Fills all of `buf`.
    pub inline fn fill(in: Input, buf: []u8) void {
        switch (in.source) {
            .smith => |s| s.bytes(buf),
            .random => |r| r.bytes(buf),
        }
    }

    /// Whether the input ends here. Smith returns true eventually; the PRNG
    /// returns true one time in eight.
    pub inline fn done(in: Input) bool {
        return switch (in.source) {
            .smith => |s| s.eos(),
            .random => |r| r.uintLessThan(u8, 8) == 0,
        };
    }
};
