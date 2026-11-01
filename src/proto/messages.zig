//! Every message and its body encoding. A message struct declares type_id,
//! which frame.zig writes in the frame header, and tags, a wire.zig field tag
//! for each struct field. Its encodedLen, encode and decode derive the body
//! from tags through bodyLen, encodeBody and decodeBody. Type ids below 1000
//! pass between tx and txd, and txd forwards some of them to and from session
//! processes. Ids from 1000 pass only between txd and session processes, on
//! unix sockets.

const std = @import("std");
const Writer = std.Io.Writer;
const wire = @import("wire.zig");
const DecodeError = wire.DecodeError;

/// Revision of the messages between tx and txd. Hello and HelloReply carry
/// it, each end refuses a peer with another, and the login signature covers it.
pub const revision: u32 = 0;

/// The client's first message on a connection.
pub const Hello = struct {
    revision: u32,
    term: []const u8,
    colorterm: ?[]const u8 = null,
    cols: u16,
    rows: u16,
    cell_width_px: ?u32 = null,
    cell_height_px: ?u32 = null,
    /// NAME=value entries, each ending in NUL, whose names pass isLocaleName.
    locale: ?[]const u8 = null,

    pub const type_id = 1;
    pub const tags = .{
        .revision = 1,
        .term = 2,
        .colorterm = 3,
        .cols = 4,
        .rows = 5,
        .cell_width_px = 6,
        .cell_height_px = 7,
        .locale = 8,
    };

    pub fn encodedLen(m: Hello) usize {
        return bodyLen(Hello, m);
    }

    pub fn encode(m: Hello, w: *Writer) Writer.Error!void {
        return encodeBody(Hello, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Hello {
        return decodeBody(Hello, bytes);
    }
};

/// Whether an environment variable name is LANG, or LC_ and then uppercase
/// letters and underscores. tx sends only these in Hello.locale, and txd
/// takes only these from it.
pub fn isLocaleName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "LANG")) return true;
    if (!std.mem.startsWith(u8, name, "LC_") or name.len == "LC_".len) return false;
    for (name["LC_".len..]) |c| if (!std.ascii.isUpper(c) and c != '_') return false;
    return true;
}

/// txd's answer to Hello.
pub const HelloReply = struct {
    revision: u32,

    pub const type_id = 2;
    pub const tags = .{ .revision = 1 };

    pub fn encodedLen(m: HelloReply) usize {
        return bodyLen(HelloReply, m);
    }

    pub fn encode(m: HelloReply, w: *Writer) Writer.Error!void {
        return encodeBody(HelloReply, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!HelloReply {
        return decodeBody(HelloReply, bytes);
    }
};

/// Asks for a terminal session. txd passes it on to the session process
/// after Connect. With no session_id, reuse or command, txd starts a new
/// session.
pub const Attach = struct {
    session_id: ?u64 = null,
    /// Attaches to the one detached session, or starts a new session when
    /// none is detached. More than one detached is ErrorCode.several_detached.
    reuse: bool = false,
    /// Runs through txd's shell with -c in a new session. session_id and
    /// reuse must be unset.
    command: ?[]const u8 = null,
    /// Terminfo source for Hello.term, which txd compiles for a new session.
    terminfo: ?[]const u8 = null,
    /// The client terminal's default colors as 0xRRGGBB.
    foreground: ?u32 = null,
    background: ?u32 = null,
    /// 4-byte {index, r, g, b} entries for palette indexes below 16.
    palette: ?[]const u8 = null,
    /// Whether the client's terminal reports a dark color scheme.
    dark: ?bool = null,
    /// A new session sends SIGHUP to its program's process group when its
    /// client leaves, or when the client stays lost for
    /// session.session.hangup_grace_ms.
    hangup: bool = false,

    pub const type_id = 3;
    pub const tags = .{
        .session_id = 1,
        .reuse = 2,
        .command = 3,
        .terminfo = 4,
        .foreground = 5,
        .background = 6,
        .palette = 7,
        .dark = 8,
        .hangup = 9,
    };

    pub fn encodedLen(m: Attach) usize {
        return bodyLen(Attach, m);
    }

    pub fn encode(m: Attach, w: *Writer) Writer.Error!void {
        return encodeBody(Attach, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Attach {
        return decodeBody(Attach, bytes);
    }
};

/// The session's answer to Attach or Resume, forwarded by txd.
pub const Attached = struct {
    session_id: u64,
    /// The secret that a later Resume proves the client holds. Each Attach or
    /// Resume gets a new one.
    resume_key: []const u8,
    /// Input bytes the session has received since the last Attach. On a
    /// resume the client resends its input past this offset.
    input_offset: u64 = 0,

    pub const type_id = 4;
    pub const tags = .{ .session_id = 1, .resume_key = 2, .input_offset = 3 };

    pub fn encodedLen(m: Attached) usize {
        return bodyLen(Attached, m);
    }

    pub fn encode(m: Attached, w: *Writer) Writer.Error!void {
        return encodeBody(Attached, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Attached {
        return decodeBody(Attached, bytes);
    }
};

/// Program output, one record of the session's log.
pub const Output = struct {
    /// The record's sequence number in the log.
    seq: u64,
    bytes: []const u8,

    pub const type_id = 5;
    pub const tags = .{ .seq = 1, .bytes = 2 };

    pub fn encodedLen(m: Output) usize {
        return bodyLen(Output, m);
    }

    pub fn encode(m: Output, w: *Writer) Writer.Error!void {
        return encodeBody(Output, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Output {
        return decodeBody(Output, bytes);
    }
};

/// The client's acknowledgement of the Output with this seq.
pub const Ack = struct {
    seq: u64,

    pub const type_id = 6;
    pub const tags = .{ .seq = 1 };

    pub fn encodedLen(m: Ack) usize {
        return bodyLen(Ack, m);
    }

    pub fn encode(m: Ack, w: *Writer) Writer.Error!void {
        return encodeBody(Ack, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Ack {
        return decodeBody(Ack, bytes);
    }
};

/// Bytes for the program's terminal input, from the client.
pub const Input = struct {
    bytes: []const u8,

    pub const type_id = 7;
    pub const tags = .{ .bytes = 1 };

    pub fn encodedLen(m: Input) usize {
        return bodyLen(Input, m);
    }

    pub fn encode(m: Input, w: *Writer) Writer.Error!void {
        return encodeBody(Input, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Input {
        return decodeBody(Input, bytes);
    }
};

pub const Resize = struct {
    cols: u16,
    rows: u16,
    cell_width_px: ?u32 = null,
    cell_height_px: ?u32 = null,

    pub const type_id = 8;
    pub const tags = .{
        .cols = 1,
        .rows = 2,
        .cell_width_px = 3,
        .cell_height_px = 4,
    };

    pub fn encodedLen(m: Resize) usize {
        return bodyLen(Resize, m);
    }

    pub fn encode(m: Resize, w: *Writer) Writer.Error!void {
        return encodeBody(Resize, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Resize {
        return decodeBody(Resize, bytes);
    }
};

/// From a client, asks txd to close the connection. From txd to a session
/// process, says the client closed its connection itself.
pub const Detach = struct {
    pub const type_id = 9;
    pub const tags = .{};

    pub fn encodedLen(m: Detach) usize {
        return bodyLen(Detach, m);
    }

    pub fn encode(m: Detach, w: *Writer) Writer.Error!void {
        return encodeBody(Detach, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Detach {
        return decodeBody(Detach, bytes);
    }
};

/// The session's program, or an Exec command, ended.
pub const Exit = struct {
    /// The exit status, or 128 plus the signal number, or 255 when the
    /// process's end is unknown.
    status: u8 = 0,
    /// The signal's name without "SIG".
    signal: ?[]const u8 = null,

    pub const type_id = 10;
    pub const tags = .{ .status = 1, .signal = 2 };

    pub fn encodedLen(m: Exit) usize {
        return bodyLen(Exit, m);
    }

    pub fn encode(m: Exit, w: *Writer) Writer.Error!void {
        return encodeBody(Exit, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Exit {
        return decodeBody(Exit, bytes);
    }
};

/// Values of Error.code.
pub const ErrorCode = enum(u32) {
    /// A malformed or unexpected message, or a failure with no code of its own.
    protocol = 1,
    /// The peer has another revision or internal_revision.
    revision = 2,
    /// The session doesn't exist or has ended.
    no_session = 3,
    /// The session's log no longer holds the output the client needs next.
    log_trimmed = 4,
    /// A session or command didn't start.
    spawn = 5,
    /// A login or a resume was refused.
    auth = 6,
    /// Another client attached to the session.
    attached_elsewhere = 7,
    /// Attach.reuse found several detached sessions. The message lists their
    /// ids.
    several_detached = 8,
    /// The session process's connection closed without an Exit or Error.
    session_lost = 9,
};

/// A failure. The sender finishes its side of the stream after it.
pub const Error = struct {
    /// An ErrorCode value.
    code: u32,
    /// Text for the user.
    message: []const u8 = "",

    pub const type_id = 11;
    pub const tags = .{ .code = 1, .message = 2 };

    pub fn encodedLen(m: Error) usize {
        return bodyLen(Error, m);
    }

    pub fn encode(m: Error, w: *Writer) Writer.Error!void {
        return encodeBody(Error, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Error {
        return decodeBody(Error, bytes);
    }
};

/// Asks whether txd accepts a public key for a user, before the client signs
/// with it.
pub const AuthProbe = struct {
    /// Empty means the account txd runs as.
    user: []const u8,
    /// An SSH public key blob.
    key: []const u8,

    pub const type_id = 12;
    pub const tags = .{ .user = 1, .key = 2 };

    pub fn encodedLen(m: AuthProbe) usize {
        return bodyLen(AuthProbe, m);
    }

    pub fn encode(m: AuthProbe, w: *Writer) Writer.Error!void {
        return encodeBody(AuthProbe, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthProbe {
        return decodeBody(AuthProbe, bytes);
    }
};

pub const AuthProbeReply = struct {
    /// The probed key, echoed.
    key: []const u8,
    accepted: bool,

    pub const type_id = 13;
    pub const tags = .{ .key = 1, .accepted = 2 };

    pub fn encodedLen(m: AuthProbeReply) usize {
        return bodyLen(AuthProbeReply, m);
    }

    pub fn encode(m: AuthProbeReply, w: *Writer) Writer.Error!void {
        return encodeBody(AuthProbeReply, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthProbeReply {
        return decodeBody(AuthProbeReply, bytes);
    }
};

pub const AuthSignature = struct {
    user: []const u8,
    key: []const u8,
    /// The key's signature over an auth.login.Transcript of this connection.
    signature: []const u8,

    pub const type_id = 14;
    pub const tags = .{ .user = 1, .key = 2, .signature = 3 };

    pub fn encodedLen(m: AuthSignature) usize {
        return bodyLen(AuthSignature, m);
    }

    pub fn encode(m: AuthSignature, w: *Writer) Writer.Error!void {
        return encodeBody(AuthSignature, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthSignature {
        return decodeBody(AuthSignature, bytes);
    }
};

pub const AuthOk = struct {
    pub const type_id = 15;
    pub const tags = .{};

    pub fn encodedLen(m: AuthOk) usize {
        return bodyLen(AuthOk, m);
    }

    pub fn encode(m: AuthOk, w: *Writer) Writer.Error!void {
        return encodeBody(AuthOk, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthOk {
        return decodeBody(AuthOk, bytes);
    }
};

/// Terminal output that redraws the session's screen. A long redraw comes in
/// several Rebuild messages.
pub const Rebuild = struct {
    /// The seq of the Output that follows the redraw.
    seq: u64,
    bytes: []const u8,

    pub const type_id = 16;
    pub const tags = .{ .seq = 1, .bytes = 2 };

    pub fn encodedLen(m: Rebuild) usize {
        return bodyLen(Rebuild, m);
    }

    pub fn encode(m: Rebuild, w: *Writer) Writer.Error!void {
        return encodeBody(Rebuild, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Rebuild {
        return decodeBody(Rebuild, bytes);
    }
};

/// Reattaches a client that lost its connection. txd accepts it before login.
/// The session checks proof, and its Attached completes the login.
pub const Resume = struct {
    session_id: u64,
    /// The seq of the next Output the client needs. Null asks for a redraw.
    next_seq: ?u64 = null,
    /// auth.resume_.proof from Attached.resume_key, this connection's resume
    /// exporter secret and session_id.
    proof: []const u8,

    pub const type_id = 17;
    pub const tags = .{ .session_id = 1, .next_seq = 2, .proof = 3 };

    pub fn encodedLen(m: Resume) usize {
        return bodyLen(Resume, m);
    }

    pub fn encode(m: Resume, w: *Writer) Writer.Error!void {
        return encodeBody(Resume, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Resume {
        return decodeBody(Resume, bytes);
    }
};

/// Asks for the sessions. txd sends List to each session process, and answers
/// the client with their SessionInfo messages and then ListEnd.
pub const List = struct {
    pub const type_id = 18;
    pub const tags = .{};

    pub fn encodedLen(m: List) usize {
        return bodyLen(List, m);
    }

    pub fn encode(m: List, w: *Writer) Writer.Error!void {
        return encodeBody(List, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!List {
        return decodeBody(List, bytes);
    }
};

pub const SessionInfo = struct {
    session_id: u64,
    cols: u16,
    rows: u16,
    /// Seconds since the session started.
    running_s: u64,
    /// The attached client's address. Null while detached.
    attached_from: ?[]const u8 = null,
    title: ?[]const u8 = null,
    /// The session process's pid.
    pid: ?u64 = null,

    pub const type_id = 19;
    pub const tags = .{ .session_id = 1, .cols = 2, .rows = 3, .running_s = 4, .attached_from = 5, .title = 6, .pid = 7 };

    pub fn encodedLen(m: SessionInfo) usize {
        return bodyLen(SessionInfo, m);
    }

    pub fn encode(m: SessionInfo, w: *Writer) Writer.Error!void {
        return encodeBody(SessionInfo, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!SessionInfo {
        return decodeBody(SessionInfo, bytes);
    }
};

pub const ListEnd = struct {
    pub const type_id = 20;
    pub const tags = .{};

    pub fn encodedLen(m: ListEnd) usize {
        return bodyLen(ListEnd, m);
    }

    pub fn encode(m: ListEnd, w: *Writer) Writer.Error!void {
        return encodeBody(ListEnd, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!ListEnd {
        return decodeBody(ListEnd, bytes);
    }
};

/// Ends a session's program. txd passes it to the session process and
/// answers with Killed.
pub const Kill = struct {
    session_id: u64,

    pub const type_id = 21;
    pub const tags = .{ .session_id = 1 };

    pub fn encodedLen(m: Kill) usize {
        return bodyLen(Kill, m);
    }

    pub fn encode(m: Kill, w: *Writer) Writer.Error!void {
        return encodeBody(Kill, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Kill {
        return decodeBody(Kill, bytes);
    }
};

pub const Killed = struct {
    session_id: u64,

    pub const type_id = 22;
    pub const tags = .{ .session_id = 1 };

    pub fn encodedLen(m: Killed) usize {
        return bodyLen(Killed, m);
    }

    pub fn encode(m: Killed, w: *Writer) Writer.Error!void {
        return encodeBody(Killed, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Killed {
        return decodeBody(Killed, bytes);
    }
};

/// Runs a command through txd's shell with -c, without a terminal. Its
/// output comes on streams of its own, and Exit follows on the main stream.
pub const Exec = struct {
    command: []const u8,

    pub const type_id = 23;
    pub const tags = .{ .command = 1 };

    pub fn encodedLen(m: Exec) usize {
        return bodyLen(Exec, m);
    }

    pub fn encode(m: Exec, w: *Writer) Writer.Error!void {
        return encodeBody(Exec, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Exec {
        return decodeBody(Exec, bytes);
    }
};

/// Offers the client's clipboard contents, which txd reads with
/// ClipboardRequest.
pub const ClipboardOffer = struct {
    /// The client clipboard's change count.
    change: u64,
    /// MIME types, each ending in NUL.
    mimes: []const u8,

    pub const type_id = 24;
    pub const tags = .{ .change = 1, .mimes = 2 };

    pub fn encodedLen(m: ClipboardOffer) usize {
        return bodyLen(ClipboardOffer, m);
    }

    pub fn encode(m: ClipboardOffer, w: *Writer) Writer.Error!void {
        return encodeBody(ClipboardOffer, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!ClipboardOffer {
        return decodeBody(ClipboardOffer, bytes);
    }
};

/// Asks to read the client's clipboard. The client answers on a stream it
/// opens.
pub const ClipboardRequest = struct {
    /// Echoed in the answer's ClipboardData.
    id: u64,
    /// The change count of the offer being read. The client refuses when its
    /// clipboard has changed since.
    change: u64,
    mime: []const u8,

    pub const type_id = 25;
    pub const tags = .{ .id = 1, .change = 2, .mime = 3 };

    pub fn encodedLen(m: ClipboardRequest) usize {
        return bodyLen(ClipboardRequest, m);
    }

    pub fn encode(m: ClipboardRequest, w: *Writer) Writer.Error!void {
        return encodeBody(ClipboardRequest, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!ClipboardRequest {
        return decodeBody(ClipboardRequest, bytes);
    }
};

/// The first frame of a client stream that answers a ClipboardRequest. The
/// clipboard's bytes follow it until the stream ends, unless refused is set.
pub const ClipboardData = struct {
    id: u64,
    refused: bool = false,

    pub const type_id = 26;
    pub const tags = .{ .id = 1, .refused = 2 };

    pub fn encodedLen(m: ClipboardData) usize {
        return bodyLen(ClipboardData, m);
    }

    pub fn encode(m: ClipboardData, w: *Writer) Writer.Error!void {
        return encodeBody(ClipboardData, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!ClipboardData {
        return decodeBody(ClipboardData, bytes);
    }
};

/// The first frame of a txd stream that sets the client's clipboard. The data
/// for each MIME type follows it in order, back to back.
pub const ClipboardCopy = struct {
    /// MIME types, each ending in NUL.
    mimes: []const u8,
    /// Each MIME type's data length as 8 bytes big-endian.
    lens: []const u8,

    pub const type_id = 27;
    pub const tags = .{ .mimes = 1, .lens = 2 };

    pub fn encodedLen(m: ClipboardCopy) usize {
        return bodyLen(ClipboardCopy, m);
    }

    pub fn encode(m: ClipboardCopy, w: *Writer) Writer.Error!void {
        return encodeBody(ClipboardCopy, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!ClipboardCopy {
        return decodeBody(ClipboardCopy, bytes);
    }
};

/// Revision of the messages between txd and session processes. Start and
/// Connect carry it, and a session process refuses a txd with another.
pub const internal_revision: u32 = 0;

/// The first message on a connection that txd opens to a session's socket for
/// a client. Attach or Resume follows.
pub const Connect = struct {
    /// The client's address.
    remote: []const u8,
    cols: u16,
    rows: u16,
    cell_width_px: ?u32 = null,
    cell_height_px: ?u32 = null,
    /// The client connection's resume exporter secret, to check the Resume
    /// that follows. Null before an Attach.
    resume_exporter: ?[]const u8 = null,
    internal_revision: u32 = 0,

    pub const type_id = 1000;
    pub const tags = .{ .remote = 1, .cols = 2, .rows = 3, .cell_width_px = 4, .cell_height_px = 5, .resume_exporter = 6, .internal_revision = 7 };

    pub fn encodedLen(m: Connect) usize {
        return bodyLen(Connect, m);
    }

    pub fn encode(m: Connect, w: *Writer) Writer.Error!void {
        return encodeBody(Connect, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Connect {
        return decodeBody(Connect, bytes);
    }
};

/// The first message to a new session process, on the socket it inherits.
/// The process answers with Started.
pub const Start = struct {
    session_id: u64,
    /// Where the process listens for connections from txd.
    socket_path: []const u8,
    /// Arguments, each ending in NUL.
    argv: []const u8,
    /// The file to execute. Null runs argv[0].
    program: ?[]const u8 = null,
    /// Null keeps the session process's directory.
    cwd: ?[]const u8 = null,
    /// NAME=value entries, each ending in NUL.
    environ: []const u8,
    cols: u16,
    rows: u16,
    cell_width_px: ?u32 = null,
    cell_height_px: ?u32 = null,
    max_scrollback_bytes: ?u64 = null,
    max_scrollback_lines: ?u64 = null,
    kitty_image_storage_limit: u64,
    log_capacity: u64,
    internal_revision: u32 = 0,

    pub const type_id = 1001;
    pub const tags = .{
        .session_id = 1,
        .socket_path = 2,
        .argv = 3,
        .program = 4,
        .cwd = 5,
        .environ = 6,
        .cols = 7,
        .rows = 8,
        .cell_width_px = 9,
        .cell_height_px = 10,
        .max_scrollback_bytes = 11,
        .max_scrollback_lines = 12,
        .kitty_image_storage_limit = 13,
        .log_capacity = 14,
        .internal_revision = 15,
    };

    pub fn encodedLen(m: Start) usize {
        return bodyLen(Start, m);
    }

    pub fn encode(m: Start, w: *Writer) Writer.Error!void {
        return encodeBody(Start, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Start {
        return decodeBody(Start, bytes);
    }
};

pub const Started = struct {
    /// The session process's pid.
    pid: u64,

    pub const type_id = 1002;
    pub const tags = .{ .pid = 1 };

    pub fn encodedLen(m: Started) usize {
        return bodyLen(Started, m);
    }

    pub fn encode(m: Started, w: *Writer) Writer.Error!void {
        return encodeBody(Started, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Started {
        return decodeBody(Started, bytes);
    }
};

/// Asks a session process for its terminal's state, answered with DumpReply.
pub const Dump = struct {
    pub const type_id = 1003;
    pub const tags = .{};

    pub fn encodedLen(m: Dump) usize {
        return bodyLen(Dump, m);
    }

    pub fn encode(m: Dump, w: *Writer) Writer.Error!void {
        return encodeBody(Dump, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Dump {
        return decodeBody(Dump, bytes);
    }
};

pub const DumpReply = struct {
    /// term.state.dumpAlloc of the terminal.
    state: []const u8,
    /// The terminal's contents as plain text.
    text: []const u8,
    cols: u16,
    rows: u16,

    pub const type_id = 1004;
    pub const tags = .{ .state = 1, .text = 2, .cols = 3, .rows = 4 };

    pub fn encodedLen(m: DumpReply) usize {
        return bodyLen(DumpReply, m);
    }

    pub fn encode(m: DumpReply, w: *Writer) Writer.Error!void {
        return encodeBody(DumpReply, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!DumpReply {
        return decodeBody(DumpReply, bytes);
    }
};

/// Bytes that a session's program reads as typed input.
pub const Inject = struct {
    bytes: []const u8,

    pub const type_id = 1005;
    pub const tags = .{ .bytes = 1 };

    pub fn encodedLen(m: Inject) usize {
        return bodyLen(Inject, m);
    }

    pub fn encode(m: Inject, w: *Writer) Writer.Error!void {
        return encodeBody(Inject, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Inject {
        return decodeBody(Inject, bytes);
    }
};

/// Any message. Each payload type's type_id identifies it in a frame.
pub const Message = union(enum) {
    hello: Hello,
    hello_reply: HelloReply,
    attach: Attach,
    attached: Attached,
    output: Output,
    ack: Ack,
    input: Input,
    resize: Resize,
    detach: Detach,
    exit: Exit,
    @"error": Error,
    auth_probe: AuthProbe,
    auth_probe_reply: AuthProbeReply,
    auth_signature: AuthSignature,
    auth_ok: AuthOk,
    rebuild: Rebuild,
    @"resume": Resume,
    list: List,
    session_info: SessionInfo,
    list_end: ListEnd,
    kill: Kill,
    killed: Killed,
    exec: Exec,
    clipboard_offer: ClipboardOffer,
    clipboard_request: ClipboardRequest,
    clipboard_data: ClipboardData,
    clipboard_copy: ClipboardCopy,
    connect: Connect,
    start: Start,
    started: Started,
    dump: Dump,
    dump_reply: DumpReply,
    inject: Inject,
    unknown: Unknown,

    /// A type id with no message type in this file. Encoding writes body
    /// unchanged.
    pub const Unknown = struct {
        type_id: u64,
        body: []const u8,
    };

    comptime {
        const types = @typeInfo(Message).@"union".field_types;
        for (types, 0..) |T, i| {
            if (T == Unknown) continue;
            for (types[0..i]) |U| {
                if (U != Unknown and U.type_id == T.type_id)
                    @compileError(@typeName(T) ++ " reuses a message type");
            }
        }
    }

    pub fn typeId(m: Message) u64 {
        return switch (m) {
            .unknown => |u| u.type_id,
            inline else => |v| @TypeOf(v).type_id,
        };
    }

    /// Length of the body alone. frame.encodedLen adds the frame header.
    pub fn encodedLen(m: Message) usize {
        return switch (m) {
            .unknown => |u| u.body.len,
            inline else => |v| v.encodedLen(),
        };
    }

    /// Writes the body alone. frame.encode adds the frame header.
    pub fn encode(m: Message, w: *Writer) Writer.Error!void {
        return switch (m) {
            .unknown => |u| w.writeAll(u.body),
            inline else => |v| v.encode(w),
        };
    }

    /// Decodes a body as the message type with this type_id, or returns it
    /// as unknown. Slices in the result point into body.
    pub fn decode(type_id: u64, body: []const u8) DecodeError!Message {
        inline for (@typeInfo(Message).@"union".field_names, @typeInfo(Message).@"union".field_types) |name, T| {
            if (T != Unknown and type_id == T.type_id)
                return @unionInit(Message, name, try T.decode(body));
        }
        return .{ .unknown = .{ .type_id = type_id, .body = body } };
    }
};

fn checkSchema(comptime M: type) void {
    comptime {
        const info = @typeInfo(M).@"struct";
        const Tags = @TypeOf(M.tags);
        const tag_names = @typeInfo(Tags).@"struct".field_names;
        if (tag_names.len != info.field_names.len)
            @compileError(@typeName(M) ++ ".tags must name each field once");

        // decodeBody marks the fields it has seen in a u64.
        if (info.field_names.len > 64)
            @compileError(@typeName(M) ++ " has more than 64 fields");

        for (info.field_names, info.field_types, 0..) |name, T, i| {
            if (!@hasField(Tags, name))
                @compileError(@typeName(M) ++ "." ++ name ++ " has no tag");

            const tag = @field(M.tags, name);
            if (tag < 0 or tag > wire.max_varint)
                @compileError(@typeName(M) ++ "." ++ name ++ " has an invalid tag");

            for (info.field_names[0..i]) |prev| {
                if (@field(M.tags, prev) == tag)
                    @compileError(@typeName(M) ++ "." ++ name ++ " reuses a tag");
            }

            const V = switch (@typeInfo(T)) {
                .optional => |o| o.child,
                else => T,
            };
            if (V != []const u8 and V != bool and !(@typeInfo(V) == .int and
                @typeInfo(V).int.signedness == .unsigned and @typeInfo(V).int.bits <= 64))
                @compileError(@typeName(M) ++ "." ++ name ++ " has an unsupported type");
        }
    }
}

// A bool is an integer field holding 0 or 1.
fn valueLen(comptime T: type, tag: u64, value: T) usize {
    if (T == []const u8) return wire.fieldLen(tag, value.len);
    if (T == bool) return wire.uintFieldLen(tag, @intFromBool(value));
    return wire.uintFieldLen(tag, value);
}

fn writeValue(comptime T: type, w: *Writer, tag: u64, value: T) Writer.Error!void {
    if (T == []const u8) return wire.writeBytesField(w, tag, value);
    if (T == bool) return wire.writeUintField(w, tag, @intFromBool(value));
    return wire.writeUintField(w, tag, value);
}

fn readValue(comptime T: type, bytes: []const u8) DecodeError!T {
    if (@typeInfo(T) == .optional) return try readValue(@typeInfo(T).optional.child, bytes);
    if (T == []const u8) return bytes;
    if (T == bool) return try wire.readUint(u1, bytes) == 1;
    return wire.readUint(T, bytes);
}

fn bodyLen(comptime M: type, m: M) usize {
    comptime checkSchema(M);
    const info = @typeInfo(M).@"struct";
    var len: usize = 0;
    inline for (info.field_names, info.field_types) |name, T| {
        const tag = @field(M.tags, name);
        const value = @field(m, name);
        switch (@typeInfo(T)) {
            .optional => |o| if (value) |v| {
                len += valueLen(o.child, tag, v);
            },
            else => len += valueLen(T, tag, value),
        }
    }
    return len;
}

/// Writes the fields in declaration order. A null optional is left out, and
/// every other field is written, also when it holds its default.
fn encodeBody(comptime M: type, m: M, w: *Writer) Writer.Error!void {
    comptime checkSchema(M);
    const info = @typeInfo(M).@"struct";
    inline for (info.field_names, info.field_types) |name, T| {
        const tag = @field(M.tags, name);
        const value = @field(m, name);
        switch (@typeInfo(T)) {
            .optional => |o| if (value) |v| try writeValue(o.child, w, tag, v),
            else => try writeValue(T, w, tag, value),
        }
    }
}

/// Skips fields with unknown tags, and keeps the last value of a repeated
/// tag. An absent field takes its default, or fails with MissingField when it
/// has none. Byte slices in the result point into bytes.
fn decodeBody(comptime M: type, bytes: []const u8) DecodeError!M {
    comptime checkSchema(M);
    const info = @typeInfo(M).@"struct";
    var m: M = undefined;

    // Bit i is set once field i has a value.
    var seen: u64 = 0;

    var it: wire.FieldIterator = .init(bytes);
    while (try it.next()) |field| {
        inline for (info.field_names, info.field_types, 0..) |name, T, i| {
            if (field.tag == @field(M.tags, name)) {
                @field(m, name) = try readValue(T, field.value);
                seen |= @as(u64, 1) << i;
            }
        }
    }

    inline for (info.field_names, info.field_types, info.field_attrs, 0..) |name, T, attrs, i| {
        if (seen & (@as(u64, 1) << i) == 0)
            @field(m, name) = attrs.defaultValue(T) orelse return error.MissingField;
    }
    return m;
}

const testing = std.testing;

fn roundTrip(buf: []u8, m: Message) !Message {
    var w: Writer = .fixed(buf);
    try m.encode(&w);
    try testing.expectEqual(m.encodedLen(), w.buffered().len);
    return Message.decode(m.typeId(), w.buffered());
}

test "every message round trips" {
    const samples = [_]Message{
        .{ .hello = .{
            .revision = revision,
            .term = "xterm-ghostty",
            .colorterm = "truecolor",
            .cols = 80,
            .rows = 24,
            .cell_width_px = 10,
            .cell_height_px = 20,
            .locale = "LANG=en_US.UTF-8\x00LC_TIME=en_GB.UTF-8\x00",
        } },
        .{ .hello_reply = .{ .revision = 7 } },
        .{ .attach = .{ .session_id = std.math.maxInt(u64) } },
        .{ .attach = .{} },
        .{ .attached = .{ .session_id = 0x0123_4567_89ab_cdef, .resume_key = "key", .input_offset = 9 } },
        .{ .output = .{ .seq = 1 << 40, .bytes = "\x1b[1mhi\x1b[m" } },
        .{ .output = .{ .seq = 0, .bytes = "" } },
        .{ .ack = .{ .seq = 300 } },
        .{ .input = .{ .bytes = "\x03" } },
        .{ .resize = .{ .cols = 65535, .rows = 1, .cell_width_px = 0, .cell_height_px = 1 << 31 } },
        .{ .detach = .{} },
        .{ .exit = .{ .status = 255 } },
        .{ .exit = .{ .signal = "KILL" } },
        .{ .@"error" = .{ .code = 4, .message = "no such session" } },
        .{ .auth_probe = .{ .user = "rohit", .key = "blob" } },
        .{ .auth_probe_reply = .{ .key = "blob", .accepted = true } },
        .{ .auth_probe_reply = .{ .key = "blob", .accepted = false } },
        .{ .auth_signature = .{ .user = "rohit", .key = "blob", .signature = "sig" } },
        .{ .auth_ok = .{} },
        .{ .rebuild = .{ .seq = 12, .bytes = "\x1b[Hab" } },
        .{ .rebuild = .{ .seq = 0, .bytes = "" } },
        .{ .@"resume" = .{ .session_id = 3, .next_seq = 40, .proof = "proof" } },
        .{ .@"resume" = .{ .session_id = 3, .proof = "" } },
        .{ .attach = .{ .reuse = true } },
        .{ .list = .{} },
        .{ .session_info = .{ .session_id = 2, .cols = 80, .rows = 24, .running_s = 3600, .attached_from = "127.0.0.1:5000", .title = "vim", .pid = 99 } },
        .{ .session_info = .{ .session_id = 3, .cols = 80, .rows = 24, .running_s = 0 } },
        .{ .list_end = .{} },
        .{ .kill = .{ .session_id = 2 } },
        .{ .killed = .{ .session_id = 2 } },
        .{ .exec = .{ .command = "git-upload-pack 'repo'" } },
        .{ .clipboard_offer = .{ .change = 7, .mimes = "image/png\x00text/plain\x00" } },
        .{ .clipboard_offer = .{ .change = 8, .mimes = "" } },
        .{ .clipboard_request = .{ .id = 1, .change = 7, .mime = "image/png" } },
        .{ .clipboard_data = .{ .id = 1 } },
        .{ .clipboard_data = .{ .id = 2, .refused = true } },
        .{ .clipboard_copy = .{ .mimes = "text/plain\x00", .lens = "\x00\x00\x00\x00\x00\x00\x00\x05" } },
        .{ .connect = .{ .remote = "[::1]:5000", .cols = 80, .rows = 24, .cell_width_px = 9, .cell_height_px = 18, .resume_exporter = "exporter" } },
        .{ .connect = .{ .remote = "", .cols = 1, .rows = 1 } },
        .{ .start = .{
            .session_id = 4,
            .socket_path = "/run/user/1000/tx/4.sock",
            .argv = "-zsh\x00",
            .program = "/bin/zsh",
            .cwd = "/home/rohit",
            .environ = "TERM=xterm\x00HOME=/home/rohit\x00",
            .cols = 80,
            .rows = 24,
            .max_scrollback_bytes = 1 << 20,
            .kitty_image_storage_limit = 0,
            .log_capacity = 4096,
        } },
        .{ .started = .{ .pid = 4321 } },
        .{ .dump = .{} },
        .{ .dump_reply = .{ .state = "state", .text = "text", .cols = 80, .rows = 24 } },
        .{ .inject = .{ .bytes = "ls\r" } },
        .{ .unknown = .{ .type_id = 1999, .body = "\x01\x00" } },
    };
    var buf: [256]u8 = undefined;
    for (samples) |m| try testing.expectEqualDeep(m, try roundTrip(&buf, m));
}

test "absent optional fields decode to their defaults" {
    var buf: [256]u8 = undefined;
    const hello = try roundTrip(&buf, .{ .hello = .{ .revision = 0, .term = "xterm", .cols = 80, .rows = 24 } });
    try testing.expectEqual(null, hello.hello.colorterm);
    try testing.expectEqual(null, hello.hello.cell_width_px);
    try testing.expectEqual(null, hello.hello.cell_height_px);
    try testing.expectEqual(null, hello.hello.locale);

    try testing.expectEqual(null, (try Attach.decode("")).session_id);
    const exit = try Exit.decode("");
    try testing.expectEqual(0, exit.status);
    try testing.expectEqual(null, exit.signal);
    try testing.expectEqualStrings("", (try Error.decode(&.{ 0x01, 0x00 })).message);
}

test "a missing required field is an error" {
    try testing.expectError(error.MissingField, Output.decode(&.{ 0x01, 0x00 }));
    try testing.expectError(error.MissingField, Hello.decode(""));
    try testing.expectError(error.MissingField, Error.decode(&.{ 0x02, 0x01, 'x' }));
}

test "a field value of the wrong type is an error" {
    try testing.expectError(error.WrongType, Resize.decode(&.{ 0x01, 0x03, 0x01, 0x11, 0x70, 0x02, 0x00 }));
    try testing.expectError(error.WrongType, Ack.decode(&.{ 0x01, 0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0 }));
    try testing.expectError(error.NonMinimal, Ack.decode(&.{ 0x01, 0x01, 0x00 }));
}

test "a bool is 0 or 1" {
    try testing.expectError(error.WrongType, AuthProbeReply.decode(&.{ 0x01, 0x00, 0x02, 0x01, 0x02 }));
    try testing.expectEqual(false, (try AuthProbeReply.decode(&.{ 0x01, 0x00, 0x02, 0x00 })).accepted);
}

test "unknown fields are skipped" {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try wire.writeBytesField(&w, 1000, "from a later revision");
    try (Ack{ .seq = 9 }).encode(&w);
    try wire.writeUintField(&w, 63, 1);
    try testing.expectEqual(9, (try Ack.decode(w.buffered())).seq);
}

test "the last occurrence of a repeated field is used" {
    try testing.expectEqual(2, (try Ack.decode(&.{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x02 })).seq);
}

test "decoded bytes point into the input" {
    const body = [_]u8{ 0x01, 0x01, 0x05, 0x02, 0x02, 'h', 'i' };
    const output = try Output.decode(&body);
    try testing.expectEqual(5, output.seq);
    try testing.expectEqual(@as([*]const u8, &body) + 5, output.bytes.ptr);
}

test isLocaleName {
    for ([_][]const u8{ "LANG", "LC_ALL", "LC_CTYPE", "LC_MEASUREMENT" }) |name| try testing.expect(isLocaleName(name));
    for ([_][]const u8{ "", "LANGUAGE", "LC_", "LC_ctype", "LC_CTYPE=", "XLC_ALL", "PATH" }) |name| try testing.expect(!isLocaleName(name));
}

test "Hello encoding is stable" {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try (Hello{ .revision = 0, .term = "xterm", .colorterm = "truecolor", .cols = 80, .rows = 300 }).encode(&w);
    try testing.expectEqualSlices(u8, "\x01\x00" ++
        "\x02\x05xterm" ++
        "\x03\x09truecolor" ++
        "\x04\x01\x50" ++
        "\x05\x02\x01\x2c", w.buffered());
}
