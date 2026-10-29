//! The tx wire protocol: message encoding and framing.
//!
//! `wire` has the varint and field encodings, `messages` the revision 0
//! messages, and `frame` the framing of messages on a stream.
pub const wire = @import("wire.zig");
pub const messages = @import("messages.zig");
pub const frame = @import("frame.zig");

pub const revision = messages.revision;
pub const DecodeError = wire.DecodeError;

pub const Message = messages.Message;
pub const Hello = messages.Hello;
pub const HelloReply = messages.HelloReply;
pub const Attach = messages.Attach;
pub const Attached = messages.Attached;
pub const Output = messages.Output;
pub const Ack = messages.Ack;
pub const Input = messages.Input;
pub const Resize = messages.Resize;
pub const Detach = messages.Detach;
pub const Exit = messages.Exit;
pub const Error = messages.Error;
pub const AuthProbe = messages.AuthProbe;
pub const AuthProbeReply = messages.AuthProbeReply;
pub const AuthSignature = messages.AuthSignature;
pub const AuthOk = messages.AuthOk;
pub const Rebuild = messages.Rebuild;
pub const Resume = messages.Resume;
pub const ErrorCode = messages.ErrorCode;
pub const SessionInfo = messages.SessionInfo;
pub const Kill = messages.Kill;
pub const Exec = messages.Exec;
pub const ClipboardOffer = messages.ClipboardOffer;
pub const ClipboardRequest = messages.ClipboardRequest;
pub const ClipboardData = messages.ClipboardData;
pub const ClipboardCopy = messages.ClipboardCopy;
pub const Connect = messages.Connect;
pub const Start = messages.Start;
pub const DumpReply = messages.DumpReply;
pub const internal_revision = messages.internal_revision;
pub const isLocaleName = messages.isLocaleName;

pub const Decoder = frame.Decoder;
pub const encode = frame.encode;
pub const encodedLen = frame.encodedLen;

test {
    _ = wire;
    _ = messages;
    _ = frame;
}
