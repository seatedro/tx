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

pub const Decoder = frame.Decoder;
pub const encode = frame.encode;
pub const encodedLen = frame.encodedLen;

test {
    _ = wire;
    _ = messages;
    _ = frame;
}
