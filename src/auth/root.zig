//! Keys and logins: SSH key formats, SSHSIG, the agent client, private
//! key files, `authorized_keys` and `known_hosts`.
pub const ssh = @import("ssh.zig");
pub const sshsig = @import("sshsig.zig");
pub const login = @import("login.zig");
pub const resume_ = @import("resume.zig");
pub const agent = @import("agent.zig");
pub const authorized_keys = @import("authorized_keys.zig");
pub const known_hosts = @import("known_hosts.zig");
pub const private_key = @import("private_key.zig");

pub const Key = ssh.Key;
pub const Fingerprint = ssh.Fingerprint;
pub const Agent = agent.Agent;

test {
    _ = ssh;
    _ = sshsig;
    _ = login;
    _ = resume_;
    _ = agent;
    _ = authorized_keys;
    _ = known_hosts;
    _ = private_key;
}
