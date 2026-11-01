# tx

tx is a remote terminal. The `tx` client connects to `txd` on another machine
over QUIC and attaches to a session there. A session is your shell on a pty, in
a process of its own on the server. It keeps running when the client detaches
or the connection drops. After a network change or sleep, tx reconnects and
resumes the session, and a session can be reattached later from another
machine.

tx takes ssh's command line and reads `~/.ssh/config`. It logs in with the keys
in your SSH agent or in `~/.ssh/id_ed25519`, which txd checks against your
`authorized_keys`. git and rsync can run tx as their ssh.

txd keeps each session's terminal state with libghostty-vt. A program's output
reaches your terminal as the program wrote it. On reattach, txd writes the
session's screen and scrollback into your terminal.

tx and txd run on Linux and macOS.

## Install

```sh
curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh
```

This puts `tx` and `txd` in `~/.local/bin`. On the server, `--txd` also runs
`txd --install`, which starts txd as a service:

```sh
curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh -s -- --txd
```

tx prints this command when txd doesn't answer. install.sh checks the download
against the release's SHA256SUMS. `TX_INSTALL_DIR` sets the directory, and
`TX_VERSION` picks a release, such as `0.0.0-nightly.20261031`. With `--txd`, a
txd service that was running is restarted on the new binary.

Releases are nightly builds of main, for Linux and macOS on x86_64 and aarch64.
The Linux binaries are static and need no libc on the host.

### Nix

The flake's default package has tx and txd, and `overlays.default` adds it as
`pkgs.tx`. The home-manager module runs txd as a systemd user service on Linux
or a launchd agent on macOS, and adds the package to `home.packages`.

```nix
# flake.nix
inputs.tx.url = "github:seatedro/tx";

# a home-manager module
{ inputs, ... }:
{
  imports = [ inputs.tx.homeModules.default ];
  services.txd.enable = true;
  services.txd.listen = "tailnet"; # optional, see The server
}
```

The module leaves lingering off. Without lingering, systemd stops user services
when your last login ends. `loginctl enable-linger` turns it on.

## Use

```sh
tx host               # attach to the detached session, or start one
tx --new host         # start another session
tx --list host        # list the sessions
tx --attach 3 host    # attach to session 3
tx --kill 3 host      # end session 3
tx host make test     # run a command without a terminal
tx -t host htop       # run a command in a new session, on a terminal
```

The destination is `[USER@]HOST` or `ssh://[USER@]HOST[:PORT]`.

`tx host` attaches to the session that no client is attached to. When there is
none it starts one, and when several are detached it lists them and asks for
`--attach` or `--new`. `--attach` takes the session from a client attached to
it. A session runs your login shell in your home directory. It lasts until the
shell exits or `--kill` ends it, with SIGHUP, and SIGKILL a second later if the
shell still runs.

`~.` at the start of a line detaches, and tx prints the command that reattaches.
`~~` sends a `~`. `-e` sets another escape character, and `-e none` turns it
off.

While tx is attached, a connection that hears nothing from txd for 6 seconds is
closed, and tx reconnects and resumes the session. It keeps trying until the
session resumes or you detach. After 3 seconds it shows a notice on the bottom
line. Input typed in the meantime is sent once the session resumes.

A command without `-t` runs as `$SHELL -c COMMAND`, with its stdin, stdout and
stderr carried over the connection, as ssh runs a command without a pty. tx
doesn't reconnect to it. tx exits with the command's status, or 255 when tx
fails. git and rsync can run tx as their ssh:

```sh
GIT_SSH_COMMAND=tx git clone host:repo
rsync -a -e tx dir/ host:dir/
```

A command with `-t` runs in a session of its own. It gets SIGHUP when you
detach, or 5 minutes after the connection is lost unless a client has attached
again by then.

The ssh options tx acts on are `-p` (txd's port), `-l`, `-t`, `-T`, `-4`, `-6`,
`-i`, `-F`, `-e`, `-n`, `-G`, `-V`, and `-o` with Port, User, IdentityFile and
RequestTTY. tx refuses the options of features it lacks, among them port
forwarding (`-L`, `-R`, `-D`), `-J`, `-W`, `-N` and subsystems (`-s`, which
sftp uses). It warns about `-A`, `-X`, `-Y` and `-I` and connects without them.
Other ssh options have no effect. `tx -G` prints the settings tx resolved, as
`ssh -G` does.

## Logging in

tx offers the SSH agent's Ed25519 and RSA keys, then the key files that `-i` or
IdentityFile name, `~/.ssh/id_ed25519` by default. A key file must hold an
Ed25519 key in OpenSSH's format. tx asks for the passphrase of a key file that
has one.

txd accepts the keys in `~/.config/tx/authorized_keys`, or in
`~/.ssh/authorized_keys` when the first file doesn't exist. It refuses a key
whose line has options, such as `from=` or `restrict`.

txd serves the account it runs as. A login that names no user logs in to that
account. A user given on the command line or by a User line must be that
account.

### Host keys

txd has an Ed25519 host key of its own. tx keeps the host keys it trusts in
`~/.config/tx/known_hosts`, in OpenSSH's format, under the host name it
connects to, or `[host]:port` on a port other than 8739. For a host that file
doesn't list, tx fetches txd's key and trusts it when

- `~/.ssh/known_hosts` lists that key for the host,
- `tailscale status` shows that the address that answered is this machine or
  an untagged node of your Tailscale user, or
- you answer yes to ssh's prompt.

tx then adds the key to `~/.config/tx/known_hosts`. When a host presents a key
other than the one tx trusts for it, tx refuses it and names the file to edit.

`txd --print-host-key` prints txd's key as `ssh-ed25519 KEY`. A line of
`HOST ssh-ed25519 KEY` in `~/.config/tx/known_hosts` trusts it ahead of the
first connection, for example where tx has no terminal to ask on.

## Configuration

tx reads `~/.config/tx/config` (`$XDG_CONFIG_HOME/tx/config`), then
`~/.ssh/config` or the file `-F` names. Both are in ssh_config's syntax. The
command line comes first, and as in ssh, the first value found for a setting
wins. The keywords tx reads are Host, Match, Include, HostName, User, Port,
IdentityFile, IdentitiesOnly, IdentityAgent and ProxyJump. It ignores the
others.

Port is txd's port, 8739 by default. tx takes it from the command line or from
its own config, since Port in `~/.ssh/config` is sshd's.

```
# ~/.config/tx/config
Host box
    Port 9000
```

Match takes `all`, `host`, `originalhost`, `user`, `localuser`, `exec`, `final`
and `canonical`. A Match block with another criterion doesn't apply, and tx
warns about it. tx warns about ProxyJump and connects directly. As ssh does, tx
refuses a config file, other than the one `-F` names, that isn't yours or
root's or that group or others can write.

## The server

txd runs as your user and listens on UDP port 8739. With no `--listen`, it
listens on Tailscale's addresses and loopback when Tailscale is up as txd
starts, and on every address otherwise. `--listen tailnet` or
`--listen tailnet:PORT` keeps it to the tailnet and loopback, and
`--listen ADDRESS:PORT`, such as `0.0.0.0:8739`, picks an address. On a
wildcard address, as by default, txd picks up addresses as interfaces come and
go.

`txd --install` runs txd as a systemd user service on Linux, and turns on
lingering so that it runs without a login. On macOS it loads a launchd agent.
When neither works, it starts txd in the background until the machine
restarts. Without `--listen`, the service gets the scope txd chose at install
time. `--install` prints the host key's fingerprint, which tx shows the first
time it connects. The log is in `journalctl --user -u txd` on Linux,
`~/Library/Logs/txd.log` on macOS, and `~/.local/state/tx/txd.log` for txd in
the background.

`txd --uninstall` stops txd and ends every session. It then removes the
service, the host key, txd's log and `~/.local/share/tx`. It turns lingering
off when `--install` turned it on.

Each session runs in a process of its own (`txd --session`) outside txd's
process tree. Sessions outlive txd, and a restarted or upgraded txd finds them.
The shell is `$SHELL`, or `/bin/sh`, started as a login shell in `$HOME`. Its
environment has HOME, USER, LOGNAME, SHELL, PATH, TZ, LANG and LC_* from txd's
environment, the client's TERM, COLORTERM and locale, and `TX_SESSION=1` and
`TX_SESSION_ID`. A command without `-t` gets the same environment without TERM,
COLORTERM and TX_SESSION_ID.

tx sends the local terminal's terminfo entry (`infocmp -x`), and txd compiles
it with `tic` under `~/.local/share/tx/terminfo` for the session's TERMINFO.
When tic can't compile it, the session's TERM is xterm-256color.

On Linux, txd runs a Wayland server with a clipboard and no display, and
sessions get its WAYLAND_DISPLAY. Programs that use the wlr or ext data-control
protocols, such as wl-copy and wl-paste, reach the pasteboard of a tx client on
macOS. Copies in the session go to the Mac's pasteboard. A program can read the
pasteboard within 5 seconds of a paste keystroke in the session (Ctrl-V, or the
start of a bracketed paste).

Files txd uses:

- `~/.local/state/tx/host_key`, the host key, or the file `--key` names
- `~/.config/tx/authorized_keys`, or else `~/.ssh/authorized_keys`
- `$XDG_RUNTIME_DIR/tx` on Linux (`~/.local/state/tx/run` without it), or `tx`
  in the per-user temporary directory on macOS, for the sessions' sockets and
  the Wayland socket

## Security

tx and txd speak QUIC (ngtcp2) with TLS 1.3 (picotls), and the cryptography
comes from Zig's standard library. txd authenticates with its Ed25519 host key
as a raw public key. The handshake offers X25519MLKEM768 and X25519 key
exchange. To log in, tx signs a transcript that holds a TLS exporter secret of
the connection and txd's host key, in SSHSIG format, and txd verifies it with
the key from authorized_keys. A resume skips that login. With an HMAC over the
new connection's exporter secret, tx proves that it holds the random key the
session sent it when it last attached.

## Build

tx builds with Zig 0.17.0, which `nix develop` provides.

```sh
zig build -Doptimize=ReleaseSafe   # zig-out/bin/tx and zig-out/bin/txd
zig build test
zig build release                  # zig-out/release/tx-VERSION-OS-ARCH.tar.gz
nix build                          # result/bin/tx and result/bin/txd
```

`zig build` fetches Ghostty (for libghostty-vt), libxev, ngtcp2 and picotls.
`zig build release` builds the four release platforms. Tests that run wl-copy
and wl-paste skip without wl-clipboard, and the end-to-end tests of git and
rsync skip without those programs.

## License

MIT. See [LICENSE](LICENSE).
