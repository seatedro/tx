# tx

A remote terminal on QUIC and libghostty-vt, meant to replace ssh and mosh.
Sessions run on the server, survive network changes and sleep, and can be
reattached from anywhere.

tx is early and changes often.

## Install

    curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh

This puts tx and txd in `~/.local/bin`. On a machine you connect to, add
`--txd` to also run txd as a user service. Run it again to upgrade.

    curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh -s -- --txd

Releases are nightly builds of main for Linux and macOS, on x86_64 and aarch64.

With Nix, the flake has a package and a home-manager module:

```nix
# inputs.tx.url = "github:seatedro/tx";
imports = [ inputs.tx.homeModules.default ];
services.txd = { enable = true; listen = "tailnet"; };
```

On Linux the service starts at boot only with lingering on
(`loginctl enable-linger`).

## Use

```sh
tx host               # attach to the detached session, or start one
tx --new host         # start another session
tx --list host        # list sessions
tx --attach 3 host    # attach to session 3
tx --kill 3 host      # end session 3
tx host make test     # run a command, as ssh does
tx -t host htop       # run a command on a terminal, in a new session
```

`~.` detaches. tx takes ssh's options and reads `~/.ssh/config`, so git and
rsync can use it: `GIT_SSH_COMMAND=tx git clone host:repo`, `rsync -e tx`.
Options for features tx lacks, such as `-L`, are refused.

`-p` is txd's port, 8739 by default. A `Port` line counts only in
`~/.config/tx/config`, which tx reads before `~/.ssh/config`, in the same
format.

## Logging in

tx logs in with the SSH agent's keys, then the Ed25519 key files `-i` or
IdentityFile name, `~/.ssh/id_ed25519` by default. txd accepts the keys in
`~/.config/tx/authorized_keys`, or else `~/.ssh/authorized_keys`, and logs you
in to the account it runs as.

The first time tx connects to a host, it asks whether to trust txd's key, as
ssh does, unless `~/.ssh/known_hosts` lists the key or Tailscale says the host
is one of your untagged nodes. Trusted keys go in `~/.config/tx/known_hosts`.

## Server

txd runs as your user on UDP port 8739. If Tailscale is up when it starts, it
listens only on tailnet addresses and loopback. `--listen` picks other
addresses.

`txd --install` runs txd as a systemd user service or a launchd agent.
`txd --uninstall` ends the sessions and removes the service and txd's files,
the host key included. Each session is a process of its own, so a restart or
upgrade of txd leaves sessions running.

On Linux, programs in a session share the clipboard of the Mac running tx,
through a Wayland server that only does the clipboard. They can read it only
within 5 seconds of a paste.

## Build

Needs Zig 0.17.0, or `nix develop`.

    zig build            # zig-out/bin/tx and zig-out/bin/txd
    zig build test
    zig build release    # release tarballs in zig-out/release
    nix build            # result/bin/tx and result/bin/txd

## License

MIT
