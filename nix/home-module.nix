# home-manager module that runs txd as a systemd user service on Linux and a
# launchd agent on macOS, with the settings `txd --install` writes
# (src/cli/install.zig). `self` is the tx flake, for the default package.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.txd;
  args = [
    (lib.getExe' cfg.package "txd")
  ]
  ++ lib.optionals (cfg.listen != null) [
    "--listen"
    cfg.listen
  ];
in
{
  options.services.txd = {
    enable = lib.mkEnableOption "txd, the server tx connects to, for this user";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "tx.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The tx package, which has txd. It goes in home.packages too.";
    };

    listen = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "tailnet";
      description = ''
        txd's `--listen`: `tailnet`, `tailnet:PORT`, or an address and port,
        such as `0.0.0.0:8739`. When null, txd listens on its tailnet
        addresses if Tailscale is up when it starts, and on every address
        if not, so on a machine with Tailscale, `tailnet` is safer: at boot,
        txd can start before Tailscale.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      { home.packages = [ cfg.package ]; }

      (lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
        systemd.user.services.txd = {
          Unit.Description = "tx sessions";
          Service = {
            ExecStart = lib.escapeShellArgs args;
            Restart = "on-failure";
            # Session processes share txd's cgroup and keep running when the
            # service stops.
            KillMode = "process";
          };
          Install.WantedBy = [ "default.target" ];
        };
      })

      (lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
        launchd.agents.txd = {
          enable = true;
          config = {
            ProgramArguments = args;
            RunAtLoad = true;
            KeepAlive.SuccessfulExit = false;
            ProcessType = "Interactive";
            AbandonProcessGroup = true;
            StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/txd.log";
          };
        };
      })
    ]
  );
}
