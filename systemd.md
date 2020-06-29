# Manual Linux setup with systemd

First, install Go and the [`piv-go` dependencies](https://github.com/go-piv/piv-go#installation), build `yubikey-agent` and place it in `$PATH`.

```text
$ git clone https://filippo.io/yubikey-agent && cd yubikey-agent
$ go build && sudo cp yubikey-agent /usr/local/bin/
```

Make sure you have a `pinentry` program that works for you (terminal-based or graphical) in `$PATH`.

Use `yubikey-agent -setup` to create a new key on the YubiKey.

```text
$ yubikey-agent -setup
```

Then, create a systemd user service at `~/.config/systemd/user/yubikey-agent.service`.

```systemd
[Unit]
Description=Seamless ssh-agent for YubiKeys
Documentation=https://filippo.io/yubikey-agent

[Service]
ExecStart=/usr/local/bin/yubikey-agent -l %t/yubikey-agent/yubikey-agent.sock
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=strict
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateUsers=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
NoNewPrivileges=yes
KeyringMode=private
UMask=0177
RuntimeDirectory=yubikey-agent

[Install]
WantedBy=default.target
```

Refresh systemd, make sure that the PC/SC daemon is available, and start the yubikey-agent.

```text
$ systemctl daemon-reload --user
$ sudo systemctl enable --now pcscd.socket
$ systemctl --user enable --now yubikey-agent
```

Finally, add the following line to your shell profile and restart it.

```
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/yubikey-agent/yubikey-agent.sock"
```
