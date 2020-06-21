# Manual Linux setup with systemd

Build `yubikey-agent` and place it in `$PATH`.

```text
$ go install filippo.io/yubikey-agent
$ sudo cp $GOPATH/bin/yubikey-agent /usr/local/bin/
```

Now create a systemd user service `~/.config/systemd/user/yubikey-agent.service` with the following content:

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
WantedBy=multi-user.target
```

Then refresh systemd daemon configuration, make sure that PC/SC daemon is available and start the yubikey-agent:

```text
$ systemctl daemon-reload --user
$ sudo systemctl start pcscd.socket
$ systemctl --user start yubikey-agent
```

The path of the SSH auth sock is `${XDG_RUNTIME_DIR}/yubikey-agent/yubikey-agent.sock`.
