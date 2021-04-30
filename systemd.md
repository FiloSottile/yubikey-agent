# Manual Linux setup with systemd

Note: this is usually only necessary in case your distribution doesn't already
provide a yubikey-agent as a package.

Refer to [the README](README.md) for a list of distributions providing packages.

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

Then, create a systemd user service at `~/.config/systemd/user/yubikey-agent.service`
with the contents of [yubikey-agent.service](contrib/systemd/user/yubikey-agent.service).

Depending on your distribution (`systemd <=239` or no user namespace support),
you might need to edit the `ExecStart=` line and some of the sandboxing
options.

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
