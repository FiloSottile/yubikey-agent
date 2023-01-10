# Manual Linux setup with systemd

Note: this is usually only necessary in case your distribution doesn't already
provide a yubikey-agent as a package.

Refer to [the README](README.md) for a list of distributions providing packages.

## Dependencies

First, [install Go](https://golang.org/doc/install) and all [dependencies for`piv-go`](https://github.com/go-piv/piv-go#installation).
Make sure you have a `pinentry` program that works for you, either in the terminal-based or graphical, in `$PATH`.

### Packages for Ubuntu 20.04

`piv-go` requires `libpcsclite-dev` to build and `yubikey-agent` needs `pcscd` to run.

```sh
sudo apt install -y pcscd libpcsclite-dev
```

### `pcscd.socket`

Make sure `pcsdc.socket` is active before using `yubikey-agent`.

```sh
$ systemctl is-active pcscd.socket
active
```

If `pcscd.socket` is not active, you need to start it manually:

```sh
sudo systemctl enable --now pcscd.socket
```

## Building

Build the `yubikey-agent` and place it somewhere on your `$PATH`, such as `/usr/local/bin/`.

```sh
git clone https://filippo.io/yubikey-agent
cd yubikey-agent
go build
sudo cp yubikey-agent /usr/local/bin/
```

## Creating your first key

After all dependencies are installed and `yubikey-agent` is built, you are ready to start.
Use `yubikey-agent -setup` to create a new key on your YubiKey.

```sh
yubikey-agent -setup
```

## systemd service

Now we will create a systemd user service for `~/.config/systemd/user/yubikey-agent.service`
with the contents of [yubikey-agent.service](contrib/systemd/user/yubikey-agent.service).

```sh
mkdir -p ~/.config/systemd/user/
cp contrib/systemd/user/yubikey-agent.service ~/.config/systemd/user/yubikey-agent.service
```

**NB:** _Depending on your distribution (`systemd <=239` or no user namespace support), you might need to edit the `ExecStart=` line and some of the sandboxing options._

Refresh the systemd daemon and start the `yubikey-agent` service.

```sh
systemctl daemon-reload --user
systemctl --user enable --now yubikey-agent
```

To integrate `yubikey-agent` with SSH, set `SSH_AUTH_SOCK` to `yubikey-agent`'s socket. 
Add the following to your shell profile and restart your shell.

```sh
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/yubikey-agent/yubikey-agent.sock"
```

### Fish shell

If you use Fish shell, then add the following to `~/.config/fish/config.fish`

```sh
set SSH_AUTH_SOCK "$XDG_RUNTIME_DIR/yubikey-agent/yubikey-agent.sock"
```