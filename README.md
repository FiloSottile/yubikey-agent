# yubikey-agent

yubikey-agent is a seamless ssh-agent for YubiKeys.

* **Easy to use.** A one-command setup, one environment variable, and it just runs in the background.
* **Indestructible.** Tolerates unplugging, sleep, and suspend. Never needs restarting.
* **Compatible.** Provides a public key that works with all services and servers.
* **Secure.** The key is generated on the YubiKey and can't be extracted. Every session requires the PIN, every login requires a touch. Setup takes care of PUK and management key.

Written in pure Go, it's based on [github.com/go-piv/piv-go](https://github.com/go-piv/piv-go) and [golang.org/x/crypto/ssh](https://golang.org/x/crypto/ssh).

![](https://user-images.githubusercontent.com/1225294/81489747-63a03b00-9247-11ea-923a-b7434bcf7fd1.png)

## Installation

### macOS

```
brew install yubikey-agent
brew services start yubikey-agent
yubikey-agent -setup # setup YubiKey and generate a new key on it
```

Then add the following line to your `~/.zshrc` and restart the shell.

```
export SSH_AUTH_SOCK="$(brew --prefix)/var/run/yubikey-agent.sock"
```

### Linux

#### Arch

On Arch, use [the `yubikey-agent` package](https://aur.archlinux.org/packages/yubikey-agent/) from the AUR.

```
git clone https://aur.archlinux.org/yubikey-agent.git
cd yubikey-agent && makepkg -si

systemctl daemon-reload --user
sudo systemctl enable --now pcscd.socket
systemctl --user enable --now yubikey-agent

export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/yubikey-agent/yubikey-agent.sock"
```

#### NixOS / nixpkgs

On NixOS unstable and 20.09 (unreleased at time of writing), you can
add this to your `/etc/nixos/configuration.nix`:

```
services.yubikey-agent.enable = true;
```

This installs `yubikey-agent` and sets up a systemd unit to start
yubikey-agent for you.

On other systems using nix, you can also install from nixpkgs:

```
nix-env -iA nixpkgs.yubikey-agent
```

This installs the software but does *not* install a systemd unit.  You
will have to set up service management manually (see below).

#### Other systemd-based Linux systems

On other systemd-based Linux systems, follow [the manual installation instructions](systemd.md).

Packaging contributions are very welcome.

### FreeBSD

Install the [`yubikey-agent` port](https://svnweb.freebsd.org/ports/head/security/yubikey-agent/).

### Windows

Windows support is currently WIP.

## Advanced topics

### Coexisting with other `ssh-agent`s

It's possible to configure `ssh-agent`s on a per-host basis.

For example to only use `yubikey-agent` when connecting to `example.com`, you'd add the following lines to `~/.ssh/config` instead of setting `SSH_AUTH_SOCK`.

```
Host example.com
    IdentityAgent /usr/local/var/run/yubikey-agent.sock
```

To use `yubikey-agent` for all hosts but one, you'd add the following lines instead. In both cases, you can keep using `ssh-add` to interact with the main `ssh-agent`.

```
Host example.com
    IdentityAgent $SSH_AUTH_SOCK

Host *
    IdentityAgent /usr/local/var/run/yubikey-agent.sock
```

### Conflicts with `gpg-agent` and Yubikey Manager

`yubikey-agent` takes a persistent transaction so the YubiKey will cache the PIN after first use. Unfortunately, this makes the YubiKey PIV and PGP applets unavailable to any other applications, like `gpg-agent` and Yubikey Manager. Our upstream [is investigating solutions to this annoyance](https://github.com/go-piv/piv-go/issues/47).

If you need `yubikey-agent` to release its lock on the YubiKey, send it a hangup signal or use `ssh-add`'s "delete all identities" flag. Likewise, you might have to kill `gpg-agent` after use for it to release its own lock.

```
ssh-add -D
```

This does not affect the FIDO2 functionality.

### Changing PIN and PUK

Use YubiKey Manager if you need to change the PIN and PUK.

```
killall -HUP yubikey-agent
ykman piv access change-pin
ykman piv access change-puk
```

### Unblocking the PIN with the PUK

If the wrong PIN is entered incorrectly three times in a row, YubiKey Manager can be used to unlock it with PUK.

```
ykman piv access unblock-pin
```

If the PUK is also entered incorrectly three times, the key is permanently irrecoverable. The YubiKey PIV applet can be reset with `yubikey-agent --setup --really-delete-all-piv-keys`.

### Manual setup and technical details

`yubikey-agent` only officially supports YubiKeys set up with `yubikey-agent -setup` and `yubikey-agent -add-key`.

In practice, any PIV token with an RSA or ECDSA P-256 key and certificate in the Authentication slot should work, with any PIN and touch policy. Simply skip the setup step and use `ssh-add -L` to view the public key.

`yubikey-agent -setup` generates a random Management Key and [stores it in PIN-protected metadata](https://pkg.go.dev/github.com/go-piv/piv-go/piv?tab=doc#YubiKey.SetMetadata).

### Using multiple slots

`yubikey-agent` supports using multiple PIV slots on your YubiKey, allowing you to store several SSH keys with different security policies.

#### Available slots

- **Standard slots**: `9a` (Authentication), `9c` (Signature), `9d` (Key Management), `9e` (Card Authentication)
- **Retired Key Management slots**: `82` through `95` (20 additional slots)

#### Setting up your YubiKey

**Initial setup** (fresh YubiKey):

```bash
yubikey-agent -setup
```

This will:
- Set up a new PIN and PUK (6-8 characters)
- Generate and store a management key
- Create an SSH key in the default slot (9a)

**Adding keys to additional slots:**

```bash
yubikey-agent -addkey -slot 9c
```

This will:
- Ask for your current PIN
- Retrieve the management key from the YubiKey
- Generate a new SSH key in the specified slot
- No changes to PIN/PUK

You can customize the security policies and algorithm for each slot:

```bash
yubikey-agent -setup -slot 9a -algo ec256 -touch-policy always
yubikey-agent -addkey -slot 9c -algo rsa2048 -touch-policy cached
```

**Key algorithms:**
- `ec256` (default): ECDSA P-256 curve
- `ec384`: ECDSA P-384 curve
- `ed25519`: Ed25519 curve
- `rsa2048`: RSA 2048-bit

**Touch policies:**
- `always` (default): Requires a physical touch for every operation
- `never`: No touch required
- `cached`: Touch is cached for 15 seconds

#### Using multiple keys in agent
`yubikey-agent` will automatically load all valid keys from the configured slots. You can list them with:

```bash
ssh-add -L
```
or
```bash
ykman piv info
```

If you (for some reason) want to use only a specific slots, you can pass them as a comma-separated list to the agent's `-slots` flag:
```bash
yubikey-agent -l /path/to/agent.socket -slots 9a,9c
```

### Alternatives

#### Native FIDO2

Recent versions of OpenSSH [support using FIDO2 tokens directly](https://buttondown.email/cryptography-dispatches/archive/cryptography-dispatches-openssh-82-just-works/). Since those are their own key type, they require server-side support, which has only recently reached Debian and [GitHub](https://www.yubico.com/blog/github-now-supports-ssh-security-keys/).

FIDO2 SSH keys by default don't require a PIN, and require a private key file, acting more like a second factor. `yubikey-agent` keys always require PINs and can be ported to a different machine simply by plugging in the YubiKey. (With recent enough tokens such as a YubiKey 5, a similar setup can be achieved by using the `verify-required` and `resident` options, after setting a FIDO2 PIN with YubiKey Manager: the private key file will still be required, but it can be regenerated from the YubiKey.)

#### `gpg-agent`

`gpg-agent` can act as an `ssh-agent`, and it can use keys stored on the PGP applet of a YubiKey.

This requires a finicky setup process dealing with PGP keys and the `gpg` UX, and seems to lose track of the YubiKey and require restarting all the time. Frankly, I've also had enough of PGP and GnuPG.

#### `ssh-agent` and PKCS#11

`ssh-agent` can load PKCS#11 applets to interact with PIV tokens directly. There are two third-party PKCS#11 providers for YubiKeys (OpenSC and ykcs11) and one that ships with macOS (`man 8 ssh-keychain`).

The UX of this solution is poor: it requires calling `ssh-add` to load the PKCS#11 module and to unlock it with the PIN (as the agent has no way of requesting input from the client during use, a limitation that `yubikey-agent` handles with `pinentry`), and needs manual reloading every time the YubiKey is unplugged or the machine goes to sleep.

The ssh-agent that ships with macOS (which is pretty cool, as it starts on demand and is preconfigured in the environment) also has restrictions on where the `.so` modules can be loaded from. It can see through symlinks, so a Homebrew-installed `/usr/local/lib/libykcs11.dylib` won't work, while a hard copy at `/usr/local/lib/libykcs11.copy.dylib` will.

`/usr/lib/ssh-keychain.dylib` works out of the box, but only with RSA keys. Key generation is undocumented.

#### Secretive and SeKey

[Secretive](https://github.com/maxgoedjen/secretive) and [SeKey](https://github.com/sekey/sekey) are similar projects that use the Secure Enclave to store the private key and Touch ID for authorization. The Secure Enclave has so far a worse security track record compared to YubiKeys.

#### `pivy-agent`

[`pivy-agent`](https://github.com/joyent/pivy#using-pivy-agent) is part of a suite of tools to work with PIV tokens. It's similar to `yubikey-agent`, and inspired its design.

The main difference is that it requires unlocking via `ssh-add -X` rather than using a graphical pinentry, and it caches the PIN in memory rather than relying on the device PIN policy. It's also written in C.

`yubikey-agent` also aims to provide an even smoother setup process.
