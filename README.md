# yubikey-agent

yubikey-agent is a seamless ssh-agent for YubiKeys.

## Installation

### macOS

```
brew tap filippo.io/yubikey-agent https://filippo.io/yubikey-agent
brew install yubikey-agent
brew services start yubikey-agent

yubikey-agent -setup
```

Then add the following line to your `~/.zshrc` and restart the shell.

```
export SSH_AUTH_SOCK="/usr/local/var/run/yubikey-agent.sock"
```
