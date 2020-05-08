# systemd setup

Build `yubikey-agent`, place it in `$PATH`, and create a user to run the daemon.

```text
$ go install filippo.io/yubikey-agent
$ sudo cp $GOPATH/bin/yubikey-agent /usr/local/bin/
$ sudo useradd yubikey-agent
```

Now create `/etc/systemd/system/yubikey-agent.service` with the following contents:

```systemd
[Unit]
Description=Seamless ssh-agent for YubiKeys
Documentation=https://github.com/FiloSottile/yubikey-agent
After=network.target

[Service]
ExecStart=/usr/local/bin/yubikey-agent -l /var/run/yubikey-agent/yubikey-agent.sock
User=yubikey-agent
RuntimeDirectory=yubikey-agent
LimitNOFILE=1024
LimitNPROC=512
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Finally, reload the systemd daemon configurations and start the service:

```text
$ sudo systemctl daemon-reload 
$ sudo systemctl start yubikey-agent
$ sudo systemctl status yubikey-agent
● yubikey-agent.service - Seamless ssh-agent for YubiKeys
     Loaded: loaded (/etc/systemd/system/yubikey-agent.service; disabled; vendor preset: enabled)
     Active: active (running) since Fri 2020-05-08 17:00:55 EDT; 1s ago
       Docs: https://github.com/FiloSottile/yubikey-agent
   Main PID: 1963040 (yubikey-agent)
      Tasks: 7 (limit: 76980)
     Memory: 1.6M
     CGroup: /system.slice/yubikey-agent.service
             └─1963040 /usr/local/bin/yubikey-agent -l /var/run/yubikey-agent/yubikey-agent.sock

May 08 17:00:55 hostname systemd[1]: Started Seamless ssh-agent for YubiKeys.
```
