# Copyright 2020 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

class YubikeyAgent < Formula
  desc "Seamless ssh-agent for YubiKeys"
  homepage "https://filippo.io/yubikey-agent"
  url "https://github.com/FiloSottile/yubikey-agent/archive/v0.1.1.zip"
  sha256 "cffd7db3ecc38cbfaa4cabbca9b2ef3a694db1a8ea47afb63f47840fb0b5861b"

  depends_on "pinentry-mac"
  depends_on "go" => :build

  def install
    ENV["GOPATH"] = HOMEBREW_CACHE/"go_cache"
    mkdir bin
    system "go", "build", "-trimpath", "-ldflags", "-X main.Version=v#{version}",
        "-o", bin, "filippo.io/yubikey-agent"
    prefix.install_metafiles
  end

  def post_install
    (var/"run").mkpath
    (var/"log").mkpath
  end

  def plist
    <<~EOS
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>Label</key>
        <string>#{plist_name}</string>
        <key>EnvironmentVariables</key>
        <dict>
          <key>PATH</key>
          <string>/usr/bin:/bin:/usr/sbin:/sbin:#{Formula["pinentry-mac"].opt_bin}</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
          <string>#{opt_bin}/yubikey-agent</string>
          <string>-l</string>
          <string>#{var}/run/yubikey-agent.sock</string>
        </array>
        <key>RunAtLoad</key><true/>
        <key>KeepAlive</key><true/>
        <key>ProcessType</key>
        <string>Background</string>
        <key>StandardErrorPath</key>
        <string>#{var}/log/yubikey-agent.log</string>
        <key>StandardOutPath</key>
        <string>#{var}/log/yubikey-agent.log</string>
      </dict>
      </plist>
    EOS
  end

  def caveats
    <<~EOS
      To set up a new YubiKey, run this command:
        yubikey-agent -setup

      To use this SSH agent, set this variable in your ~/.zshrc and/or ~/.bashrc:
        export SSH_AUTH_SOCK="#{var}/run/yubikey-agent.sock"
    EOS
  end
end
