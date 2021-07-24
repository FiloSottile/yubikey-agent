// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build !darwin
// +build !darwin

package main

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/gopasspw/pinentry"
)

func init() {
	pinentry.Unescape = true
	if _, err := exec.LookPath(pinentry.GetBinary()); err != nil {
		log.Fatalf("PIN entry program %q not found!", pinentry.GetBinary())
	}
}

func getPIN(serial uint32, retries int) (string, error) {
	p, err := pinentry.New()
	if err != nil {
		return "", fmt.Errorf("failed to start %q: %w", pinentry.GetBinary(), err)
	}
	defer p.Close()
	p.Set("title", "yubikey-agent PIN Prompt")
	p.Set("desc", fmt.Sprintf("YubiKey serial number: %d (%d tries remaining)", serial, retries))
	p.Set("prompt", "Please enter your PIN:")

	// Enable opt-in external PIN caching (in the OS keychain).
	// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
	p.Option("allow-external-password-cache")
	p.Set("KEYINFO", fmt.Sprintf("--yubikey-id-%d", serial))

	pin, err := p.GetPin()
	return string(pin), err
}
