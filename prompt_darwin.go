// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
)

var scriptTemplate = template.Must(template.New("script").Parse(`
var app = Application.currentApplication()
app.includeStandardAdditions = true
app.displayDialog(
	"YubiKey serial number: {{ .Serial }} " +
	"({{ .Tries }} tries remaining)\n\n" +
	{{ if .Forgot }}"The PIN stored in the Keychain was removed.\n\n" +{{ end }}
	"Please enter your PIN:", {
    defaultAnswer: "",
	withTitle: "yubikey-agent PIN prompt",
    buttons: ["Cancel", "Remember", "OK"],
    defaultButton: "OK",
	cancelButton: "Cancel",
    hiddenAnswer: true,
})`))

// keychainService is the service name of the generic Keychain items that hold
// PINs the user opted to remember, one per YubiKey serial number.
const keychainService = "yubikey-agent"

// defaultPINRetries is the PIV default. A stored PIN is only used while the
// YubiKey reports this many retries, so a stale one costs at most one attempt.
const defaultPINRetries = 3

// keychainUsed caches whether any PIN was ever stored, so that users who never
// opt in don't pay for a Keychain lookup on every prompt. It's checked once,
// and set when a PIN is stored. getPIN is only called with Agent.mu held.
var keychainChecked, keychainUsed bool

func haveStoredPINs() bool {
	if !keychainChecked {
		keychainChecked = true
		// Without -w this only matches attributes and doesn't read the secret.
		keychainUsed = exec.Command("security", "find-generic-password",
			"-s", keychainService).Run() == nil
	}
	return keychainUsed
}

func getPIN(serial uint32, retries int) (string, error) {
	account := strconv.FormatUint(uint64(serial), 10)

	forgot := false
	if !haveStoredPINs() {
		// Nothing to use or forget.
	} else if retries >= defaultPINRetries {
		if pin, ok := keychainPIN(account); ok {
			return pin, nil
		}
	} else if retries > 0 {
		// A PIN attempt failed since the last success. If we have a stored
		// PIN it may be the culprit, so don't use it again. (Zero can also
		// mean the retry counter couldn't be read, so leave it alone then.)
		forgot = forgetKeychainPIN(account)
	}

	script := new(bytes.Buffer)
	if err := scriptTemplate.Execute(script, map[string]interface{}{
		"Serial": serial, "Tries": retries, "Forgot": forgot,
	}); err != nil {
		return "", err
	}

	c := exec.Command("osascript", "-s", "se", "-l", "JavaScript")
	c.Stdin = script
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute osascript: %v", err)
	}
	var x struct {
		PIN    string `json:"textReturned"`
		Button string `json:"buttonReturned"`
	}
	if err := json.Unmarshal(out, &x); err != nil {
		return "", fmt.Errorf("failed to parse osascript output: %v", err)
	}
	if x.Button == "Remember" {
		storeKeychainPIN(account, x.PIN)
	}
	return x.PIN, nil
}

func keychainPIN(account string) (string, bool) {
	out, err := exec.Command("security", "find-generic-password",
		"-s", keychainService, "-a", account, "-w").Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(string(out), "\n"), true
}

func storeKeychainPIN(account, pin string) {
	// With -w as the last option, security reads the password (twice) from
	// stdin, keeping it out of the process arguments.
	c := exec.Command("security", "add-generic-password", "-U",
		"-s", keychainService, "-a", account,
		"-l", "yubikey-agent PIN for YubiKey #"+account, "-w")
	c.Stdin = strings.NewReader(pin + "\n" + pin + "\n")
	if out, err := c.CombinedOutput(); err != nil {
		log.Printf("Failed to store PIN in the Keychain: %v: %s", err, out)
		return
	}
	keychainChecked, keychainUsed = true, true
	log.Printf("Stored PIN for YubiKey #%s in the Keychain.", account)
}

func forgetKeychainPIN(account string) bool {
	err := exec.Command("security", "delete-generic-password",
		"-s", keychainService, "-a", account).Run()
	if err == nil {
		log.Printf("Removed stored PIN for YubiKey #%s from the Keychain.", account)
	}
	return err == nil
}
