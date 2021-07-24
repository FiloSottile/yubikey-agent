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
	"os/exec"
	"text/template"
)

var scriptTemplate = template.Must(template.New("script").Parse(`
var app = Application.currentApplication()
app.includeStandardAdditions = true
app.displayDialog(
	"YubiKey serial number: {{ .Serial }} " +
	"({{ .Tries }} tries remaining)\n\n" +
	"Please enter your PIN:", {
    defaultAnswer: "",
	withTitle: "yubikey-agent PIN prompt",
    buttons: ["Cancel", "OK"],
    defaultButton: "OK",
	cancelButton: "Cancel",
    hiddenAnswer: true,
})`))

func getPIN(serial uint32, retries int) (string, error) {
	script := new(bytes.Buffer)
	if err := scriptTemplate.Execute(script, map[string]interface{}{
		"Serial": serial, "Tries": retries,
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
		PIN string `json:"textReturned"`
	}
	if err := json.Unmarshal(out, &x); err != nil {
		return "", fmt.Errorf("failed to parse osascript output: %v", err)
	}
	return x.PIN, nil
}
