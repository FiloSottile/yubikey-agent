// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"log"

	"github.com/Microsoft/go-winio"
)

func runAgent(pipeAddress string) {
	a := &Agent{}

	l, err := winio.ListenPipe(pipeAddress, nil)
	if err != nil {
		log.Fatalln("Failed to listen on Windows pipe:", err)
	}

	serveConns(l, a)
}
