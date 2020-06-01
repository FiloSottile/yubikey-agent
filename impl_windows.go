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
