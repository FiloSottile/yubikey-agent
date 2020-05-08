// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/gopasspw/gopass/pkg/pinentry"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of yubikey-agent:\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate a new SSH key on the attached YubiKey.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -l PATH\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tRun the agent, listening on the UNIX socket at PATH.\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	resetFlag := flag.Bool("really-delete-all-piv-keys", false, "setup: reset the PIV applet")
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *setupFlag {
		yk := connectForSetup()
		if *resetFlag {
			runReset(yk)
		}
		runSetup(yk)
	} else {
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}
		runAgent(*socketPath)
	}
}

func runAgent(socketPath string) {
	if _, err := exec.LookPath(pinentry.GetBinary()); err != nil {
		log.Fatalf("PIN entry program %q not found!", pinentry.GetBinary())
	}

	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	a := &Agent{}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(c)
	}
}

type Agent struct {
	mu     sync.Mutex
	yk     *piv.YubiKey
	serial uint32
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func healthy(yk *piv.YubiKey) bool {
	// We can't use Serial because it locks the session on older firmwares, and
	// can't use Retries because it fails when the session is unlocked.
	_, err := yk.AttestationCertificate()
	return err == nil
}

func (a *Agent) ensureYK() error {
	if a.yk == nil || !healthy(a.yk) {
		if a.yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			a.yk.Close()
		} else {
			log.Println("Connecting to the YubiKey...")
		}
		yk, err := a.connectToYK()
		if err != nil {
			return err
		}
		a.yk = yk
	}
	return nil
}

func (a *Agent) connectToYK() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys.
	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, err
	}
	// Cache the serial number locally because requesting it on older firmwares
	// requires switching application, which drops the PIN cache.
	a.serial, _ = yk.Serial()
	return yk, nil
}

func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.yk != nil {
		log.Println("Received SIGHUP, dropping YubiKey transaction...")
		err := a.yk.Close()
		a.yk = nil
		return err
	}
	return nil
}

func (a *Agent) getPIN() (string, error) {
	p, err := pinentry.New()
	if err != nil {
		return "", fmt.Errorf("failed to start %q: %w", pinentry.GetBinary(), err)
	}
	defer p.Close()
	p.Set("title", "yubikey-agent PIN Prompt")
	var retries string
	if r, err := a.yk.Retries(); err == nil {
		retries = fmt.Sprintf(" (%d tries remaining)", r)
	}
	p.Set("desc", fmt.Sprintf("YubiKey serial number: %d"+retries, a.serial))
	p.Set("prompt", "Please enter your PIN:")
	pin, err := p.GetPin()
	return string(pin), err
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	pk, err := getPublicKey(a.yk, piv.SlotAuthentication)
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format:  pk.Type(),
		Blob:    pk.Marshal(),
		Comment: fmt.Sprintf("YubiKey #%d PIV Slot 9a", a.serial),
	}}, nil
}

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	return a.signers()
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	pk, err := getPublicKey(a.yk, piv.SlotAuthentication)
	if err != nil {
		return nil, err
	}
	priv, err := a.yk.PrivateKey(
		piv.SlotAuthentication,
		pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
		piv.KeyAuth{PINPrompt: a.getPIN},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare private key: %w", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	return []ssh.Signer{s}, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	signers, err := a.signers()
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		alg := ssh.SigAlgoRSA
		switch {
		case flags&agent.SignatureFlagRsaSha256 != 0:
			alg = ssh.SigAlgoRSASHA2256
		case flags&agent.SignatureFlagRsaSha512 != 0:
			alg = ssh.SigAlgoRSASHA2512
		}
		// TODO: maybe retry if the PIN is not correct?
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
	}
	return nil, fmt.Errorf("no private keys match the requested public key")
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) RemoveAll() error {
	return ErrOperationUnsupported
}
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}
