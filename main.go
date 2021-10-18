// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type slotConfig map[piv.Slot]piv.PINPolicy

var slotConfiguration = slotConfig{piv.SlotAuthentication: -1}

func (s *slotConfig) String() string {
	// FIXME: Provide a nicer string representation
	return fmt.Sprint(slotConfiguration)
}

func (s *slotConfig) Set(value string) error {
	slot := strings.Split(value, ",")
	if len(slot) > 0 {
		var pin_policy piv.PINPolicy
		if len(slot) > 1 {
			switch strings.ToLower(slot[1]) {
			case "once":
				pin_policy = piv.PINPolicyOnce
			case "never":
				pin_policy = piv.PINPolicyNever
			case "always":
				pin_policy = piv.PINPolicyAlways
			default:
				return fmt.Errorf("unknown pin caching policy: %s - valid values are: once, never & always", slot[1])
			}
		} else {
			pin_policy = -1
		}

		switch strings.ToLower(slot[0]) {
		case "authentication":
			slotConfiguration[piv.SlotAuthentication] = pin_policy
		case "signature":
			slotConfiguration[piv.SlotSignature] = pin_policy
		case "keymanagement":
			slotConfiguration[piv.SlotKeyManagement] = pin_policy
		case "cardauthentication":
			slotConfiguration[piv.SlotCardAuthentication] = pin_policy
		default:
			return fmt.Errorf("unknown card slot: %s - valid values are: Authentication, Signature, KeyManagement & CardAuthentication", slot[0])
		}
		return nil
	} else {
		return fmt.Errorf("got invalid slot configuration: %s", value)
	}
}

func main() {
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
	cardSerial := flag.Uint("serial", 0, "select a specific YubiKey by its serial number")
	flag.Var(&slotConfiguration, "slot", "specify which YubiKey slots to use and (optionally) their pin policy: e.g.: --slot Authentication,once --slot Signature,always --slot KeyManagement,once --slot CardAuthentication,never")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *setupFlag {
		log.SetFlags(0)
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
		runAgent(*socketPath, uint32(*cardSerial))
	}
}

func runAgent(socketPath string, cardSerial uint32) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	a := &Agent{
		serial: cardSerial,
	}
	defer a.Close()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
		log.Fatalln("Failed to create UNIX socket folder:", err)
	}
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

	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
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

	// Find a valid yubikey from all present smartcards
	for _, card := range cards {
		yk, err := piv.Open(card)
	if err != nil {
			log.Printf("failed to open card %s: %s\n", card, err)
		} else {
			serial, err := yk.Serial()
			if err != nil {
				log.Printf("failed to get serial for card %s: %s\n", card, err)
			} else {
				if a.serial != 0 {
					// We are looking for a specific serial
					if serial == a.serial {
						return yk, nil
	}
				} else {
					// We use the first valid card that we find

	// Cache the serial number locally because requesting it on older firmwares
	// requires switching application, which drops the PIN cache.
					a.serial = serial
	return yk, nil
}
			}
			yk.Close()
		}
	}

	return nil, fmt.Errorf("could not find a yubikey card to use")
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
	if a.touchNotification != nil && a.touchNotification.Stop() {
		defer a.touchNotification.Reset(5 * time.Second)
	}
	r, _ := a.yk.Retries()
	return getPIN(a.serial, r)
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	var keys []*agent.Key

	for slot, _ := range slotConfiguration {
		pk, err := getPublicKey(a.yk, slot)
		if err == nil {
			keys = append(keys, &agent.Key{
				Format:  pk.Type(),
				Blob:    pk.Marshal(),
				Comment: fmt.Sprintf("YubiKey #%d PIV Slot %s", a.serial, slot),
			})
		}
	}

	return keys, nil
}

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
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
	var signers []ssh.Signer
	signerErrors := map[piv.Slot]error{}

	for slot, pin_policy := range slotConfiguration {
		pk, err := getPublicKey(a.yk, slot)
		if err != nil {
			signerErrors[slot] = fmt.Errorf("failed to retrieve public key: %w", err)
			continue
		}

		priv, err := a.yk.PrivateKey(
			slot,
			pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
			piv.KeyAuth{PINPrompt: a.getPIN, PINPolicy: pin_policy},
		)
		if err != nil {
			signerErrors[slot] = fmt.Errorf("failed to prepare private key: %w", err)
			continue
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			signerErrors[slot] = fmt.Errorf("failed to prepare signer: %w", err)
			continue
		}
		signers = append(signers, s)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("failed to prepare a valid signer: %s", signerErrors)
	}

	return signers, nil
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

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a.touchNotification = time.NewTimer(5 * time.Second)
		go func() {
			select {
			case <-a.touchNotification.C:
			case <-ctx.Done():
				a.touchNotification.Stop()
				return
			}
			showNotification("Waiting for YubiKey touch...")
		}()

		alg := key.Type()
		switch {
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
			alg = ssh.SigAlgoRSASHA2256
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
			alg = ssh.SigAlgoRSASHA2512
		}
		// TODO: maybe retry if the PIN is not correct?
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
	}
	return nil, fmt.Errorf("no private keys match the requested public key")
}

func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	case "linux":
		exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
	}
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
