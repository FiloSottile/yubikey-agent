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

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of yubikey-agent:\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tSetup YubiKey and generate a new SSH key on it.\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -add-key\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate additional SSH key on the attached YubiKey.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -l PATH\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tRun the agent, listening on the UNIX socket at PATH.\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	slotsList := flag.String("slots", "auto", "agent: comma-separated list of PIV slots to use in SSH keys (9a, 9c, 9d, 9e, 82-95) or `auto` for auto-detect")
	resetFlag := flag.Bool("really-delete-all-piv-keys", false, "setup: reset the PIV applet")
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	addKeyFlag := flag.Bool("add-key", false, "setup: generate a new SSH key on the YubiKey")
	keySlot := flag.String("slot", "", "setup: PIV slot for the new SSH key (9a, 9c, 9d, 9e, 82-95)")
	keyAlgo := flag.String("algo", "", "setup: algorithm for the new SSH key (ec256(default), ec384, ed25519, rsa2048)")
	keyTouchPolicy := flag.String("touch-policy", "cached", "setup: touch policy for the new SSH key (cached, always(default) or never)")
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
		key := runSetup(yk)
		runAddKey(yk, key, *keySlot, *keyAlgo, *keyTouchPolicy)
	} else if *addKeyFlag {
		log.SetFlags(0)
		yk := connectForSetup()
		key := getManagementKey(yk)
		runAddKey(yk, key, *keySlot, *keyAlgo, *keyTouchPolicy)
	} else {
		// Agent mode
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}
		runAgent(*socketPath, *slotsList)
	}
}

func parseSlots(slotsList string) []piv.Slot {
	var slots []piv.Slot

	if slotsList == "auto" {
		slotsStr := []string{"9a", "9c", "9d", "9e"}
		for i := 0x82; i <= 0x95; i++ {
			slotsStr = append(slotsStr, fmt.Sprintf("%x", i))
		}
		yk, err := openYK()
		if err != nil {
			log.Fatalln("Failed to connect to the YubiKey:", err)
		}
		defer yk.Close()
		for i := range slotsStr {
			slot, err := parseSlot(slotsStr[i])
			if err != nil {
				log.Fatalf("Invalid slot `%s` in auto-detected slots: %s\n", slotsStr[i], err)
			}
			_, err = yk.Certificate(slot)
			if err == nil {
				slots = append(slots, slot)
			}
		}
		return slots
	}

	for _, slotStr := range strings.Split(slotsList, ",") {
		slot, err := parseSlot(slotStr)
		if err != nil {
			log.Fatalf("Invalid slot `%s` in slots: %s\n", slotStr, err)
		}
		slots = append(slots, slot)
	}

	return slots
}

func runAgent(socketPath string, slotsList string) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	slots := parseSlots(slotsList)

	a := &Agent{slots: slots}

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

	slots []piv.Slot
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

func (a *Agent) maybeReleaseYK() {
	// On macOS, YubiKey 5s persist the PIN cache even across sessions (and even
	// processes), so we can release the lock on the key, to let other
	// applications like age-plugin-yubikey use it.
	if runtime.GOOS != "darwin" || a.yk.Version().Major < 5 {
		return
	}
	if err := a.yk.Close(); err != nil {
		log.Println("Failed to automatically release YubiKey lock:", err)
	}
	a.yk = nil
}

func (a *Agent) connectToYK() (*piv.YubiKey, error) {
	yk, err := openYK()
	if err != nil {
		return nil, err
	}
	// Cache the serial number locally because requesting it on older firmwares
	// requires switching application, which drops the PIN cache.
	a.serial, _ = yk.Serial()
	return yk, nil
}

func openYK() (yk *piv.YubiKey, err error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys. For now, select the first one that opens
	// successfully, to skip any internal unused smart card readers.
	for _, card := range cards {
		yk, err = piv.Open(card)
		if err == nil {
			return
		}
	}
	return
}

func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.yk != nil {
		log.Println("Received HUP, dropping YubiKey transaction...")
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
	defer a.maybeReleaseYK()

	var keys []*agent.Key
	for _, slot := range a.slots {
		pk, err := getPublicKey(a.yk, slot)
		if err != nil {
			// If a slot doesn't have a key, skip it silently
			if errors.Is(err, piv.ErrNotFound) {
				continue
			}
			log.Printf("Warning: could not get public key for slot %s: %v", slot, err)
			continue
		}
		keys = append(keys, &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: fmt.Sprintf("YubiKey #%d PIV Slot %s", a.serial, slot),
		})
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
	defer a.maybeReleaseYK()

	return a.signers()
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, slot := range a.slots {
		pk, err := getPublicKey(a.yk, slot)
		if err != nil {
			// If a slot doesn't have a key, skip it silently
			if errors.Is(err, piv.ErrNotFound) {
				continue
			}
			log.Printf("Warning: could not get public key for slot %s: %v", slot, err)
			continue
		}
		priv, err := a.yk.PrivateKey(
			slot,
			pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
			piv.KeyAuth{PINPrompt: a.getPIN},
		)
		if err != nil {
			log.Printf("Warning: failed to prepare private key for slot %s: %v", slot, err)
			continue
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			log.Printf("Warning: failed to prepare signer for slot %s: %v", slot, err)
			continue
		}
		signers = append(signers, s)
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
	defer a.maybeReleaseYK()

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
	return a.Close()
}
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}
