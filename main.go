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
		fmt.Fprintf(os.Stderr, "\t\tGenerate a new SSH key on the attached YubiKey.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -add-key [-slot 9c|9d|9e] [-no-touch]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate a new SSH key in another slot on an already provisioned YubiKey.\n")
		fmt.Fprintf(os.Stderr, "\t\t-no-touch: key does not require touch to sign (less secure).\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -list-slots\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tList PIV slots (9a, 9c, 9d, 9e) and whether each has an SSH key.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -l PATH\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tRun the agent, listening on the UNIX socket at PATH.\n")
		fmt.Fprintf(os.Stderr, "\t\tSlot file PATH.slot can restrict to one slot; SIGHUP or -set-slot reloads it.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -set-slot 9a|9c|9d|9e|all [-l PATH]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tSwitch which slot the running agent exposes (writes PATH.slot, sends SIGHUP).\n")
		fmt.Fprintf(os.Stderr, "\t\tUse \"all\" to expose all slots again. Use -l PATH if not using SSH_AUTH_SOCK.\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	resetFlag := flag.Bool("really-delete-all-piv-keys", false, "setup: reset the PIV applet")
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	addKeyFlag := flag.Bool("add-key", false, "setup: generate a new SSH key in another slot on an already provisioned YubiKey")
	listSlotsFlag := flag.Bool("list-slots", false, "list PIV slots and whether each has an SSH key")
	setSlotFlag := flag.String("set-slot", "", "runtime: write slot to agent's .slot file and SIGHUP the agent to switch slot")
	slotFlag := flag.String("slot", "", "add-key: target slot (9c, 9d, or 9e); if empty, use first empty slot")
	noTouchFlag := flag.Bool("no-touch", false, "add-key: generate key without touch requirement (TouchPolicyNever)")
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
	} else if *addKeyFlag {
		log.SetFlags(0)
		yk := connectForSetup()
		runAddKey(yk, *slotFlag, *noTouchFlag)
	} else if *listSlotsFlag {
		log.SetFlags(0)
		yk := connectForSetup()
		runListSlots(yk)
	} else if *setSlotFlag != "" {
		log.SetFlags(0)
		runSetSlot(*setSlotFlag, *socketPath)
	} else {
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}
		runAgent(*socketPath)
	}
}

func parseSlotEnv(s string) (piv.Slot, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuthentication, nil
	default:
		return piv.Slot{}, fmt.Errorf("slot must be 9a, 9c, 9d, or 9e")
	}
}

func readSlotFile(slotFilePath string) ([]piv.Slot, error) {
	b, err := os.ReadFile(slotFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return sshSlots, nil // no file = all slots
		}
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "all" {
		return sshSlots, nil
	}
	slot, err := parseSlotEnv(s)
	if err != nil {
		return nil, err
	}
	return []piv.Slot{slot}, nil
}

func runSetSlot(slot, socketPath string) {
	if socketPath == "" {
		socketPath = os.Getenv("SSH_AUTH_SOCK")
	}
	if socketPath == "" {
		log.Fatalln("Cannot determine agent socket: set -l PATH or SSH_AUTH_SOCK")
	}
	slot = strings.TrimSpace(strings.ToLower(slot))
	if slot != "all" {
		if _, err := parseSlotEnv(slot); err != nil {
			log.Fatalln(err)
		}
	}
	slotFilePath := socketPath + ".slot"
	if err := os.WriteFile(slotFilePath, []byte(slot+"\n"), 0600); err != nil {
		log.Fatalln("Failed to write slot file:", err)
	}
	pidFilePath := socketPath + ".pid"
	pidBytes, err := os.ReadFile(pidFilePath)
	if err != nil {
		log.Fatalln("Failed to read agent PID (is the agent running?):", err)
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(pidBytes)), "%d", &pid); err != nil {
		log.Fatalln("Invalid PID file:", err)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		log.Fatalln("Failed to signal agent:", err)
	}
	if slot == "all" {
		fmt.Println("Switched to all slots")
	} else {
		fmt.Println("Switched to slot", slot)
	}
}

func runAgent(socketPath string) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	slotFilePath := socketPath + ".slot"
	pidFilePath := socketPath + ".pid"

	slots := sshSlots
	if s := os.Getenv("YUBIKEY_AGENT_SLOT"); s != "" {
		slot, err := parseSlotEnv(s)
		if err != nil {
			log.Fatalln("YUBIKEY_AGENT_SLOT:", err)
		}
		slots = []piv.Slot{slot}
		log.Println("YUBIKEY_AGENT_SLOT="+s+": exposing only PIV slot", s)
	} else {
		var err error
		slots, err = readSlotFile(slotFilePath)
		if err != nil {
			log.Println("Reading", slotFilePath+":", err, "(using all slots)")
		} else if len(slots) == 1 {
			log.Println("Slot file:", slotFilePath, "→ exposing only PIV slot", slots[0].String())
		}
	}

	a := &Agent{slots: slots}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			if newSlots, err := readSlotFile(slotFilePath); err == nil {
				a.SetSlots(newSlots)
				log.Println("Reloaded slot file → now exposing slot(s):", slotSliceString(newSlots))
			}
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
	if err := os.WriteFile(pidFilePath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		log.Println("Failed to write PID file:", err)
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

	// slots is the set of PIV slots this agent exposes (default all four). Can be
	// restricted to one slot via YUBIKEY_AGENT_SLOT for multiple-account setups.
	slots []piv.Slot

	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
}

// sshSlots are the PIV slots used for SSH keys (9a, 9c, 9d, 9e).
var sshSlots = []piv.Slot{
	piv.SlotAuthentication,
	piv.SlotSignature,
	piv.SlotKeyManagement,
	piv.SlotCardAuthentication,
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

func slotSliceString(slots []piv.Slot) string {
	if len(slots) == 0 {
		return "(none)"
	}
	if len(slots) == 1 {
		return slots[0].String()
	}
	var b strings.Builder
	for i, s := range slots {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(s.String())
	}
	return b.String()
}

func (a *Agent) SetSlots(slots []piv.Slot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(slots) > 0 {
		a.slots = slots
	}
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
			continue // skip empty slots or unsupported key types
		}
		keys = append(keys, &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: fmt.Sprintf("YubiKey #%d PIV Slot %s", a.serial, slot.String()),
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

func runListSlots(yk *piv.YubiKey) {
	fmt.Println("PIV slots on YubiKey:")
	fmt.Println("")
	for _, slot := range sshSlots {
		pk, err := getPublicKey(yk, slot)
		if err != nil {
			if errors.Is(err, piv.ErrNotFound) {
				fmt.Printf("  %s: (empty)\n", slot.String())
			} else {
				fmt.Printf("  %s: (error: %v)\n", slot.String(), err)
			}
			continue
		}
		fmt.Printf("  %s: ", slot.String())
		os.Stdout.Write(ssh.MarshalAuthorizedKey(pk))
	}
}

func slotForPublicKey(yk *piv.YubiKey, key ssh.PublicKey, slots []piv.Slot) (piv.Slot, error) {
	keyBlob := key.Marshal()
	for _, slot := range slots {
		pk, err := getPublicKey(yk, slot)
		if err != nil {
			continue
		}
		if bytes.Equal(pk.Marshal(), keyBlob) {
			return slot, nil
		}
	}
	return piv.Slot{}, errors.New("no slot found for public key")
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
			continue
		}
		priv, err := a.yk.PrivateKey(
			slot,
			pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
			piv.KeyAuth{PINPrompt: a.getPIN},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare private key for slot %s: %w", slot.String(), err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare signer: %w", err)
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

	slot, err := slotForPublicKey(a.yk, key, a.slots)
	if err != nil {
		return nil, fmt.Errorf("no private keys match the requested public key")
	}

	pk, err := getPublicKey(a.yk, slot)
	if err != nil {
		return nil, err
	}
	priv, err := a.yk.PrivateKey(
		slot,
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
