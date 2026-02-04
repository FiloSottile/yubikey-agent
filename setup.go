// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func init() {
	if Version != "" {
		return
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildInfo.Main.Version
		return
	}
	Version = "(unknown version)"
}

func connectForSetup() *piv.YubiKey {
	yk, err := openYK()
	if err != nil {
		log.Fatalln("Failed to connect to the YubiKey:", err)
	}
	return yk
}

// addKeySlots are the PIV slots that -add-key can use (9c, 9d, 9e). Slot 9a is for initial setup only.
var addKeySlots = []piv.Slot{
	piv.SlotSignature,
	piv.SlotKeyManagement,
	piv.SlotCardAuthentication,
}

// generateKeyInSlot generates an ECDSA P-384 key and certificate in the given slot and stores the cert on the YubiKey.
func generateKeyInSlot(yk *piv.YubiKey, key [24]byte, slot piv.Slot) (interface{}, error) {
	pub, err := yk.GenerateKey(key, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC384,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyAlways,
	})
	if err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"yubikey-agent"},
			OrganizationalUnit: []string{Version},
		},
		PublicKey: priv.Public(),
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH key",
		},
		NotAfter:     time.Now().AddDate(42, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: randomSerialNumber(),
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	if err := yk.SetCertificate(key, slot, cert); err != nil {
		return nil, err
	}
	return pub, nil
}

func runReset(yk *piv.YubiKey) {
	fmt.Print(`Do you want to reset the PIV applet? This will delete all PIV keys. Type "delete": `)
	var res string
	if _, err := fmt.Scanln(&res); err != nil {
		log.Fatalln("Failed to read response:", err)
	}
	if res != "delete" {
		log.Fatalln("Aborting...")
	}

	fmt.Println("Resetting YubiKey PIV applet...")
	if err := yk.Reset(); err != nil {
		log.Fatalln("Failed to reset YubiKey:", err)
	}
}

func runSetup(yk *piv.YubiKey) {
	if _, err := yk.Certificate(piv.SlotAuthentication); err == nil {
		log.Println("‼️  This YubiKey looks already setup")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	} else if !errors.Is(err, piv.ErrNotFound) {
		log.Fatalln("Failed to access authentication slot:", err)
	}

	fmt.Println("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	fmt.Print("Choose a new PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) < 6 || len(pin) > 8 {
		log.Fatalln("The PIN needs to be 6-8 characters.")
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	} else if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}

	fmt.Println("")
	fmt.Println("🧪 Reticulating splines...")

	var key [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatal(err)
	}
	if err := yk.SetManagementKey(piv.DefaultManagementKey, key); err != nil {
		log.Println("‼️  The default Management Key did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetMetadata(key, &piv.Metadata{
		ManagementKey: &key,
	}); err != nil {
		log.Fatalln("Failed to store the Management Key on the device:", err)
	}
	if err := yk.SetPIN(piv.DefaultPIN, string(pin)); err != nil {
		log.Println("‼️  The default PIN did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetPUK(piv.DefaultPUK, string(pin)); err != nil {
		log.Println("‼️  The default PUK did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}

	pub, err := generateKeyInSlot(yk, key, piv.SlotAuthentication)
	if err != nil {
		log.Fatalln("Failed to generate key:", err)
	}

	sshKey, err := ssh.NewPublicKey(pub.(*ecdsa.PublicKey))
	if err != nil {
		log.Fatalln("Failed to generate public key:", err)
	}

	fmt.Println("")
	fmt.Println("✅ Done! This YubiKey is secured and ready to go.")
	fmt.Println("🤏 When the YubiKey blinks, touch it to authorize the login.")
	fmt.Println("")
	fmt.Println("🔑 Here's your new shiny SSH public key:")
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	fmt.Println("")
	fmt.Println("Next steps: ensure yubikey-agent is running via launchd/systemd/...,")
	fmt.Println(`set the SSH_AUTH_SOCK environment variable, and test with "ssh-add -L"`)
	fmt.Println("")
	fmt.Println("💭 Remember: everything breaks, have a backup plan for when this YubiKey does.")
}

func runAddKey(yk *piv.YubiKey, slotFlag string) {
	if _, err := yk.Certificate(piv.SlotAuthentication); errors.Is(err, piv.ErrNotFound) {
		log.Fatalln("This YubiKey is not yet set up. Run yubikey-agent -setup first.")
	} else if err != nil {
		log.Fatalln("Failed to access authentication slot:", err)
	}

	fmt.Print("Enter current PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}

	metadata, err := yk.Metadata(string(pin))
	if err != nil {
		log.Fatalln("Failed to get metadata (wrong PIN?):", err)
	}
	if metadata == nil || metadata.ManagementKey == nil {
		log.Fatalln("No management key found on device. This YubiKey may not have been set up with yubikey-agent -setup.")
	}
	key := *metadata.ManagementKey

	var slot piv.Slot
	if slotFlag != "" {
		slotFlag = strings.ToLower(strings.TrimSpace(slotFlag))
		switch slotFlag {
		case "9c":
			slot = piv.SlotSignature
		case "9d":
			slot = piv.SlotKeyManagement
		case "9e":
			slot = piv.SlotCardAuthentication
		default:
			log.Fatalln("Invalid -slot. Use 9c, 9d, or 9e.")
		}
		if _, err := yk.Certificate(slot); err == nil {
			fmt.Printf("Slot %s already has a key. Overwrite? (y/N): ", slotFlag)
			var confirm string
			if _, err := fmt.Scanln(&confirm); err != nil {
				log.Fatalln("Aborting...")
			}
			if !strings.EqualFold(strings.TrimSpace(confirm), "y") {
				log.Fatalln("Aborting...")
			}
		}
	} else {
		for _, s := range addKeySlots {
			if _, err := yk.Certificate(s); errors.Is(err, piv.ErrNotFound) {
				slot = s
				break
			}
		}
		if slot.Key == 0 && slot.Object == 0 {
			log.Fatalln("All add-key slots (9c, 9d, 9e) already have keys. Use -slot 9c|9d|9e to overwrite one.")
		}
	}

	fmt.Println("")
	fmt.Println("Generating key in slot", slot.String(), "...")

	pub, err := generateKeyInSlot(yk, key, slot)
	if err != nil {
		log.Fatalln("Failed to generate key:", err)
	}

	sshKey, err := ssh.NewPublicKey(pub.(*ecdsa.PublicKey))
	if err != nil {
		log.Fatalln("Failed to generate public key:", err)
	}

	fmt.Println("")
	fmt.Println("Done! New SSH public key for slot", slot.String()+":")
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	fmt.Println("")
	fmt.Println("Use ssh-add -L to see all keys.")
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
