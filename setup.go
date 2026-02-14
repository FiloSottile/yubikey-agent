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

func isInitialized(yk *piv.YubiKey) bool {
	if err := yk.SetManagementKey(piv.DefaultManagementKey, piv.DefaultManagementKey); err != nil {
		return true
	}
	// This could affect tries counter
	if _, err := yk.Metadata(piv.DefaultPIN); err != nil {
		return true
	}
	return false
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

func readPass(name string) string {
	for {
		fmt.Printf("Enter new %s: ", name)
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\n")
		if err != nil {
			log.Fatalf("Failed to read %s: %v\n", name, err)
		}
		if len(pass) < 6 || len(pass) > 8 {
			log.Fatalf("The %s needs to be 6-8 characters.\n", name)
		}
		fmt.Printf("Repeat %s: ", name)
		repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\n")
		if err != nil {
			log.Fatalf("Failed to read %s: %v\n", name, err)
		} else if bytes.Equal(repeat, pass) {
			return string(pass)
		}
		log.Printf("%ss don't match!\n", name)
	}
}

// parseSlot converts a string to piv.Slot
func parseSlot(slot string) (piv.Slot, error) {
	slot = strings.TrimPrefix(slot, "0x")
	switch slot {
	case "", "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuthentication, nil
	default:
		// Try parsing as retired key management slot (0x82-0x95)
		var key uint32
		if _, err := fmt.Sscanf(slot, "%x", &key); err != nil {
			return piv.Slot{}, fmt.Errorf("invalid slot identifier: %s", slot)
		}
		slot_, ok := piv.RetiredKeyManagementSlot(key)
		if !ok {
			return piv.Slot{}, fmt.Errorf("invalid retired key management slot: %s", slot)
		}
		return slot_, nil
	}
}

// parseTouchPolicy converts a string to piv.TouchPolicy
func parseTouchPolicy(policy string) (piv.TouchPolicy, error) {
	switch policy {
	case "", "always":
		return piv.TouchPolicyAlways, nil
	case "never":
		return piv.TouchPolicyNever, nil
	case "cached":
		return piv.TouchPolicyCached, nil
	default:
		return 0, fmt.Errorf("invalid touch policy: %s (must be 'never', 'always', or 'cached')", policy)
	}
}

// parseAlgorithm converts a string to piv.Algorithm
func parseAlgorithm(algo string) (piv.Algorithm, error) {
	switch algo {
	case "", "ec256":
		return piv.AlgorithmEC256, nil
	case "ec384":
		return piv.AlgorithmEC384, nil
	case "ed25519":
		return piv.AlgorithmEd25519, nil
	case "rsa2048":
		return piv.AlgorithmRSA2048, nil
	default:
		return 0, fmt.Errorf("invalid algorithm: %s (must be 'ec256', 'ec384', 'ed25519' or 'rsa2048')", algo)
	}
}

func runSetup(yk *piv.YubiKey) [24]byte {
	if isInitialized(yk) {
		log.Println("‼️  This YubiKey looks already setup")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}

	fmt.Println("🔐 The PIN/PUK are up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	pin := readPass("PIN")
	puk := readPass("PUK")

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
	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		log.Println("‼️  The default PIN did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
		log.Println("‼️  The default PUK did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	return key
}

func getManagementKey(yk *piv.YubiKey) [24]byte {
	if !isInitialized(yk) {
		log.Fatalln("This YubiKey doesn't look initialized. Run with --setup first.")
	}
	fmt.Printf("Enter PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}

	metadata, err := yk.Metadata(string(pin))
	if err != nil {
		log.Fatalln("Failed to read management key from YubiKey:", err)
	}
	managementKey := metadata.ManagementKey
	return *managementKey
}

func runAddKey(yk *piv.YubiKey, managementKey [24]byte, slot string, algo string, touchPolicy string) {
	slot_, err := parseSlot(slot)
	if err != nil {
		log.Fatalln("Failed to parse slot:", err)
	}

	algo_, err := parseAlgorithm(algo)
	if err != nil {
		log.Fatalln("Failed to parse algorithm:", err)
	}

	touchPolicy_, err := parseTouchPolicy(touchPolicy)
	if err != nil {
		log.Fatalln("Failed to parse touch policy:", err)
	}

	log.Println("Generating key on the YubiKey...")
	pub, err := yk.GenerateKey(managementKey, slot_, piv.Key{
		Algorithm:   algo_,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: touchPolicy_,
	})
	if err != nil {
		log.Fatalln("Failed to generate key:", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln("Failed to generate parent key:", err)
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
		log.Fatalln("Failed to generate certificate:", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalln("Failed to parse certificate:", err)
	}
	if err := yk.SetCertificate(managementKey, slot_, cert); err != nil {
		log.Fatalln("Failed to store certificate:", err)
	}

	sshKey, err := ssh.NewPublicKey(pub)
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

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
