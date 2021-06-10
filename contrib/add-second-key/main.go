package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var Version = "devel"

func connectForSetup() *piv.YubiKey {
	cards, err := piv.Cards()
	if err != nil {
		log.Fatalln("Failed to enumerate tokens:", err)
	}
	if len(cards) == 0 {
		log.Fatalln("No YubiKeys detected!")
	}
	// TODO: support multiple YubiKeys.
	yk, err := piv.Open(cards[0])
	if err != nil {
		log.Fatalln("Failed to connect to the YubiKey:", err)
	}
	return yk
}

func main() {
	yk := connectForSetup()
	fmt.Print("PIN: ")
	pin, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) == 0 || len(pin) > 8 {
		log.Fatalln("The PIN needs to be 1-8 characters.")
	}
	m, err := yk.Metadata(string(pin))
	if err != nil {
		log.Fatal("Failed to get metadata from Yubikey")
	}
	if m.ManagementKey == nil {
		log.Fatal("Failed to get management key from metadata")
	}
	key := *m.ManagementKey

	// fmt.Printf("Management key is: %x\n", key)
	slot := piv.SlotKeyManagement
	fmt.Printf("Generating private key on slot %x\n", slot.Key)
	pub, err := yk.GenerateKey(key, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyNever,
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
			CommonName: "SSH key with NO TOUCH REQUIRED",
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
	if err := yk.SetCertificate(key, slot, cert); err != nil {
		log.Fatalln("Failed to store certificate:", err)
	}

	sshKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		log.Fatalln("Failed to generate public key:", err)
	}

	fmt.Println("")
	fmt.Printf("✅ Done! No-touch key stored to slot %x\n", slot.Key)
	fmt.Println("")
	fmt.Println("🔑 Here's your new shiny SSH public key:")
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))

}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
