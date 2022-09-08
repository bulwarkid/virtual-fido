package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
	"virtual_fido"
)

func prompt(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	fmt.Print("--> ")
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s - %s\n", response, err)
		panic(err)
	}
	return response
}

type ClientSupport struct{}

func (support *ClientSupport) ApproveAccountCreation(relyingParty string) bool {
	response := prompt(fmt.Sprintf("Approve account creation for \"%s\" (Y/n)?", relyingParty))
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func (support *ClientSupport) ApproveLogin(relyingParty string, username string) bool {
	response := prompt(fmt.Sprintf("Approve login for \"%s\" with identity \"%s\" (Y/n)?", relyingParty, username))
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func (support *ClientSupport) SaveData(data []byte) {
	// TODO: Implement
}

func (support *ClientSupport) RetrieveData() []byte {
	// TODO: Implement
	return nil
}

func (support *ClientSupport) Passphrase() string {
	// TODO: Implement
	return "test passphrase"
}

func main() {
	// ALL OF THIS IS INSECURE, FOR TESTING PURPOSES ONLY
	authority := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Virtual FIDO"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Could not generate attestation CA private key")
		return
	}
	authorityCertBytes, err := x509.CreateCertificate(rand.Reader, authority, authority, &privateKey.PublicKey, privateKey)
	if err != nil {
		fmt.Println("Could not generate attestation CA cert bytes")
		return
	}
	encryptionKey := sha256.Sum256([]byte("test"))

	virtual_fido.SetLogOutput(os.Stdout)
	support := ClientSupport{}
	client := virtual_fido.NewClient(authorityCertBytes, privateKey, encryptionKey, &support, &support)
	virtual_fido.Start(client)
}
