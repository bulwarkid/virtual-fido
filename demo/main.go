package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"
	"virtual_fido"
)

var vaultFilename string = "vault.data"

func checkErr(err error, message string) {
	if err != nil {
		panic(fmt.Sprintf("Error: %s - %s", err, message))
	}
}

func listIdentities(client virtual_fido.Client) {
	fmt.Printf("Identities in file '%s':\n", vaultFilename)
	sources := client.Identities()
	for _, source := range sources {
		fmt.Printf("\t- '%s' for website '%s'\n", source.User.Name, source.RelyingParty.Name)
	}
}

func createClient() virtual_fido.Client {
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
	checkErr(err, "Could not generate attestation CA private key")
	authorityCertBytes, err := x509.CreateCertificate(rand.Reader, authority, authority, &privateKey.PublicKey, privateKey)
	checkErr(err, "Could not generate attestation CA cert bytes")
	encryptionKey := sha256.Sum256([]byte("test"))

	virtual_fido.SetLogOutput(os.Stdout)
	support := ClientSupport{}
	return virtual_fido.NewClient(authorityCertBytes, privateKey, encryptionKey, &support, &support)
}

func printUsage(message string) {
	fmt.Printf("Incorrect Usage: %s", message)
	fmt.Printf("Usage: go run start.go [command]\n")
	fmt.Printf("\tCommand: start\n")
	fmt.Printf("\tCommand: list\n")
}

func main() {
	if len(os.Args) < 2 {
		printUsage("Not enough arguments")
		return
	}
	client := createClient()
	switch os.Args[1] {
	case "start":
		runServer(client)
	case "list":
		listIdentities(client)
	default:
		fmt.Printf("Unknown command: \"%s\"", os.Args[1])
	}
}
