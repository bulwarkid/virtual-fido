package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
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
	fmt.Printf("------- Identities in file '%s' -------\n", vaultFilename)
	sources := client.Identities()
	for _, source := range sources {
		fmt.Printf("(%s): '%s' for website '%s'\n", hex.EncodeToString(source.ID[:4]), source.User.Name, source.RelyingParty.Name)
	}
}

func deleteIdentity(client virtual_fido.Client, prefix string) {
	identities := client.Identities()
	targetIDs := make([]*virtual_fido.CredentialSource, 0)
	for _, id := range identities {
		hexString := hex.EncodeToString(id.ID)
		if strings.HasPrefix(hexString, prefix) {
			targetIDs = append(targetIDs, &id)
		}
	}
	if len(targetIDs) > 1 {
		fmt.Printf("Multiple identities with prefix (%s):\n", prefix)
		for _, id := range targetIDs {
			fmt.Printf("- (%s)\n", hex.EncodeToString(id.ID))
		}
	} else if len(targetIDs) == 1 {
		fmt.Printf("Deleting identity (%s)\n...", hex.EncodeToString(targetIDs[0].ID))
		if client.DeleteIdentity(targetIDs[0].ID) {
			fmt.Printf("Done.\n")
		} else {
			fmt.Printf("Could not find (%s).\n", hex.EncodeToString(targetIDs[0].ID))
		}
	} else {
		fmt.Printf("No identity found with prefix (%s)\n", prefix)
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
	case "delete":
		deleteIdentity(client, os.Args[2])
	default:
		fmt.Printf("Unknown command: \"%s\"", os.Args[1])
	}
}
