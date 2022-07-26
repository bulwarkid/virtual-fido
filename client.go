package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type Client struct {
	deviceEncryptionKey  []byte
	certificateAuthority *x509.Certificate
	caPrivateKey         *ecdsa.PrivateKey
}

func NewClient() *Client {
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
	authorityCert, err := x509.ParseCertificate(authorityCertBytes)
	checkErr(err, "Could not parse authority CA cert")
	encryptionKey := sha256.Sum256([]byte("test"))
	return &Client{
		deviceEncryptionKey:  encryptionKey[:],
		certificateAuthority: authorityCert,
		caPrivateKey:         privateKey,
	}
}

func (client *Client) newPrivateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	return privateKey
}

func (client *Client) keyHandle(privateKey *ecdsa.PrivateKey, applicationId []byte) KeyHandle {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	checkErr(err, "Could not encode private key")
	wrappedPrivateKey := encrypt(client.deviceEncryptionKey, privateKeyBytes)
	signature := sign(privateKey, applicationId)
	return KeyHandle{WrappedPrivateKey: wrappedPrivateKey, ApplicationSignature: signature}
}

func (client *Client) createAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte {
	// TODO: Fill in fields like SerialNumber and SubjectKeyIdentifier
	templateCert := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Virtual FIDO"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, templateCert, client.certificateAuthority, &privateKey.PublicKey, client.caPrivateKey)
	checkErr(err, "Could not generate attestation certificate")
	return certBytes
}
