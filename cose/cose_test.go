package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Error - %s", err)
	}
}

func testCOSEKey(t *testing.T, key *SupportedCOSEPrivateKey) {
	data := []byte("test")
	signature := key.Sign(data)
	if !key.Public().Verify(data, signature) {
		t.Fatalf("Signature not verified: %#v", signature)
	}
	encoded := MarshalCOSEPrivateKey(key)
	decoded, err := UnmarshalCOSEPrivateKey(encoded)
	checkErr(t, err)
	if !decoded.Equal(key) {
		t.Fatalf("Encode and decode does not result in same key")
	}
}

func TestECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(t, err)
	cosePrivateKey := &SupportedCOSEPrivateKey{ECDSA: privateKey}
	testCOSEKey(t, cosePrivateKey)
}

func TestEd25519(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	checkErr(t, err)
	cosePrivateKey := &SupportedCOSEPrivateKey{Ed25519: &privateKey}
	testCOSEKey(t, cosePrivateKey)
}

func TestRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	checkErr(t, err)
	cosePrivateKey := &SupportedCOSEPrivateKey{RSA: privateKey}
	testCOSEKey(t, cosePrivateKey)
}
