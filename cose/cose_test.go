package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/fxamacker/cbor/v2"
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

func TestECDSACoordinatesFixedLength(t *testing.T) {
	// Leading zero bytes occur ~1/256 of the time per value; iterate enough to
	// exercise them. COSE EC2 requires 32-byte coordinates for P-256.
	for i := 0; i < 2048; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		checkErr(t, err)
		cosePrivateKey := &SupportedCOSEPrivateKey{ECDSA: privateKey}

		var pub COSEEC2Key
		checkErr(t, cbor.Unmarshal(MarshalCOSEPublicKey(cosePrivateKey.Public()), &pub))
		if len(pub.X) != 32 || len(pub.Y) != 32 {
			t.Fatalf("public key coordinates not 32 bytes: x=%d y=%d", len(pub.X), len(pub.Y))
		}

		encoded := MarshalCOSEPrivateKey(cosePrivateKey)
		var priv COSEEC2Key
		checkErr(t, cbor.Unmarshal(encoded, &priv))
		if len(priv.X) != 32 || len(priv.Y) != 32 || len(priv.D) != 32 {
			t.Fatalf("private key fields not 32 bytes: x=%d y=%d d=%d", len(priv.X), len(priv.Y), len(priv.D))
		}
		decoded, err := UnmarshalCOSEPrivateKey(encoded)
		checkErr(t, err)
		if !decoded.Equal(cosePrivateKey) {
			t.Fatalf("round trip changed key")
		}
	}
}
