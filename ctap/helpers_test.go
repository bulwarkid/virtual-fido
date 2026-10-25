package ctap

import (
	"crypto/ecdsa"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

func TestMakeAttestedCredentialData(t *testing.T) {
	priv := cose.SupportedCOSEPrivateKey{ECDSA: mustKey(t)}
	cs := identities.CredentialSource{
		ID:         []byte("cred"),
		PrivateKey: &priv,
	}
	data := MakeAttestedCredentialData(&cs)
	if len(data) == 0 {
		t.Fatalf("attested cred data empty")
	}
}

func TestBuildMakeCredentialResponse(t *testing.T) {
	priv := cose.SupportedCOSEPrivateKey{ECDSA: mustKey(t)}
	cs := identities.CredentialSource{
		ID:         []byte("cred"),
		PrivateKey: &priv,
		RelyingParty: &webauthn.PublicKeyCredentialRPEntity{
			ID:   "example.com",
			Name: "example.com",
		},
	}
	resp := BuildMakeCredentialResponse(&cs, []byte{1, 2, 3}, 0x05)
	if len(resp.AuthData) == 0 || resp.FormatIdentifer != "packed" {
		t.Fatalf("invalid response: %#v", resp)
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	return crypto.GenerateECDSAKey()
}
