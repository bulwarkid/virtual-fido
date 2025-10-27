package ctap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

type memSaver struct{ data []byte }

func (m *memSaver) SaveData(d []byte) { m.data = append([]byte{}, d...) }
func (m *memSaver) RetrieveData() []byte {
	if m.data == nil {
		return nil
	}
	return append([]byte{}, m.data...)
}
func (m *memSaver) Passphrase() string { return "passphrase" }

type autoApprove struct{}

func (a *autoApprove) ApproveClientAction(_ fido_client.ClientAction, _ fido_client.ClientActionRequestParams) bool {
	return true
}

// Utility: derive PIN auth like server does
func hmac16(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	out := h.Sum(nil)
	return out[:16]
}

// Extract extensions CBOR from authData (GA case: no attested data). authData layout:
// 32 rpIdHash | 1 flags | 4 sigCounter | CBOR(extensions)
func parseExtensionsFromAuthData(t *testing.T, authData []byte) map[string][]byte {
	t.Helper()
	if len(authData) < 37 {
		t.Fatalf("authData too short: %d", len(authData))
	}
	ext := make(map[string][]byte)
	if len(authData) == 37 {
		return ext
	}
	tail := authData[37:]
	var m map[string][]byte
	err := cbor.Unmarshal(tail, &m)
	if err != nil {
		t.Fatalf("cbor unmarshal ext: %v", err)
	}
	return m
}

func newClient(t *testing.T) *fido_client.DefaultFIDOClient {
	caPriv, err := identities.CreateCAPrivateKey()
	if err != nil {
		t.Fatalf("create CA priv: %v", err)
	}
	ca, err := identities.CreateSelfSignedCA(caPriv)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	key := sha256.Sum256([]byte("test"))
	saver := &memSaver{}
	appr := &autoApprove{}
	c := fido_client.NewDefaultClient(ca, caPriv, key, true, appr, nil, saver)
	c.SetPIN([]byte("1234"))
	return c
}

func TestHmacSecretTwoSalts(t *testing.T) {
	client := newClient(t)
	ctap := NewCTAPServer(client)

	// MC with hmac-secret extension requested
	rp := &webauthn.PublicKeyCredentialRPEntity{ID: "example.com", Name: "Example"}
	user := &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1, 2, 3}, DisplayName: "Alice", Name: "alice"}
	clientDataHash := crypto.RandomBytes(32)
	argsMC := makeCredentialArgs{
		ClientDataHash:    clientDataHash,
		RP:                rp,
		User:              user,
		PubKeyCredParams:  []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}},
		Options:           &makeCredentialOptions{ResidentKey: true, UserVerification: true},
		Extensions:        map[string]interface{}{"hmac-secret": true},
		PINUVAuthProtocol: 1,
		PINUVAuthParam:    hmac16(client.PINToken(), clientDataHash),
	}
	payloadMC := util.Concat([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(argsMC))
	respMC := ctap.HandleMessage(payloadMC)
	if ctapStatusCode(respMC[0]) != ctap1ErrSuccess {
		t.Fatalf("MC failed: %x", respMC[0])
	}
	var mc makeCredentialResponse
	if err := cbor.Unmarshal(respMC[1:], &mc); err != nil {
		t.Fatalf("decode MC: %v", err)
	}
	// Extract created credential ID from attestedCredentialData in mc.AuthData
	// authData: 32 rpIdHash | 1 flags | 4 counter | attestedCredData
	ad := mc.AuthData
	if len(ad) < 37 {
		t.Fatalf("authData too short: %d", len(ad))
	}
	// Skip to attested data: flags has AT bit set, so next is attested data
	att := ad[37:]
	if len(att) < 16+2 {
		t.Fatalf("attested data too short: %d", len(att))
	}
	// Skip AAGUID(16), read L (2)
	l := int(att[16])<<8 | int(att[17])
	if len(att) < 18+l {
		t.Fatalf("attested cred id too short")
	}
	credID := append([]byte{}, att[18:18+l]...)

	// Prepare GA with hmac-secret: build salts and keyAgreement
	salt1 := crypto.RandomBytes(32)
	salt2 := crypto.RandomBytes(32)
	salts := append(salt1, salt2...)
	// Use client's PINKeyAgreement as authenticator private; platform key is random
	platKey := crypto.GenerateECDHKey()
	shared := crypto.HashSHA256(client.PINKeyAgreement().ECDH(platKey.X, platKey.Y))
	saltEnc := crypto.EncryptAESCBC(shared, salts)
	saltAuth := hmac16(shared, saltEnc)
	keyAgreement := &cose.COSEEC2Key{KeyType: int8(cose.COSE_KEY_TYPE_EC2), Algorithm: int8(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256), Curve: int8(1), X: platKey.X.Bytes(), Y: platKey.Y.Bytes()}
	// Build hmac-secret input
	hmin := hmacSecretInput{KeyAgreement: keyAgreement, SaltEnc: saltEnc, SaltAuth: saltAuth}
	raw, err := cbor.Marshal(hmin)
	if err != nil {
		t.Fatalf("marshal hmac-secret input: %v", err)
	}

	argsGA := getAssertionArgs{
		RPID:              "example.com",
		ClientDataHash:    crypto.RandomBytes(32),
		AllowList:         []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: credID}},
		Extensions:        map[string]cbor.RawMessage{"hmac-secret": raw},
		Options:           getAssertionOptions{},
		PINUVAuthProtocol: 1,
		PINUVAuthParam:    hmac16(client.PINToken(), nil), // nil here is atypical, but server only checks equality with args.ClientDataHash; set param properly:
	}
	// Correct pinAuth with the GA clientDataHash
	argsGA.PINUVAuthParam = hmac16(client.PINToken(), argsGA.ClientDataHash)

	payloadGA := util.Concat([]byte{byte(ctapCommandGetAssertion)}, util.MarshalCBOR(argsGA))
	// Use channel-aware handler to enable GetNextAssertion sessions
	respGA := ctap.HandleMessageForChannel(1, payloadGA)
	if ctapStatusCode(respGA[0]) != ctap1ErrSuccess {
		t.Fatalf("GA failed: %x", respGA[0])
	}
	var ga getAssertionResponse
	if err := cbor.Unmarshal(respGA[1:], &ga); err != nil {
		t.Fatalf("decode GA: %v", err)
	}
	// Parse extensions
	exts := parseExtensionsFromAuthData(t, ga.AuthenticatorData)
	out := exts["hmac-secret"]
	if len(out) != 64 {
		t.Fatalf("unexpected hmac-secret len: %d", len(out))
	}
	// Verify outputs
	// find credRandom of created credential
	var credRandom []byte
	for _, c := range client.Identities() {
		if bytes.Equal(c.ID, credID) {
			credRandom = c.CredRandom
			break
		}
	}
	if len(credRandom) != 32 {
		t.Fatalf("credRandom not found or invalid length: %d", len(credRandom))
	}
	h1 := hmac.New(sha256.New, credRandom)
	h1.Write(salt1)
	want1 := h1.Sum(nil)
	h2 := hmac.New(sha256.New, credRandom)
	h2.Write(salt2)
	want2 := h2.Sum(nil)
	if !bytes.Equal(out[:32], want1) || !bytes.Equal(out[32:], want2) {
		t.Fatalf("hmac-secret outputs mismatch")
	}
}

func TestClientPinGetPINToken(t *testing.T) {
	client := newClient(t)
	ctap := NewCTAPServer(client)

	// Platform generates ECDH key
	plat := crypto.GenerateECDHKey()
	// Shared secret = SHA256(ECDH(authPriv, platPub)) where authPriv is client.PINKeyAgreement
	shared := crypto.HashSHA256(client.PINKeyAgreement().ECDH(plat.X, plat.Y))
	// pinHash = LEFT(SHA256(PIN),16)
	pinHash := crypto.HashSHA256([]byte("1234"))[:16]
	pinHashEnc := crypto.EncryptAESCBC(shared, pinHash)

	// Build request: getPINToken
	ka := &cose.COSEEC2Key{KeyType: int8(cose.COSE_KEY_TYPE_EC2), Algorithm: int8(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256), Curve: int8(1), X: plat.X.Bytes(), Y: plat.Y.Bytes()}
	args := clientPINArgs{PINUVAuthProtocol: 1, SubCommand: clientPinSubcommandGetPINToken, KeyAgreement: ka, PINHashEncoding: pinHashEnc}
	req := util.Concat([]byte{byte(ctapCommandClientPIN)}, util.MarshalCBOR(args))
	resp := ctap.HandleMessage(req)
	if ctapStatusCode(resp[0]) != ctap1ErrSuccess {
		t.Fatalf("getPINToken failed: %x", resp[0])
	}
	var out clientPINResponse
	if err := cbor.Unmarshal(resp[1:], &out); err != nil {
		t.Fatalf("decode getPINToken resp: %v", err)
	}
	if len(out.PinToken) == 0 {
		t.Fatalf("no pinToken returned")
	}
	// Decrypt pinToken and compare with client's stored token
	decrypted := crypto.DecryptAESCBC(shared, out.PinToken)
	if !bytes.Equal(decrypted, client.PINToken()) {
		t.Fatalf("pin token mismatch")
	}
}
