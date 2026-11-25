package ctap

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
)

// pinTestClient is a CTAPClient with working PIN state and a configurable
// user approval, for ClientPIN tests.
type pinTestClient struct {
	dummyCTAPClient
	pinHash      []byte
	pinRetries   int32
	keyAgreement *crypto.ECDHKey
	pinToken     []byte
	approve      bool
	approvals    int
}

func newPINTestClient() *pinTestClient {
	return &pinTestClient{
		pinRetries:   8,
		keyAgreement: crypto.GenerateECDHKey(),
		pinToken:     crypto.RandomBytes(16),
		approve:      true,
	}
}

func (client *pinTestClient) SupportsPIN() bool                { return true }
func (client *pinTestClient) PINHash() []byte                  { return client.pinHash }
func (client *pinTestClient) SetPINHash(pinHash []byte)        { client.pinHash = pinHash }
func (client *pinTestClient) PINRetries() int32                { return client.pinRetries }
func (client *pinTestClient) SetPINRetries(retries int32)      { client.pinRetries = retries }
func (client *pinTestClient) PINKeyAgreement() *crypto.ECDHKey { return client.keyAgreement }
func (client *pinTestClient) PINToken() []byte                 { return client.pinToken }

func (client *pinTestClient) ApproveAccountCreation(relyingParty string) bool {
	client.approvals++
	return client.approve
}

func (client *pinTestClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	client.approvals++
	return client.approve
}

func (client *pinTestClient) setTestPIN(pin string) {
	client.pinHash = crypto.HashSHA256([]byte(pin))[:16]
}

// pinTestPlatform is the platform side of a PIN protocol 1 key agreement.
type pinTestPlatform struct {
	publicKey    cose.COSEEC2Key
	sharedSecret []byte
}

func newPINTestPlatform(client *pinTestClient) pinTestPlatform {
	key := crypto.GenerateECDHKey()
	authenticatorKey := client.keyAgreement
	return pinTestPlatform{
		publicKey: cose.COSEEC2Key{
			KeyType:   int8(cose.COSE_KEY_TYPE_EC2),
			Algorithm: int8(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256),
			Curve:     int8(cose.COSE_CURVE_ID_P256),
			X:         key.X.Bytes(),
			Y:         key.Y.Bytes(),
		},
		sharedSecret: crypto.HashSHA256(key.ECDH(authenticatorKey.X, authenticatorKey.Y)),
	}
}

func (platform pinTestPlatform) encrypt(data []byte) []byte {
	return crypto.EncryptAESCBC(platform.sharedSecret, data)
}

func (platform pinTestPlatform) authenticate(data []byte) []byte {
	return (&CTAPServer{}).derivePINAuth(platform.sharedSecret, data)
}

func (platform pinTestPlatform) encryptedPINHash(pin string) []byte {
	return platform.encrypt(crypto.HashSHA256([]byte(pin))[:16])
}

func (platform pinTestPlatform) encryptedNewPIN(pin string) []byte {
	padded := make([]byte, 64)
	copy(padded, pin)
	return platform.encrypt(padded)
}

// runPINTestCommand sends a CTAP command and returns its status code and body.
func runPINTestCommand(t *testing.T, server *CTAPServer, command ctapCommand, args interface{}) (ctapStatusCode, []byte) {
	t.Helper()
	response := server.HandleMessage(util.Concat([]byte{byte(command)}, util.MarshalCBOR(args)))
	if len(response) == 0 {
		t.Fatal("empty response")
	}
	return ctapStatusCode(response[0]), response[1:]
}
