package ctap

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

// flexibleMockClient extends dummyCTAPClient to allow controlling responses
type flexibleMockClient struct {
	dummyCTAPClient
	approveCreation bool
	approveLogin    bool
}

func (m *flexibleMockClient) ApproveAccountCreation(rpName, rpID string) bool {
	return m.approveCreation
}

func (m *flexibleMockClient) ApproveAccountLogin(cs *identities.CredentialSource) bool {
	return m.approveLogin
}

func TestGetInfo_FIDO21_Details(t *testing.T) {
	client := &dummyCTAPClient{}
	server := NewCTAPServer(client)

	respBytes := server.handleGetInfo()
	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap1ErrSuccess, "Expected success")

	var resp getInfoResponse
	err := cbor.Unmarshal(respBytes[1:], &resp)
	util.CheckErr(err, "CBOR unmarshal failed")

	test.AssertContains(t, resp.Versions, "FIDO_2_1", "FIDO_2_1 should be reported")
	test.Assert(t, resp.Options.CanUserVerification, "Should support UV")
	test.Assert(t, resp.Options.CanUserPresence, "Should support UP")
}

func TestMakeCredential_Unapproved(t *testing.T) {
	client := &flexibleMockClient{approveCreation: false}
	server := NewCTAPServer(client)

	args := MakeCredentialArgs{
		RP: &webauthn.PublicKeyCredentialRPEntity{ID: "test.com"},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256},
		},
	}
	data := util.MarshalCBOR(args)
	respBytes := server.handleMakeCredential(data)

	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap2ErrOperationDenied, "Expected operation denied")
}

func TestMakeCredential_UnsupportedAlgorithm(t *testing.T) {
	client := &flexibleMockClient{approveCreation: true}
	server := NewCTAPServer(client)

	args := MakeCredentialArgs{
		RP: &webauthn.PublicKeyCredentialRPEntity{ID: "test.com"},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{Type: "public-key", Algorithm: -999}, // Unsupported
		},
	}
	data := util.MarshalCBOR(args)
	respBytes := server.handleMakeCredential(data)

	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap2ErrUnsupportedAlgorithm, "Expected unsupported algorithm")
}

func TestGetAssertion_Unapproved(t *testing.T) {
	client := &flexibleMockClient{approveLogin: false}
	// Setup a credential in vault so it finds something to ask for approval
	identity := client.vault.NewIdentity(&webauthn.PublicKeyCredentialRPEntity{ID: "test.com"}, &webauthn.PublicKeyCrendentialUserEntity{ID: []byte("user")})

	server := NewCTAPServer(client)
	args := GetAssertionArgs{
		RPID: "test.com",
		AllowList: []webauthn.PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: identity.ID},
		},
	}
	data := util.MarshalCBOR(args)
	respBytes := server.handleGetAssertion(data)

	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap2ErrOperationDenied, "Expected operation denied")
}

func TestGetAssertion_NotFound(t *testing.T) {
	client := &flexibleMockClient{approveLogin: true}
	server := NewCTAPServer(client)

	args := GetAssertionArgs{
		RPID: "unknown.com",
		AllowList: []webauthn.PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: []byte("nonexistent")},
		},
	}
	data := util.MarshalCBOR(args)
	respBytes := server.handleGetAssertion(data)

	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap2ErrNoCredentials, "Expected no credentials")
}

func TestMakeCredential_Flags(t *testing.T) {
	client := &flexibleMockClient{approveCreation: true}
	server := NewCTAPServer(client)

	args := MakeCredentialArgs{
		RP: &webauthn.PublicKeyCredentialRPEntity{ID: "test.com"},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256},
		},
		Options: &MakeCredentialOptions{
			ResidentKey:      true,
			UserVerification: true,
		},
	}
	data := util.MarshalCBOR(args)
	respBytes := server.handleMakeCredential(data)

	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap1ErrSuccess, "Expected success")

	var resp MakeCredentialResponse
	err := cbor.Unmarshal(respBytes[1:], &resp)
	util.CheckErr(err, "CBOR unmarshal failed")

	// Flags are at byte 32 of AuthData
	// bit 0: UP, bit 2: UV, bit 6: AT, bit 7: ED
	flags := resp.AuthData[32]
	test.Assert(t, flags&0x01 != 0, "User Present bit should be set")
	test.Assert(t, flags&0x04 != 0, "User Verified bit should be set")
	test.Assert(t, flags&0x40 != 0, "Attested Data Included bit should be set")
}

// pinMockClient extends flexibleMockClient to support PIN
type pinMockClient struct {
	flexibleMockClient
	supportsPIN bool
	pinHash     []byte
	pinRetries  int32
	pinToken    []byte
	key         *crypto.ECDHKey
}

func (m *pinMockClient) SupportsPIN() bool                { return m.supportsPIN }
func (m *pinMockClient) PINHash() []byte                  { return m.pinHash }
func (m *pinMockClient) SetPINHash(p []byte)              { m.pinHash = p }
func (m *pinMockClient) PINRetries() int32                { return m.pinRetries }
func (m *pinMockClient) SetPINRetries(r int32)            { m.pinRetries = r }
func (m *pinMockClient) PINKeyAgreement() *crypto.ECDHKey { return m.key }
func (m *pinMockClient) PINToken() []byte                 { return m.pinToken }

func TestClientPIN_Basic(t *testing.T) {
	key := crypto.GenerateECDHKey()
	client := &pinMockClient{
		supportsPIN: true,
		pinRetries:  8,
		key:         key,
	}
	server := NewCTAPServer(client)

	// Test GetRetries
	args := clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPINSubcommandGetRetries,
	}
	respBytes := server.handleClientPIN(util.MarshalCBOR(args))
	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap1ErrSuccess, "Expected success")
	var resp clientPINResponse
	cbor.Unmarshal(respBytes[1:], &resp)
	test.AssertEqual(t, *resp.Retries, uint8(8), "Expected 8 retries")

	// Test GetKeyAgreement
	args.SubCommand = clientPinSubcommandGetKeyAgreement
	respBytes = server.handleClientPIN(util.MarshalCBOR(args))
	test.AssertEqual(t, ctapStatusCode(respBytes[0]), ctap1ErrSuccess, "Expected success")
	cbor.Unmarshal(respBytes[1:], &resp)
	test.AssertNotNil(t, resp.KeyAgreement, "Expected key agreement")
}
