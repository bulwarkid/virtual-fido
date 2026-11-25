package ctap

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
)

func TestSetPINRejectsMalformedNewPINEncoding(t *testing.T) {
	client := newPINTestClient()
	server := NewCTAPServer(client)
	platform := newPINTestPlatform(client)

	cases := []struct {
		length int
		status ctapStatusCode
	}{
		{63, ctap2ErrPINAuthInvalid},   // not whole AES blocks: decryption fails
		{32, ctap1ErrInvalidParameter}, // whole blocks, but not 64 bytes
		{80, ctap1ErrInvalidParameter},
	}
	for _, c := range cases {
		newPINEnc := make([]byte, c.length)
		code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, clientPINArgs{
			PINUVAuthProtocol: 1,
			SubCommand:        clientPINSubcommandSetPIN,
			KeyAgreement:      &platform.publicKey,
			PINUVAuthParam:    platform.authenticate(newPINEnc),
			NewPINEncoding:    newPINEnc,
		})
		test.AssertEqual(t, code, c.status, "unexpected status for malformed newPinEnc")
		test.Assert(t, client.pinHash == nil, "PIN was set from a malformed newPinEnc")
	}

	newPINEnc := platform.encryptedNewPIN("1234")
	code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPINSubcommandSetPIN,
		KeyAgreement:      &platform.publicKey,
		PINUVAuthParam:    platform.authenticate(newPINEnc),
		NewPINEncoding:    newPINEnc,
	})
	test.AssertEqual(t, code, ctap1ErrSuccess, "valid setPIN failed")
}

func getPINTokenWithHashEncoding(t *testing.T, server *CTAPServer, platform pinTestPlatform, pinHashEnc []byte) ctapStatusCode {
	code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetPINToken,
		KeyAgreement:      &platform.publicKey,
		PINHashEncoding:   pinHashEnc,
	})
	return code
}

func TestGetPINTokenRejectsMalformedPINHashEncoding(t *testing.T) {
	client := newPINTestClient()
	client.setTestPIN("1234")
	server := NewCTAPServer(client)
	platform := newPINTestPlatform(client)

	for _, length := range []int{15, 17, 32} {
		code := getPINTokenWithHashEncoding(t, server, platform, make([]byte, length))
		test.AssertEqual(t, code, ctap2ErrPINInvalid, "malformed pinHashEnc not treated as a wrong PIN")
	}
	test.AssertEqual(t, client.pinRetries, int32(5), "malformed pinHashEnc should consume a retry like a wrong PIN")

	code := getPINTokenWithHashEncoding(t, server, platform, platform.encryptedPINHash("1234"))
	test.AssertEqual(t, code, ctap1ErrSuccess, "correct PIN rejected")
}

func TestGetPINTokenWithoutPINRequiresHash(t *testing.T) {
	client := newPINTestClient() // no PIN set
	server := NewCTAPServer(client)
	platform := newPINTestPlatform(client)

	// An empty pinHashEnc used to decrypt to an empty hash equal to the unset
	// PIN hash, issuing a PIN token (and thus UV) without any PIN. Built by
	// hand because clientPINArgs omits empty fields.
	args := map[int]interface{}{
		1: 1,
		2: int(clientPinSubcommandGetPINToken),
		3: platform.publicKey,
		6: []byte{},
	}
	code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, args)
	test.Assert(t, code != ctap1ErrSuccess, "PIN token issued for an empty pinHashEnc without a PIN set")
}

func TestGetPINTokenMissingKeyAgreement(t *testing.T) {
	client := newPINTestClient()
	client.setTestPIN("1234")
	server := NewCTAPServer(client)
	code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetPINToken,
		PINHashEncoding:   make([]byte, 16),
	})
	test.AssertEqual(t, code, ctap2ErrMissingParam, "missing key agreement not reported")
}

func TestChangePINRejectsMalformedEncodings(t *testing.T) {
	client := newPINTestClient()
	client.setTestPIN("1234")
	server := NewCTAPServer(client)
	platform := newPINTestPlatform(client)

	changePIN := func(newPINEnc, pinHashEnc []byte) ctapStatusCode {
		code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, clientPINArgs{
			PINUVAuthProtocol: 1,
			SubCommand:        clientPINSubcommandChangePIN,
			KeyAgreement:      &platform.publicKey,
			PINUVAuthParam:    platform.authenticate(append(append([]byte{}, newPINEnc...), pinHashEnc...)),
			NewPINEncoding:    newPINEnc,
			PINHashEncoding:   pinHashEnc,
		})
		return code
	}

	test.AssertEqual(t, changePIN(platform.encryptedNewPIN("5678"), make([]byte, 17)), ctap2ErrPINInvalid, "malformed pinHashEnc accepted")
	test.AssertEqual(t, changePIN(make([]byte, 63), platform.encryptedPINHash("1234")), ctap2ErrPINAuthInvalid, "partial-block newPinEnc accepted")
	test.AssertEqual(t, changePIN(make([]byte, 32), platform.encryptedPINHash("1234")), ctap1ErrInvalidParameter, "32-byte newPinEnc accepted")
	test.AssertArrEqual(t, client.pinHash, newPINTestHash("1234"), "PIN changed by a malformed request")

	code, _ := runPINTestCommand(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPINSubcommandChangePIN,
		KeyAgreement:      &platform.publicKey,
		PINUVAuthParam:    make([]byte, 16),
		PINHashEncoding:   platform.encryptedPINHash("1234"),
	})
	test.AssertEqual(t, code, ctap2ErrMissingParam, "missing newPinEnc not reported")

	test.AssertEqual(t, changePIN(platform.encryptedNewPIN("5678"), platform.encryptedPINHash("1234")), ctap1ErrSuccess, "valid changePIN failed")
	test.AssertArrEqual(t, client.pinHash, newPINTestHash("5678"), "PIN not changed")
}

func newPINTestHash(pin string) []byte {
	client := &pinTestClient{}
	client.setTestPIN(pin)
	return client.pinHash
}
