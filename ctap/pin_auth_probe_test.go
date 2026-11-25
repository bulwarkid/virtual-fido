package ctap

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

// Probe requests are built as raw CBOR maps because the argument structs omit
// empty fields, and the probe is exactly an empty pinUvAuthParam.

func makeCredentialProbe(pinUVAuthParam []byte) map[int]interface{} {
	return map[int]interface{}{
		1: make([]byte, 32),
		2: webauthn.PublicKeyCredentialRPEntity{ID: ".dummy", Name: ".dummy"},
		3: webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1}, Name: "dummy", DisplayName: "dummy"},
		4: []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}},
		8: pinUVAuthParam,
		9: 1,
	}
}

func getAssertionProbe(pinUVAuthParam []byte) map[int]interface{} {
	return map[int]interface{}{
		1: "example.com",
		2: make([]byte, 32),
		6: pinUVAuthParam,
		7: 1,
	}
}

func TestPINAuthProbe(t *testing.T) {
	requests := map[string]struct {
		command ctapCommand
		args    func([]byte) map[int]interface{}
	}{
		"makeCredential": {ctapCommandMakeCredential, makeCredentialProbe},
		"getAssertion":   {ctapCommandGetAssertion, getAssertionProbe},
	}
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			client := newPINTestClient()
			server := NewCTAPServer(client)

			code, _ := runPINTestCommand(t, server, request.command, request.args([]byte{}))
			test.AssertEqual(t, code, ctap2ErrNoPINSet, "probe without a PIN should report PIN_NOT_SET")
			test.AssertEqual(t, client.approvals, 1, "probe must ask for user interaction")

			client.setTestPIN("1234")
			code, _ = runPINTestCommand(t, server, request.command, request.args([]byte{}))
			test.AssertEqual(t, code, ctap2ErrPINInvalid, "probe with a PIN should report PIN_INVALID")

			client.approve = false
			code, _ = runPINTestCommand(t, server, request.command, request.args([]byte{}))
			test.AssertEqual(t, code, ctap2ErrOperationDenied, "declined probe should report OPERATION_DENIED")

			// A non-empty but wrong pinUvAuthParam is not a probe.
			client.approve = true
			code, _ = runPINTestCommand(t, server, request.command, request.args(make([]byte, 16)))
			test.AssertEqual(t, code, ctap2ErrPINAuthInvalid, "wrong pinUvAuthParam should be rejected as before")
		})
	}
}

type selectingTestClient struct {
	*pinTestClient
	selections int
}

func (client *selectingTestClient) ApproveDeviceSelection() bool {
	client.selections++
	return true
}

func TestPINAuthProbeUsesDeviceSelectionApprover(t *testing.T) {
	client := &selectingTestClient{pinTestClient: newPINTestClient()}
	server := NewCTAPServer(client)
	code, _ := runPINTestCommand(t, server, ctapCommandMakeCredential, makeCredentialProbe([]byte{}))
	test.AssertEqual(t, code, ctap2ErrNoPINSet, "probe without a PIN should report PIN_NOT_SET")
	test.AssertEqual(t, client.selections, 1, "device selection prompt not used")
	test.AssertEqual(t, client.approvals, 0, "account creation prompt used instead of device selection")
}

func TestPINAuthProbeIgnoredWithoutPINSupport(t *testing.T) {
	server := NewCTAPServer(&dummyCTAPClient{})
	code, _ := runPINTestCommand(t, server, ctapCommandMakeCredential, makeCredentialProbe([]byte{}))
	test.AssertEqual(t, code, ctap1ErrSuccess, "without PIN support an empty pinUvAuthParam is not a probe")
}
