package client

import (
	"bytes"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

type mockCounterStore struct {
	creds map[string]uint32
}

func (m *mockCounterStore) IncrementCred(id []byte) uint32 {
	m.creds[string(id)]++
	return m.creds[string(id)]
}

func (m *mockCounterStore) EnsureCred(id []byte) {
	if _, ok := m.creds[string(id)]; !ok {
		m.creds[string(id)] = 0
	}
}

func (m *mockCounterStore) CredValue(id []byte) (uint32, bool) {
	v, ok := m.creds[string(id)]
	return v, ok
}

func (m *mockCounterStore) SetCred(id []byte, v uint32) {
	m.creds[string(id)] = v
}

func (m *mockCounterStore) IncrementGlobal() uint32 {
	return 1
}

type mockApprover struct {
	approved bool
}

func (m *mockApprover) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) (bool, int) {
	return m.approved, 0
}

func TestSeedClient_NewCredentialSource(t *testing.T) {
	seed := []byte("test-seed")
	counters := &mockCounterStore{creds: make(map[string]uint32)}
	approver := &mockApprover{approved: true}
	c := New(seed, counters, approver)

	rp := &webauthn.PublicKeyCredentialRPEntity{ID: "example.com", Name: "Example"}
	user := &webauthn.PublicKeyCrendentialUserEntity{ID: []byte("user1"), Name: "alice"}
	params := []webauthn.PublicKeyCredentialParams{
		{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256},
	}

	cs := c.NewCredentialSource(params, nil, rp, user)
	test.AssertNotNil(t, cs, "Expected credential source")
	test.AssertEqual(t, cs.RelyingParty.ID, "example.com", "Wrong RP ID")
	test.Assert(t, len(cs.ID) > 0, "Empty credential ID")

	// Test unsupported algorithm
	badParams := []webauthn.PublicKeyCredentialParams{
		{Type: "public-key", Algorithm: -999},
	}
	csBad := c.NewCredentialSource(badParams, nil, rp, user)
	test.Assert(t, csBad == nil, "Expected nil for unsupported algorithm")
}

func TestSeedClient_ResidentKeyAssertion(t *testing.T) {
	seed := []byte("test-seed")
	counters := &mockCounterStore{creds: make(map[string]uint32)}
	approver := &mockApprover{approved: true}
	c := New(seed, counters, approver)

	// Register with default-user to match default RK behavior
	rp := &webauthn.PublicKeyCredentialRPEntity{ID: "example.com", Name: "Example"}
	user := &webauthn.PublicKeyCrendentialUserEntity{ID: []byte("default-user"), Name: "default-user"}
	params := []webauthn.PublicKeyCredentialParams{
		{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256},
	}
	csReg := c.NewCredentialSource(params, nil, rp, user)

	// Get assertion for the same RP with empty allow list
	csAss := c.GetAssertionSource("example.com", nil)
	test.AssertNotNil(t, csAss, "Expected assertion source for RK")
	test.Assert(t, bytes.Equal(csReg.ID, csAss.ID), "RK credential ID should be deterministic and match registration")
}

func TestSeedClient_SignatureCounter(t *testing.T) {
	seed := []byte("test-seed")
	counters := &mockCounterStore{creds: make(map[string]uint32)}
	approver := &mockApprover{approved: true}
	c := New(seed, counters, approver)

	cs := &identities.CredentialSource{ID: []byte("test-cred")}
	counters.EnsureCred(cs.ID)

	count1 := c.BumpSignatureCounter(cs)
	test.AssertEqual(t, count1, int32(1), "Expected counter 1")

	count2 := c.BumpSignatureCounter(cs)
	test.AssertEqual(t, count2, int32(2), "Expected counter 2")
}

func TestSeedClient_Approvals(t *testing.T) {
	seed := []byte("test-seed")
	counters := &mockCounterStore{creds: make(map[string]uint32)}
	approver := &mockApprover{approved: false}
	c := New(seed, counters, approver)

	test.Assert(t, !c.ApproveAccountCreation("Example", "example.com"), "Should respect approver denial")

	approver.approved = true
	test.Assert(t, c.ApproveAccountCreation("Example", "example.com"), "Should respect approver approval")
}
