package ctap

import (
	"crypto/sha256"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/fxamacker/cbor/v2"
)

// MakeAttestedCredentialData builds attested credential data for a new credential.
func MakeAttestedCredentialData(credentialSource *identities.CredentialSource) []byte {
	encodedCredentialPublicKey := cose.MarshalCOSEPublicKey(credentialSource.PrivateKey.Public())
	return util.Concat(DefaultAAGUID[:], util.ToBE(uint16(len(credentialSource.ID))), credentialSource.ID, encodedCredentialPublicKey)
}

// MakeAuthData builds authenticator data for attestation/assertion.
func MakeAuthData(rpID string, credentialSource *identities.CredentialSource, attestedCredentialData []byte, flags byte) []byte {
	if attestedCredentialData != nil {
		flags = flags | byte(authDataFlagAttestedDataIncluded)
	} else {
		attestedCredentialData = []byte{}
	}
	rpIdHash := sha256.Sum256([]byte(rpID))
	return util.Concat(rpIdHash[:], []byte{uint8(flags)}, util.ToBE(credentialSource.SignatureCounter), attestedCredentialData)
}

// BuildMakeCredentialResponse builds a packed attestation response from components.
func BuildMakeCredentialResponse(cs *identities.CredentialSource, clientDataHash []byte, flags byte) MakeCredentialResponse {
	attCredData := MakeAttestedCredentialData(cs)
	authData := MakeAuthData(cs.RelyingParty.ID, cs, attCredData, flags)
	attestationSignature := cs.PrivateKey.Sign(append(authData, clientDataHash...))
	attestationStatement := basicAttestationStatement{
		Alg: cose.COSE_ALGORITHM_ID_ES256,
		Sig: attestationSignature,
		// No attestation cert; treated as self/none.
		X5c: nil,
	}
	return MakeCredentialResponse{
		AuthData:             authData,
		FormatIdentifer:      "packed",
		AttestationStatement: attestationStatement,
	}
}

// BuildGetAssertionResponse builds a getAssertion response from components.
func BuildGetAssertionResponse(cs *identities.CredentialSource, rpID string, clientDataHash []byte, flags byte) getAssertionResponse {
	authData := MakeAuthData(rpID, cs, nil, flags)
	signature := cs.PrivateKey.Sign(util.Concat(authData, clientDataHash))
	credentialDescriptor := cs.CTAPDescriptor()
	return getAssertionResponse{
		Credential:        &credentialDescriptor,
		AuthenticatorData: authData,
		Signature:         signature,
	}
}

// DecodeMakeCredentialArgs decodes CBOR makeCredential payload.
func DecodeMakeCredentialArgs(data []byte) (MakeCredentialArgs, error) {
	var args MakeCredentialArgs
	err := cbor.Unmarshal(data, &args)
	return args, err
}

// DecodeGetAssertionArgs decodes CBOR getAssertion payload.
func DecodeGetAssertionArgs(data []byte) (GetAssertionArgs, error) {
	var args GetAssertionArgs
	err := cbor.Unmarshal(data, &args)
	return args, err
}
