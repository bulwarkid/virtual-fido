package virtual_fido

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var ctapLogger = newLogger("[CTAP] ", false)

var aaguid = [16]byte{117, 108, 90, 245, 236, 166, 1, 163, 47, 198, 211, 12, 226, 242, 1, 197}

type ctapCommand uint8

const (
	ctap_COMMAND_MAKE_CREDENTIAL    ctapCommand = 0x01
	ctap_COMMAND_GET_ASSERTION      ctapCommand = 0x02
	ctap_COMMAND_GET_INFO           ctapCommand = 0x04
	ctap_COMMAND_CLIENT_PIN         ctapCommand = 0x06
	ctap_COMMAND_RESET              ctapCommand = 0x07
	ctap_COMMAND_GET_NEXT_ASSERTION ctapCommand = 0x08
)

var ctapCommandDescriptions = map[ctapCommand]string{
	ctap_COMMAND_MAKE_CREDENTIAL:    "ctap_COMMAND_MAKE_CREDENTIAL",
	ctap_COMMAND_GET_ASSERTION:      "ctap_COMMAND_GET_ASSERTION",
	ctap_COMMAND_GET_INFO:           "ctap_COMMAND_GET_INFO",
	ctap_COMMAND_CLIENT_PIN:         "ctap_COMMAND_CLIENT_PIN",
	ctap_COMMAND_RESET:              "ctap_COMMAND_RESET",
	ctap_COMMAND_GET_NEXT_ASSERTION: "ctap_COMMAND_GET_NEXT_ASSERTION",
}

type ctapStatusCode byte

const (
	ctap1_ERR_SUCCESS           ctapStatusCode = 0x00
	ctap1_ERR_INVALID_COMMAND   ctapStatusCode = 0x01
	ctap1_ERR_INVALID_PARAMETER ctapStatusCode = 0x02
	ctap1_ERR_INVALID_LENGTH    ctapStatusCode = 0x03
	ctap1_ERR_INVALID_SEQ       ctapStatusCode = 0x04
	ctap1_ERR_TIMEOUT           ctapStatusCode = 0x05
	ctap1_ERR_CHANNEL_BUSY      ctapStatusCode = 0x06

	ctap2_ERR_UNSUPPORTED_ALGORITHM ctapStatusCode = 0x26
	ctap2_ERR_INVALID_CBOR          ctapStatusCode = 0x12
	ctap2_ERR_NO_CREDENTIALS        ctapStatusCode = 0x2E
	ctap2_ERR_OPERATION_DENIED      ctapStatusCode = 0x27
)

type coseAlgorithmID int32

const (
	cose_ALGORITHM_ID_ES256 coseAlgorithmID = -7
)

type PublicKeyCredentialRpEntity struct {
	Id   string `cbor:"id"`
	Name string `cbor:"name"`
}

func (rp PublicKeyCredentialRpEntity) String() string {
	return fmt.Sprintf("RpEntity{ ID: %s, Name: %s }",
		rp.Id, rp.Name)
}

type PublicKeyCrendentialUserEntity struct {
	Id          []byte `cbor:"id"`
	DisplayName string `cbor:"displayName"`
	Name        string `cbor:"name"`
}

func (user PublicKeyCrendentialUserEntity) String() string {
	return fmt.Sprintf("User{ ID: %s, DisplayName: %s, Name: %s }",
		hex.EncodeToString(user.Id),
		user.DisplayName,
		user.Name)
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `cbor:"type"`
	Id         []byte   `cbor:"id"`
	Transports []string `cbor:"transports,omitempty"`
}

type PublicKeyCredentialParams struct {
	Type      string          `cbor:"type"`
	Algorithm coseAlgorithmID `cbor:"alg"`
}

type ctapCommandOptions struct {
	ResidentKey      bool `cbor:"rk,omitempty"`
	UserVerification bool `cbor:"uv,omitempty"`
	UserPresence     bool `cbor:"up,omitempty"`
}

type ctapCOSEPublicKey struct {
	Kty int8   `cbor:"1,keyasint"`
	Alg int8   `cbor:"3,keyasint"`
	Crv int8   `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func ctapEncodeKeyAsCOSE(publicKey *ecdsa.PublicKey) []byte {
	key := ctapCOSEPublicKey{
		Kty: 2,
		Alg: int8(cose_ALGORITHM_ID_ES256),
		Crv: 1,
		X:   publicKey.X.Bytes(),
		Y:   publicKey.Y.Bytes(),
	}
	keyBytes, err := cbor.Marshal(key)
	checkErr(err, "Could not encode public key in COSE CBOR")
	return keyBytes
}

const (
	ctap_AUTH_DATA_FLAG_USER_PRESENT            uint8 = 0b00000001
	ctap_AUTH_DATA_FLAG_USER_VERIFIED           uint8 = 0b00000100
	ctap_AUTH_DATA_FLAG_ATTESTED_DATA_INCLUDED  uint8 = 0b01000000
	ctap_AUTH_DATA_FLAG_EXTENSION_DATA_INCLUDED uint8 = 0b10000000
)

type ctapAttestedCredentialData struct {
	AAGUID             []byte
	CredentialIDLength uint16
	CredentialID       []byte
	EncodedPublicKey   []byte
}

type ctapAuthData struct {
	RelyingPartyIDHash     []byte
	Flags                  uint8
	AttestedCredentialData *ctapAttestedCredentialData
}

func ctapMakeAttestedCredentialData(credentialSource *CredentialSource) []byte {
	encodedCredentialPublicKey := ctapEncodeKeyAsCOSE(&credentialSource.PrivateKey.PublicKey)
	return flatten([][]byte{aaguid[:], toBE(uint16(len(credentialSource.ID))), credentialSource.ID, encodedCredentialPublicKey})
}

func ctapMakeAuthData(rpID string, credentialSource *CredentialSource, attestedCredentialData []byte) []byte {
	rpIdHash := sha256.Sum256([]byte(rpID))
	// TODO: Set flags according to actual user presence
	flags := ctap_AUTH_DATA_FLAG_USER_PRESENT
	if attestedCredentialData != nil {
		flags = flags | ctap_AUTH_DATA_FLAG_ATTESTED_DATA_INCLUDED
	} else {
		attestedCredentialData = []byte{}
	}
	return flatten([][]byte{rpIdHash[:], {flags}, toBE(credentialSource.SignatureCounter), attestedCredentialData})
}

type ctapServer struct {
	client FIDOClient
}

func newCTAPServer(client FIDOClient) *ctapServer {
	return &ctapServer{client: client}
}

func (server *ctapServer) handleMessage(data []byte) []byte {
	command := ctapCommand(data[0])
	ctapLogger.Printf("CTAP COMMAND: %s\n\n", ctapCommandDescriptions[command])
	switch command {
	case ctap_COMMAND_MAKE_CREDENTIAL:
		return server.handleMakeCredential(data[1:])
	case ctap_COMMAND_GET_INFO:
		return server.handleGetInfo(data[1:])
	case ctap_COMMAND_GET_ASSERTION:
		return server.handleGetAssertion(data[1:])
	case ctap_COMMAND_CLIENT_PIN:
		return server.handleClientPIN(data[1:])
	default:
		panic(fmt.Sprintf("Invalid CTAP Command: %d", command))
	}
}

type ctapMakeCredentialArgs struct {
	ClientDataHash   []byte                          `cbor:"1,keyasint,omitempty"`
	Rp               PublicKeyCredentialRpEntity     `cbor:"2,keyasint,omitempty"`
	User             PublicKeyCrendentialUserEntity  `cbor:"3,keyasint,omitempty"`
	PubKeyCredParams []PublicKeyCredentialParams     `cbor:"4,keyasint,omitempty"`
	ExcludeList      []PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Options          *ctapCommandOptions             `cbor:"7,keyasint,omitempty"`
}

func (args ctapMakeCredentialArgs) String() string {
	return fmt.Sprintf("ctapMakeCredentialArgs{ ClientDataHash: 0x%s, Relying Party: %s, User: %s, PublicKeyCredentialParams: %#v, ExcludeList: %#v, Options: %#v }",
		hex.EncodeToString(args.ClientDataHash),
		args.Rp,
		args.User,
		args.PubKeyCredParams,
		args.ExcludeList,
		args.Options)
}

type ctapMakeCredentialReponse struct {
	FormatIdentifer      string                      `cbor:"1,keyasint"`
	AuthData             []byte                      `cbor:"2,keyasint"`
	AttestationStatement map[interface{}]interface{} `cbor:"3,keyasint"`
}

func (server *ctapServer) handleMakeCredential(data []byte) []byte {
	var args ctapMakeCredentialArgs
	err := cbor.Unmarshal(data, &args)
	checkErr(err, fmt.Sprintf("Could not decode CBOR for MAKE_CREDENTIAL: %s %v", err, data))
	ctapLogger.Printf("MAKE CREDENTIAL: %s\n\n", args)

	supported := false
	for _, param := range args.PubKeyCredParams {
		if param.Algorithm == cose_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
		}
	}
	if !supported {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return []byte{byte(ctap2_ERR_UNSUPPORTED_ALGORITHM)}
	}

	// TODO: Verify user identity (e.g. PIN, password)
	if !server.client.ApproveAccountCreation(args.Rp.Name) {
		ctapLogger.Printf("ERROR: Unapproved action (Create account)")
		return []byte{byte(ctap2_ERR_OPERATION_DENIED)}
	}

	credentialSource := server.client.NewCredentialSource(args.Rp, args.User)
	attestedCredentialData := ctapMakeAttestedCredentialData(credentialSource)
	authenticatorData := ctapMakeAuthData(args.Rp.Id, credentialSource, attestedCredentialData)

	// TODO: Add support for attestation to response
	response := ctapMakeCredentialReponse{
		AuthData:             authenticatorData,
		FormatIdentifer:      "none",
		AttestationStatement: make(map[interface{}]interface{}),
	}
	responseBytes, err := cbor.Marshal(response)
	checkErr(err, "Could not encode MakeAssertion response in CBOR")
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, responseBytes...)
}

type ctapGetInfoOptions struct {
	IsPlatform     bool `cbor:"plat,omitempty"`
	CanResidentKey bool `cbor:"rk,omitempty"`
	//CanClientPin        bool `cbor:"clientPin,omitempty"`
	CanUserPresence     bool `cbor:"up,omitempty"`
	CanUserVerification bool `cbor:"uv,omitempty"`
}

type ctapGetInfoResponse struct {
	Versions []string `cbor:"1,keyasint,omitempty"`
	//Extensions []string `cbor:"2,keyasint,omitempty"`
	AAGUID  [16]byte           `cbor:"3,keyasint,omitempty"`
	Options ctapGetInfoOptions `cbor:"4,keyasint,omitempty"`
	//MaxMessageSize uint32   `cbor:"5,keyasint,omitempty"`
	//PinProtocols   []uint32 `cbor:"6,keyasint,omitempty"`
}

func (server *ctapServer) handleGetInfo(data []byte) []byte {
	response := ctapGetInfoResponse{
		Versions: []string{"FIDO_2_0", "U2F_V2"},
		AAGUID:   aaguid,
		Options: ctapGetInfoOptions{
			IsPlatform:          false,
			CanResidentKey:      true,
			CanUserPresence:     true,
			CanUserVerification: true,
		},
	}
	responseBytes, err := cbor.Marshal(response)
	checkErr(err, "Could not encode GET_INFO in CBOR")
	ctapLogger.Printf("CTAP GET_INFO RESPONSE: %v\n\n", responseBytes)
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, responseBytes...)
}

type ctapGetAssertionArgs struct {
	RpID           string                          `cbor:"1,keyasint"`
	ClientDataHash []byte                          `cbor:"2,keyasint"`
	AllowList      []PublicKeyCredentialDescriptor `cbor:"3,keyasint"`
	Options        ctapCommandOptions              `cbor:"5,keyasint"`
}

type ctapGetAssertionResponse struct {
	//Credential          *PublicKeyCredentialDescriptor  `cbor:"1,keyasint,omitempty"`
	AuthenticatorData []byte `cbor:"2,keyasint"`
	Signature         []byte `cbor:"3,keyasint"`
	//User                *PublicKeyCrendentialUserEntity `cbor:"4,keyasint,omitempty"`
	//NumberOfCredentials int32 `cbor:"5,keyasint"`
}

func (server *ctapServer) handleGetAssertion(data []byte) []byte {
	var args ctapGetAssertionArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2_ERR_INVALID_CBOR)}
	}
	ctapLogger.Printf("GET ASSERTION: %#v\n\n", args)
	credentialSource := server.client.GetAssertionSource(args.RpID, args.AllowList)
	if credentialSource == nil {
		ctapLogger.Printf("ERROR: No Credentials\n\n")
		return []byte{byte(ctap2_ERR_NO_CREDENTIALS)}
	}

	if args.Options.UserPresence {
		if !server.client.ApproveAccountLogin(credentialSource) {
			ctapLogger.Printf("ERROR: Unapproved action (Account login)")
			return []byte{byte(ctap2_ERR_OPERATION_DENIED)}
		}
	}

	authData := ctapMakeAuthData(args.RpID, credentialSource, nil)
	signature := sign(credentialSource.PrivateKey, flatten([][]byte{authData, args.ClientDataHash}))

	response := ctapGetAssertionResponse{
		//Credential:          credentialSource.ctapDescriptor(),
		AuthenticatorData: authData,
		Signature:         signature,
		//User:                credentialSource.User,
		//NumberOfCredentials: 1,
	}
	responseBytes, err := cbor.Marshal(response)
	checkErr(err, "Could not encode response in CBOR")

	ctapLogger.Printf("RESPONSE: %v\n\n", responseBytes)

	return append([]byte{byte(ctap1_ERR_SUCCESS)}, responseBytes...)
}

type ctapClientPINArgs struct {
	PinProtocol     uint32            `cbor:"1,keyasint"`
	SubCommand      uint32            `cbor:"2,keyasint"`
	KeyAgreement    ctapCOSEPublicKey `cbor:"3,keyasint"`
	PINAuth         []byte            `cbor:"4,keyasint"`
	NewPINEncoding  []byte            `cbor:"5,keyasint"`
	PINHashEncoding []byte            `cbor:"6,keyasint"`
}

func (server *ctapServer) handleClientPIN(data []byte) []byte {
	var args ctapClientPINArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2_ERR_INVALID_CBOR)}
	}
	return nil
}
