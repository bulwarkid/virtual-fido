package ctap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"

	"github.com/fxamacker/cbor/v2"
)

var ctapLogger = util.NewLogger("[CTAP] ", util.LogLevelDebug)
var unsafeCtapLogger = util.NewLogger("[CTAP] ", util.LogLevelUnsafe)

var aaguid = [16]byte{117, 108, 90, 245, 236, 166, 1, 163, 47, 198, 211, 12, 226, 242, 1, 197}

type CTAPCommand uint8

const (
	CTAP_COMMAND_MAKE_CREDENTIAL    CTAPCommand = 0x01
	CTAP_COMMAND_GET_ASSERTION      CTAPCommand = 0x02
	CTAP_COMMAND_GET_INFO           CTAPCommand = 0x04
	CTAP_COMMAND_CLIENT_PIN         CTAPCommand = 0x06
	CTAP_COMMAND_RESET              CTAPCommand = 0x07
	CTAP_COMMAND_GET_NEXT_ASSERTION CTAPCommand = 0x08
)

var CTAPCommandDescriptions = map[CTAPCommand]string{
	CTAP_COMMAND_MAKE_CREDENTIAL:    "CTAP_COMMAND_MAKE_CREDENTIAL",
	CTAP_COMMAND_GET_ASSERTION:      "CTAP_COMMAND_GET_ASSERTION",
	CTAP_COMMAND_GET_INFO:           "CTAP_COMMAND_GET_INFO",
	CTAP_COMMAND_CLIENT_PIN:         "CTAP_COMMAND_CLIENT_PIN",
	CTAP_COMMAND_RESET:              "CTAP_COMMAND_RESET",
	CTAP_COMMAND_GET_NEXT_ASSERTION: "CTAP_COMMAND_GET_NEXT_ASSERTION",
}

type CTAPStatusCode byte

const (
	CTAP1_ERR_SUCCESS           CTAPStatusCode = 0x00
	CTAP1_ERR_INVALID_COMMAND   CTAPStatusCode = 0x01
	CTAP1_ERR_INVALID_PARAMETER CTAPStatusCode = 0x02
	CTAP1_ERR_INVALID_LENGTH    CTAPStatusCode = 0x03
	CTAP1_ERR_INVALID_SEQ       CTAPStatusCode = 0x04
	CTAP1_ERR_TIMEOUT           CTAPStatusCode = 0x05
	CTAP1_ERR_CHANNEL_BUSY      CTAPStatusCode = 0x06

	CTAP2_ERR_UNSUPPORTED_ALGORITHM CTAPStatusCode = 0x26
	CTAP2_ERR_INVALID_CBOR          CTAPStatusCode = 0x12
	CTAP2_ERR_NO_CREDENTIALS        CTAPStatusCode = 0x2E
	CTAP2_ERR_OPERATION_DENIED      CTAPStatusCode = 0x27
	CTAP2_ERR_MISSING_PARAM         CTAPStatusCode = 0x14
	CTAP2_ERR_PIN_INVALID           CTAPStatusCode = 0x31
	CTAP2_ERR_PIN_BLOCKED           CTAPStatusCode = 0x32
	CTAP2_ERR_PIN_AUTH_INVALID      CTAPStatusCode = 0x33
	CTAP2_ERR_NO_PIN_SET            CTAPStatusCode = 0x35
	CTAP2_ERR_PIN_REQUIRED          CTAPStatusCode = 0x36
	CTAP2_ERR_PIN_POLICY_VIOLATION  CTAPStatusCode = 0x37
	CTAP2_ERR_PIN_EXPIRED           CTAPStatusCode = 0x38
)

type CTAPCommandOptions struct {
	ResidentKey      bool `cbor:"rk,omitempty"`
	UserVerification bool `cbor:"uv,omitempty"`
	UserPresence     *bool `cbor:"up,omitempty"`
}

const (
	CTAP_AUTH_DATA_FLAG_USER_PRESENT            uint8 = 0b00000001
	CTAP_AUTH_DATA_FLAG_USER_VERIFIED           uint8 = 0b00000100
	CTAP_AUTH_DATA_FLAG_ATTESTED_DATA_INCLUDED  uint8 = 0b01000000
	CTAP_AUTH_DATA_FLAG_EXTENSION_DATA_INCLUDED uint8 = 0b10000000
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

type ctapSelfAttestationStatement struct {
	Alg cose.COSEAlgorithmID `cbor:"alg"`
	Sig []byte               `cbor:"sig"`
}

type ctapBasicAttestationStatement struct {
	Alg cose.COSEAlgorithmID `cbor:"alg"`
	Sig []byte               `cbor:"sig"`
	X5c [][]byte             `cbor:"x5c"`
}

func ctapMakeAttestedCredentialData(credentialSource *identities.CredentialSource) []byte {
	encodedCredentialPublicKey := cose.EncodeKeyAsCOSE(&credentialSource.PrivateKey.PublicKey)
	return util.Flatten([][]byte{aaguid[:], util.ToBE(uint16(len(credentialSource.ID))), credentialSource.ID, encodedCredentialPublicKey})
}

func ctapMakeAuthData(rpID string, credentialSource *identities.CredentialSource, attestedCredentialData []byte, flags uint8) []byte {
	if attestedCredentialData != nil {
		flags = flags | CTAP_AUTH_DATA_FLAG_ATTESTED_DATA_INCLUDED
	} else {
		attestedCredentialData = []byte{}
	}
	rpIdHash := sha256.Sum256([]byte(rpID))
	return util.Flatten([][]byte{rpIdHash[:], {flags}, util.ToBE(credentialSource.SignatureCounter), attestedCredentialData})
}

type CTAPClient interface {
	NewCredentialSource(relyingParty webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource
	GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource

	CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte

	SupportsPIN() bool
	PINHash() []byte
	SetPINHash(pin []byte)
	PINRetries() int32
	SetPINRetries(retries int32)
	PINKeyAgreement() *crypto.ECDHKey
	PINToken() []byte

	ApproveAccountCreation(relyingParty string) bool
	ApproveAccountLogin(credentialSource *identities.CredentialSource) bool
}

type CTAPServer struct {
	client CTAPClient
}

func NewCTAPServer(client CTAPClient) *CTAPServer {
	return &CTAPServer{client: client}
}

func (server *CTAPServer) HandleMessage(data []byte) []byte {
	command := CTAPCommand(data[0])
	ctapLogger.Printf("CTAP COMMAND: %s\n\n", CTAPCommandDescriptions[command])
	switch command {
	case CTAP_COMMAND_MAKE_CREDENTIAL:
		return server.handleMakeCredential(data[1:])
	case CTAP_COMMAND_GET_INFO:
		return server.handleGetInfo(data[1:])
	case CTAP_COMMAND_GET_ASSERTION:
		return server.handleGetAssertion(data[1:])
	case CTAP_COMMAND_CLIENT_PIN:
		return server.handleClientPIN(data[1:])
	default:
		panic(fmt.Sprintf("Invalid CTAP Command: %d", command))
	}
}

type ctapMakeCredentialArgs struct {
	ClientDataHash   []byte                                   `cbor:"1,keyasint,omitempty"`
	Rp               webauthn.PublicKeyCredentialRpEntity     `cbor:"2,keyasint,omitempty"`
	User             webauthn.PublicKeyCrendentialUserEntity  `cbor:"3,keyasint,omitempty"`
	PubKeyCredParams []webauthn.PublicKeyCredentialParams     `cbor:"4,keyasint,omitempty"`
	ExcludeList      []webauthn.PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Options          *CTAPCommandOptions                      `cbor:"7,keyasint,omitempty"`
	PinAuth          []byte                                   `cbor:"8,keyasint,omitempty"`
	PinProtocol      uint32                                   `cbor:"9,keyasint,omitempty"`
}

func (args ctapMakeCredentialArgs) String() string {
	return fmt.Sprintf("ctapMakeCredentialArgs{ ClientDataHash: 0x%s, Relying Party: %s, User: %s, PublicKeyCredentialParams: %#v, ExcludeList: %#v, Options: %#v, PinAuth: %#v, PinProtocol: %d }",
		hex.EncodeToString(args.ClientDataHash),
		args.Rp,
		args.User,
		args.PubKeyCredParams,
		args.ExcludeList,
		args.Options,
		args.PinAuth,
		args.PinProtocol,
	)
}

type ctapMakeCredentialReponse struct {
	FormatIdentifer      string                        `cbor:"1,keyasint"`
	AuthData             []byte                        `cbor:"2,keyasint"`
	AttestationStatement ctapBasicAttestationStatement `cbor:"3,keyasint"`
}

func (server *CTAPServer) handleMakeCredential(data []byte) []byte {
	var args ctapMakeCredentialArgs
	err := cbor.Unmarshal(data, &args)
	util.CheckErr(err, fmt.Sprintf("Could not decode CBOR for MAKE_CREDENTIAL: %s %v", err, data))
	ctapLogger.Printf("MAKE CREDENTIAL: %s\n\n", args)
	var flags uint8 = 0

	supported := false
	for _, param := range args.PubKeyCredParams {
		if param.Algorithm == cose.COSE_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
		}
	}
	if !supported {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return []byte{byte(CTAP2_ERR_UNSUPPORTED_ALGORITHM)}
	}

	if server.client.SupportsPIN() {
		if args.PinProtocol == 1 && args.PinAuth != nil {
			pinAuth := server.derivePINAuth(server.client.PINToken(), args.ClientDataHash)
			if !bytes.Equal(pinAuth, args.PinAuth) {
				return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
			}
			flags = flags | CTAP_AUTH_DATA_FLAG_USER_VERIFIED
		} else if args.PinAuth == nil && server.client.PINHash() != nil {
			return []byte{byte(CTAP2_ERR_PIN_REQUIRED)}
		} else if args.PinAuth != nil && args.PinProtocol != 1 {
			return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
		}
	}

	if !server.client.ApproveAccountCreation(args.Rp.Name) {
		ctapLogger.Printf("ERROR: Unapproved action (Create account)")
		return []byte{byte(CTAP2_ERR_OPERATION_DENIED)}
	}
	flags = flags | CTAP_AUTH_DATA_FLAG_USER_PRESENT

	credentialSource := server.client.NewCredentialSource(args.Rp, args.User)
	attestedCredentialData := ctapMakeAttestedCredentialData(credentialSource)
	authenticatorData := ctapMakeAuthData(args.Rp.Id, credentialSource, attestedCredentialData, flags)

	attestationCert := server.client.CreateAttestationCertificiate(credentialSource.PrivateKey)
	attestationSignature := crypto.Sign(credentialSource.PrivateKey, append(authenticatorData, args.ClientDataHash...))
	attestationStatement := ctapBasicAttestationStatement{
		Alg: cose.COSE_ALGORITHM_ID_ES256,
		Sig: attestationSignature,
		X5c: [][]byte{attestationCert},
	}

	response := ctapMakeCredentialReponse{
		AuthData:             authenticatorData,
		FormatIdentifer:      "packed",
		AttestationStatement: attestationStatement,
	}
	ctapLogger.Printf("MAKE CREDENTIAL RESPONSE: %#v\n\n", response)
	return append([]byte{byte(CTAP1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

type ctapGetInfoOptions struct {
	IsPlatform      bool `cbor:"plat"`
	CanResidentKey  bool `cbor:"rk"`
	HasClientPIN    *bool `cbor:"clientPin,omitempty"`
	CanUserPresence bool `cbor:"up"`
	// CanUserVerification bool `cbor:"uv"`
}

type ctapGetInfoResponse struct {
	Versions []string `cbor:"1,keyasint,omitempty"`
	//Extensions []string `cbor:"2,keyasint,omitempty"`
	AAGUID  [16]byte           `cbor:"3,keyasint,omitempty"`
	Options ctapGetInfoOptions `cbor:"4,keyasint,omitempty"`
	//MaxMessageSize uint32   `cbor:"5,keyasint,omitempty"`
	PinProtocols []uint32 `cbor:"6,keyasint,omitempty"`
}

func (server *CTAPServer) handleGetInfo(data []byte) []byte {
	response := ctapGetInfoResponse{
		Versions: []string{"FIDO_2_0", "U2F_V2"},
		AAGUID:   aaguid,
		Options: ctapGetInfoOptions{
			IsPlatform:      false,
			CanResidentKey:  true,
			CanUserPresence: true,
			// CanUserVerification: true,
		},
	}
	if server.client.SupportsPIN() {
		*response.Options.HasClientPIN = server.client.PINHash() != nil
		response.PinProtocols = []uint32{1}
	}
	ctapLogger.Printf("GET_INFO RESPONSE: %#v\n\n", response)
	return append([]byte{byte(CTAP1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

type ctapGetAssertionArgs struct {
	RpID           string                                   `cbor:"1,keyasint"`
	ClientDataHash []byte                                   `cbor:"2,keyasint"`
	AllowList      []webauthn.PublicKeyCredentialDescriptor `cbor:"3,keyasint"`
	Options        CTAPCommandOptions                       `cbor:"5,keyasint"`
	PinAuth        []byte                                   `cbor:"6,keyasint,omitempty"`
	PinProtocol    uint32                                   `cbor:"7,keyasint,omitempty"`
}

type ctapGetAssertionResponse struct {
	Credential        *webauthn.PublicKeyCredentialDescriptor `cbor:"1,keyasint,omitempty"`
	AuthenticatorData []byte                                  `cbor:"2,keyasint"`
	Signature         []byte                                  `cbor:"3,keyasint"`
	//User                *PublicKeyCrendentialUserEntity `cbor:"4,keyasint,omitempty"`
	//NumberOfCredentials int32 `cbor:"5,keyasint"`
}

func (server *CTAPServer) handleGetAssertion(data []byte) []byte {
	var flags uint8 = 0
	var args ctapGetAssertionArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(CTAP2_ERR_INVALID_CBOR)}
	}
	ctapLogger.Printf("GET ASSERTION: %#v\n\n", args)

	if server.client.SupportsPIN() {
		if args.PinAuth != nil {
			if args.PinProtocol != 1 {
				return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
			}
			pinAuth := server.derivePINAuth(server.client.PINToken(), args.ClientDataHash)
			if !bytes.Equal(pinAuth, args.PinAuth) {
				return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
			}
			flags = flags | CTAP_AUTH_DATA_FLAG_USER_VERIFIED
		}
	}

	credentialSource := server.client.GetAssertionSource(args.RpID, args.AllowList)
	unsafeCtapLogger.Printf("CREDENTIAL SOURCE: %#v\n\n", credentialSource)
	if credentialSource == nil {
		ctapLogger.Printf("ERROR: No Credentials\n\n")
		return []byte{byte(CTAP2_ERR_NO_CREDENTIALS)}
	}

	if args.Options.UserPresence == nil || *args.Options.UserPresence {
		if !server.client.ApproveAccountLogin(credentialSource) {
			ctapLogger.Printf("ERROR: Unapproved action (Account login)")
			return []byte{byte(CTAP2_ERR_OPERATION_DENIED)}
		}
		flags = flags | CTAP_AUTH_DATA_FLAG_USER_PRESENT
	}

	authData := ctapMakeAuthData(args.RpID, credentialSource, nil, flags)
	signature := crypto.Sign(credentialSource.PrivateKey, util.Flatten([][]byte{authData, args.ClientDataHash}))

	credentialDescriptor := credentialSource.CTAPDescriptor()
	response := ctapGetAssertionResponse{
		Credential:        &credentialDescriptor,
		AuthenticatorData: authData,
		Signature:         signature,
		//User:                credentialSource.User,
		//NumberOfCredentials: 1,
	}

	ctapLogger.Printf("GET ASSERTION RESPONSE: %#v\n\n", response)

	return append([]byte{byte(CTAP1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

type ctapClientPINSubcommand uint32

const (
	CTAP_CLIENT_PIN_SUBCOMMAND_GET_RETRIES       ctapClientPINSubcommand = 1
	CTAP_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT ctapClientPINSubcommand = 2
	CTAP_CLIENT_PIN_SUBCOMMAND_SET_PIN           ctapClientPINSubcommand = 3
	CTAP_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN        ctapClientPINSubcommand = 4
	CTAP_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN     ctapClientPINSubcommand = 5
)

var ctapClientPINSubcommandDescriptions = map[ctapClientPINSubcommand]string{
	CTAP_CLIENT_PIN_SUBCOMMAND_GET_RETRIES:       "CTAP_CLIENT_PIN_SUBCOMMAND_GET_RETRIES",
	CTAP_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT: "CTAP_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT",
	CTAP_CLIENT_PIN_SUBCOMMAND_SET_PIN:           "CTAP_CLIENT_PIN_SUBCOMMAND_SET_PIN",
	CTAP_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN:        "CTAP_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN",
	CTAP_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN:     "CTAP_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN",
}

type ctapClientPINArgs struct {
	PinProtocol     uint32                  `cbor:"1,keyasint"`
	SubCommand      ctapClientPINSubcommand `cbor:"2,keyasint"`
	KeyAgreement    *cose.COSEPublicKey     `cbor:"3,keyasint,omitempty"`
	PINAuth         []byte                  `cbor:"4,keyasint,omitempty"`
	NewPINEncoding  []byte                  `cbor:"5,keyasint,omitempty"`
	PINHashEncoding []byte                  `cbor:"6,keyasint,omitempty"`
}

func (args ctapClientPINArgs) String() string {
	return fmt.Sprintf("ctapClientPINArgs{PinProtocol: %d, SubCommand: %s, KeyAgreement: %v, PINAuth: 0x%s, NewPINEncoding: 0x%s, PINHashEncoding: 0x%s}",
		args.PinProtocol,
		ctapClientPINSubcommandDescriptions[args.SubCommand],
		args.KeyAgreement,
		hex.EncodeToString(args.PINAuth),
		hex.EncodeToString(args.NewPINEncoding),
		hex.EncodeToString(args.PINHashEncoding))
}

type ctapClientPINResponse struct {
	KeyAgreement *cose.COSEPublicKey `cbor:"1,keyasint,omitempty"`
	PinToken     []byte              `cbor:"2,keyasint,omitempty"`
	Retries      *uint8              `cbor:"3,keyasint,omitempty"`
}

func (args ctapClientPINResponse) String() string {
	return fmt.Sprintf("ctapClientPINResponse{KeyAgreement: %s, PinToken: %s, Retries: %#v}",
		args.KeyAgreement,
		hex.EncodeToString(args.PinToken),
		args.Retries)
}

func (server *CTAPServer) getPINSharedSecret(remoteKey cose.COSEPublicKey) []byte {
	pinKey := server.client.PINKeyAgreement()
	return crypto.HashSHA256(pinKey.ECDH(util.BytesToBigInt(remoteKey.X), util.BytesToBigInt(remoteKey.Y)))
}

func (server *CTAPServer) derivePINAuth(sharedSecret []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, sharedSecret)
	hash.Write(data)
	return hash.Sum(nil)[:16]
}

func (server *CTAPServer) decryptPINHash(sharedSecret []byte, pinHashEncoding []byte) []byte {
	return crypto.DecryptAESCBC(sharedSecret, pinHashEncoding)
}

func (server *CTAPServer) decryptPIN(sharedSecret []byte, pinEncoding []byte) []byte {
	decryptedPINPadded := crypto.DecryptAESCBC(sharedSecret, pinEncoding)
	var decryptedPIN []byte = nil
	for i := range decryptedPINPadded {
		if decryptedPINPadded[i] == 0 {
			decryptedPIN = decryptedPINPadded[:i]
			break
		}
	}
	return decryptedPIN
}

func (server *CTAPServer) handleClientPIN(data []byte) []byte {
	if !server.client.SupportsPIN() {
		return []byte{byte(CTAP1_ERR_INVALID_COMMAND)}
	}
	var args ctapClientPINArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(CTAP2_ERR_INVALID_CBOR)}
	}
	if args.PinProtocol != 1 {
		return []byte{byte(CTAP1_ERR_INVALID_PARAMETER)}
	}
	ctapLogger.Printf("CLIENT_PIN: %v\n\n", args)
	var response []byte
	switch args.SubCommand {
	case CTAP_CLIENT_PIN_SUBCOMMAND_GET_RETRIES:
		response = server.handleGetRetries()
	case CTAP_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT:
		response = server.handleGetKeyAgreement(args)
	case CTAP_CLIENT_PIN_SUBCOMMAND_SET_PIN:
		response = server.handleSetPIN(args)
	case CTAP_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN:
		response = server.handleChangePIN(args)
	case CTAP_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN:
		response = server.handleGetPINToken(args)
	default:
		return []byte{byte(CTAP2_ERR_MISSING_PARAM)}
	}
	ctapLogger.Printf("CLIENT_PIN RESPONSE: %#v\n\n", response)
	return response
}

func (server *CTAPServer) handleGetRetries() []byte {
	retries := uint8(server.client.PINRetries())
	response := ctapClientPINResponse{
		Retries: &retries,
	}
	ctapLogger.Printf("CLIENT_PIN_GET_RETRIES: %v\n\n", response)
	return append([]byte{byte(CTAP1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

func (server *CTAPServer) handleGetKeyAgreement(args ctapClientPINArgs) []byte {
	key := server.client.PINKeyAgreement()
	response := ctapClientPINResponse{
		KeyAgreement: &cose.COSEPublicKey{
			KeyType:   int8(cose.COSE_KEY_TYPE_EC2),
			Algorithm: int8(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256),
			X:         key.X.Bytes(),
			Y:         key.Y.Bytes(),
		},
	}
	ctapLogger.Printf("CLIENT_PIN_GET_KEY_AGREEMENT RESPONSE: %#v\n\n", response)
	return append([]byte{byte(CTAP1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

func (server *CTAPServer) handleSetPIN(args ctapClientPINArgs) []byte {
	if server.client.PINHash() != nil {
		return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
	}
	if args.KeyAgreement == nil || args.PINAuth == nil || args.NewPINEncoding == nil {
		return []byte{byte(CTAP2_ERR_MISSING_PARAM)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	pinAuth := server.derivePINAuth(sharedSecret, args.NewPINEncoding)
	if !bytes.Equal(pinAuth, args.PINAuth) {
		return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
	}
	decryptedPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(decryptedPIN) < 4 {
		return []byte{byte(CTAP2_ERR_PIN_POLICY_VIOLATION)}
	}
	pinHash := crypto.HashSHA256(decryptedPIN)[:16]
	server.client.SetPINRetries(8)
	server.client.SetPINHash(pinHash)
	ctapLogger.Printf("SETTING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	return []byte{byte(CTAP1_ERR_SUCCESS)}
}

func (server *CTAPServer) handleChangePIN(args ctapClientPINArgs) []byte {
	if args.KeyAgreement == nil || args.PINAuth == nil {
		return []byte{byte(CTAP2_ERR_MISSING_PARAM)}
	}
	if server.client.PINRetries() == 0 {
		return []byte{byte(CTAP2_ERR_PIN_BLOCKED)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	pinAuth := server.derivePINAuth(sharedSecret, append(args.NewPINEncoding, args.PINHashEncoding...))
	if !bytes.Equal(pinAuth, args.PINAuth) {
		return []byte{byte(CTAP2_ERR_PIN_AUTH_INVALID)}
	}
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	decryptedPINHash := crypto.DecryptAESCBC(sharedSecret, args.PINHashEncoding)
	if !bytes.Equal(server.client.PINHash(), decryptedPINHash) {
		// TODO: Mismatch detected, handle it
		return []byte{byte(CTAP2_ERR_PIN_INVALID)}
	}
	server.client.SetPINRetries(8)
	newPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(newPIN) < 4 {
		return []byte{byte(CTAP2_ERR_PIN_POLICY_VIOLATION)}
	}
	pinHash := crypto.HashSHA256(newPIN)[:16]
	server.client.SetPINHash(pinHash)
	return []byte{byte(CTAP1_ERR_SUCCESS)}
}

func (server *CTAPServer) handleGetPINToken(args ctapClientPINArgs) []byte {
	if args.PINHashEncoding == nil || args.KeyAgreement.X == nil {
		return []byte{byte(CTAP2_ERR_MISSING_PARAM)}
	}
	if server.client.PINRetries() <= 0 {
		return []byte{byte(CTAP2_ERR_PIN_BLOCKED)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	pinHash := server.decryptPINHash(sharedSecret, args.PINHashEncoding)
	ctapLogger.Printf("TRYING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	if !bytes.Equal(pinHash, server.client.PINHash()) {
		// TODO: Handle mismatch here by regening the key agreement key
		ctapLogger.Printf("MISMATCH: Provided PIN %v doesn't match stored PIN %v\n\n", hex.EncodeToString(pinHash), hex.EncodeToString(server.client.PINHash()))
		return []byte{byte(CTAP2_ERR_PIN_INVALID)}
	}
	server.client.SetPINRetries(8)
	response := ctapClientPINResponse{
		PinToken: crypto.EncryptAESCBC(sharedSecret, server.client.PINToken()),
	}
	ctapLogger.Printf("GET_PIN_TOKEN RESPONSE: %#v\n\n", response)
	return append([]byte{byte(CTAP1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}
