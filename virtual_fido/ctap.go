package virtual_fido

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	util "github.com/bulwarkid/virtual-fido/virtual_fido/util"
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
	ctap2_ERR_MISSING_PARAM         ctapStatusCode = 0x14
	ctap2_ERR_PIN_INVALID           ctapStatusCode = 0x31
	ctap2_ERR_PIN_BLOCKED           ctapStatusCode = 0x32
	ctap2_ERR_PIN_AUTH_INVALID      ctapStatusCode = 0x33
	ctap2_ERR_NO_PIN_SET            ctapStatusCode = 0x35
	ctap2_ERR_PIN_REQUIRED          ctapStatusCode = 0x36
	ctap2_ERR_PIN_POLICY_VIOLATION  ctapStatusCode = 0x37
	ctap2_ERR_PIN_EXPIRED           ctapStatusCode = 0x38
)

type coseAlgorithmID int32

const (
	cose_ALGORITHM_ID_ES256         coseAlgorithmID = -7
	cose_ALGORITHM_ID_ECDH_HKDF_256 coseAlgorithmID = -25
)

type coseCurveID int32

const (
	cose_CURVE_ID_P256 coseCurveID = 1
)

type coseKeyType int32

const (
	cose_KEY_TYPE_OKP       coseKeyType = 0b001
	cose_KEY_TYPE_EC2       coseKeyType = 0b010
	cose_KEY_TYPE_SYMMETRIC coseKeyType = 0b100
)

type PublicKeyCredentialRpEntity struct {
	Id   string `cbor:"id" json:"id"`
	Name string `cbor:"name" json:"name"`
}

func (rp PublicKeyCredentialRpEntity) String() string {
	return fmt.Sprintf("RpEntity{ ID: %s, Name: %s }",
		rp.Id, rp.Name)
}

type PublicKeyCrendentialUserEntity struct {
	Id          []byte `cbor:"id" json:"id"`
	DisplayName string `cbor:"displayName" json:"display_name"`
	Name        string `cbor:"name" json:"name"`
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
	KeyType   int8   `cbor:"1,keyasint"`  // Key Type
	Algorithm int8   `cbor:"3,keyasint"`  // Key Algorithm
	Curve     int8   `cbor:"-1,keyasint"` // Key Curve
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

func (key *ctapCOSEPublicKey) String() string {
	return fmt.Sprintf("ctapCOSEPublicKey{KeyType: %d, Algorithm: %d, Curve: %d, X: %s, Y: %s}",
		key.KeyType,
		key.Algorithm,
		key.Curve,
		hex.EncodeToString(key.X),
		hex.EncodeToString(key.Y))
}

func ctapEncodeKeyAsCOSE(publicKey *ecdsa.PublicKey) []byte {
	key := ctapCOSEPublicKey{
		KeyType:   int8(cose_KEY_TYPE_EC2),
		Algorithm: int8(cose_ALGORITHM_ID_ES256),
		Curve:     int8(cose_CURVE_ID_P256),
		X:         publicKey.X.Bytes(),
		Y:         publicKey.Y.Bytes(),
	}
	return util.MarshalCBOR(key)
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

type ctapSelfAttestationStatement struct {
	Alg coseAlgorithmID `cbor:"alg"`
	Sig []byte          `cbor:"sig"`
}

type ctapBasicAttestationStatement struct {
	Alg coseAlgorithmID `cbor:"alg"`
	Sig []byte          `cbor:"sig"`
	X5c [][]byte        `cbor:"x5c"`
}

func ctapMakeAttestedCredentialData(credentialSource *CredentialSource) []byte {
	encodedCredentialPublicKey := ctapEncodeKeyAsCOSE(&credentialSource.PrivateKey.PublicKey)
	return util.Flatten([][]byte{aaguid[:], util.ToBE(uint16(len(credentialSource.ID))), credentialSource.ID, encodedCredentialPublicKey})
}

func ctapMakeAuthData(rpID string, credentialSource *CredentialSource, attestedCredentialData []byte, flags uint8) []byte {
	if attestedCredentialData != nil {
		flags = flags | ctap_AUTH_DATA_FLAG_ATTESTED_DATA_INCLUDED
	} else {
		attestedCredentialData = []byte{}
	}
	rpIdHash := sha256.Sum256([]byte(rpID))
	return util.Flatten([][]byte{rpIdHash[:], {flags}, util.ToBE(credentialSource.SignatureCounter), attestedCredentialData})
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
	PinAuth          []byte                          `cbor:"8,keyasint,omitempty"`
	PinProtocol      uint32                          `cbor:"9,keyasint,omitempty"`
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
	FormatIdentifer      string                       `cbor:"1,keyasint"`
	AuthData             []byte                       `cbor:"2,keyasint"`
	AttestationStatement ctapSelfAttestationStatement `cbor:"3,keyasint"`
}

func (server *ctapServer) handleMakeCredential(data []byte) []byte {
	var args ctapMakeCredentialArgs
	err := cbor.Unmarshal(data, &args)
	util.CheckErr(err, fmt.Sprintf("Could not decode CBOR for MAKE_CREDENTIAL: %s %v", err, data))
	ctapLogger.Printf("MAKE CREDENTIAL: %s\n\n", args)
	var flags uint8 = 0

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

	if args.PinProtocol == 1 {
		pinAuth := server.derivePINAuth(server.client.PINToken(), args.ClientDataHash)
		if !bytes.Equal(pinAuth, args.PinAuth) {
			return []byte{byte(ctap2_ERR_PIN_AUTH_INVALID)}
		}
		flags = flags | ctap_AUTH_DATA_FLAG_USER_VERIFIED
	} else {
		if server.client.PINHash() != nil {
			return []byte{byte(ctap2_ERR_PIN_REQUIRED)}
		}
	}

	if !server.client.ApproveAccountCreation(args.Rp.Name) {
		ctapLogger.Printf("ERROR: Unapproved action (Create account)")
		return []byte{byte(ctap2_ERR_OPERATION_DENIED)}
	}
	flags = flags | ctap_AUTH_DATA_FLAG_USER_PRESENT

	credentialSource := server.client.NewCredentialSource(args.Rp, args.User)
	attestedCredentialData := ctapMakeAttestedCredentialData(credentialSource)
	authenticatorData := ctapMakeAuthData(args.Rp.Id, credentialSource, attestedCredentialData, flags)

	attestationSignature := sign(credentialSource.PrivateKey, append(authenticatorData, args.ClientDataHash...))
	attestationStatement := ctapSelfAttestationStatement{
		Alg: cose_ALGORITHM_ID_ES256,
		Sig: attestationSignature,
	}

	response := ctapMakeCredentialReponse{
		AuthData:             authenticatorData,
		FormatIdentifer:      "packed",
		AttestationStatement: attestationStatement,
	}
	ctapLogger.Printf("MAKE CREDENTIAL RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

type ctapGetInfoOptions struct {
	IsPlatform      bool `cbor:"plat"`
	CanResidentKey  bool `cbor:"rk"`
	HasClientPIN    bool `cbor:"clientPin"`
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

func (server *ctapServer) handleGetInfo(data []byte) []byte {
	response := ctapGetInfoResponse{
		Versions: []string{"FIDO_2_0", "U2F_V2"},
		AAGUID:   aaguid,
		Options: ctapGetInfoOptions{
			IsPlatform:      false,
			CanResidentKey:  true,
			CanUserPresence: true,
			HasClientPIN:    server.client.PINHash() != nil,
			// CanUserVerification: true,
		},
		PinProtocols: []uint32{1},
	}
	ctapLogger.Printf("CTAP GET_INFO RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

type ctapGetAssertionArgs struct {
	RpID           string                          `cbor:"1,keyasint"`
	ClientDataHash []byte                          `cbor:"2,keyasint"`
	AllowList      []PublicKeyCredentialDescriptor `cbor:"3,keyasint"`
	Options        ctapCommandOptions              `cbor:"5,keyasint"`
	PinAuth        []byte                          `cbor:"6,keyasint,omitempty"`
	PinProtocol    uint32                          `cbor:"7,keyasint,omitempty"`
}

type ctapGetAssertionResponse struct {
	//Credential          *PublicKeyCredentialDescriptor  `cbor:"1,keyasint,omitempty"`
	AuthenticatorData []byte `cbor:"2,keyasint"`
	Signature         []byte `cbor:"3,keyasint"`
	//User                *PublicKeyCrendentialUserEntity `cbor:"4,keyasint,omitempty"`
	//NumberOfCredentials int32 `cbor:"5,keyasint"`
}

func (server *ctapServer) handleGetAssertion(data []byte) []byte {
	var flags uint8 = 0
	var args ctapGetAssertionArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2_ERR_INVALID_CBOR)}
	}
	ctapLogger.Printf("GET ASSERTION: %#v\n\n", args)

	if args.PinAuth != nil {
		if args.PinProtocol != 1 {
			return []byte{byte(ctap2_ERR_PIN_AUTH_INVALID)}
		}
		pinAuth := server.derivePINAuth(server.client.PINToken(), args.ClientDataHash)
		if !bytes.Equal(pinAuth, args.PinAuth) {
			return []byte{byte(ctap2_ERR_PIN_AUTH_INVALID)}
		}
		flags = flags | ctap_AUTH_DATA_FLAG_USER_VERIFIED
	}

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
		flags = flags | ctap_AUTH_DATA_FLAG_USER_PRESENT
	}

	authData := ctapMakeAuthData(args.RpID, credentialSource, nil, flags)
	signature := sign(credentialSource.PrivateKey, util.Flatten([][]byte{authData, args.ClientDataHash}))

	response := ctapGetAssertionResponse{
		//Credential:          credentialSource.ctapDescriptor(),
		AuthenticatorData: authData,
		Signature:         signature,
		//User:                credentialSource.User,
		//NumberOfCredentials: 1,
	}

	ctapLogger.Printf("RESPONSE: %#v\n\n", response)

	return append([]byte{byte(ctap1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

type ctapClientPINSubcommand uint32

const (
	ctap_CLIENT_PIN_SUBCOMMAND_GET_RETRIES       ctapClientPINSubcommand = 1
	ctap_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT ctapClientPINSubcommand = 2
	ctap_CLIENT_PIN_SUBCOMMAND_SET_PIN           ctapClientPINSubcommand = 3
	ctap_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN        ctapClientPINSubcommand = 4
	ctap_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN     ctapClientPINSubcommand = 5
)

var ctapClientPINSubcommandDescriptions = map[ctapClientPINSubcommand]string{
	ctap_CLIENT_PIN_SUBCOMMAND_GET_RETRIES:       "ctap_CLIENT_PIN_SUBCOMMAND_GET_RETRIES",
	ctap_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT: "ctap_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT",
	ctap_CLIENT_PIN_SUBCOMMAND_SET_PIN:           "ctap_CLIENT_PIN_SUBCOMMAND_SET_PIN",
	ctap_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN:        "ctap_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN",
	ctap_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN:     "ctap_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN",
}

type ctapClientPINArgs struct {
	PinProtocol     uint32                  `cbor:"1,keyasint"`
	SubCommand      ctapClientPINSubcommand `cbor:"2,keyasint"`
	KeyAgreement    *ctapCOSEPublicKey      `cbor:"3,keyasint,omitempty"`
	PINAuth         []byte                  `cbor:"4,keyasint,omitempty"`
	NewPINEncoding  []byte                  `cbor:"5,keyasint,omitempty"`
	PINHashEncoding []byte                  `cbor:"6,keyasint,omitempty"`
}

func (args ctapClientPINArgs) String() string {
	return fmt.Sprintf("ctapClientPINArgs{PinProtocol: %d, SubCommand: %s, KeyAgreement: %v, PINAuth: %s, NewPINEncoding: %s, PINHashEncoding: %s}",
		args.PinProtocol,
		ctapClientPINSubcommandDescriptions[args.SubCommand],
		args.KeyAgreement,
		hex.EncodeToString(args.PINAuth),
		hex.EncodeToString(args.NewPINEncoding),
		hex.EncodeToString(args.PINHashEncoding))
}

type ctapClientPINResponse struct {
	KeyAgreement *ctapCOSEPublicKey `cbor:"1,keyasint,omitempty"`
	PinToken     []byte             `cbor:"2,keyasint,omitempty"`
	Retries      *uint8             `cbor:"3,keyasint,omitempty"`
}

func (args ctapClientPINResponse) String() string {
	return fmt.Sprintf("ctapClientPINResponse{KeyAgreement: %s, PinToken: %s, Retries: %#v}",
		args.KeyAgreement,
		hex.EncodeToString(args.PinToken),
		args.Retries)
}

func (server *ctapServer) getPINSharedSecret(remoteKey ctapCOSEPublicKey) []byte {
	pinKey := server.client.PINKeyAgreement()
	return hashSHA256(pinKey.ECDH(util.BytesToBigInt(remoteKey.X), util.BytesToBigInt(remoteKey.Y)))
}

func (server *ctapServer) derivePINAuth(sharedSecret []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, sharedSecret)
	hash.Write(data)
	return hash.Sum(nil)[:16]
}

func (server *ctapServer) decryptPINHash(sharedSecret []byte, pinHashEncoding []byte) []byte {
	return decryptAESCBC(sharedSecret, pinHashEncoding)
}

func (server *ctapServer) decryptPIN(sharedSecret []byte, pinEncoding []byte) []byte {
	decryptedPINPadded := decryptAESCBC(sharedSecret, pinEncoding)
	var decryptedPIN []byte = nil
	for i := range decryptedPINPadded {
		if decryptedPINPadded[i] == 0 {
			decryptedPIN = decryptedPINPadded[:i]
			break
		}
	}
	return decryptedPIN
}

func (server *ctapServer) handleClientPIN(data []byte) []byte {
	var args ctapClientPINArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2_ERR_INVALID_CBOR)}
	}
	if args.PinProtocol != 1 {
		return []byte{byte(ctap1_ERR_INVALID_PARAMETER)}
	}
	ctapLogger.Printf("CTAP_CLIENT_PIN: %v\n\n", args)
	var response []byte
	switch args.SubCommand {
	case ctap_CLIENT_PIN_SUBCOMMAND_GET_RETRIES:
		response = server.handleGetRetries()
	case ctap_CLIENT_PIN_SUBCOMMAND_GET_KEY_AGREEMENT:
		response = server.handleGetKeyAgreement(args)
	case ctap_CLIENT_PIN_SUBCOMMAND_SET_PIN:
		response = server.handleSetPIN(args)
	case ctap_CLIENT_PIN_SUBCOMMAND_CHANGE_PIN:
		response = server.handleChangePIN(args)
	case ctap_CLIENT_PIN_SUBCOMMAND_GET_PIN_TOKEN:
		response = server.handleGetPINToken(args)
	default:
		return []byte{byte(ctap2_ERR_MISSING_PARAM)}
	}
	ctapLogger.Printf("CTAP_CLIENT_PIN RESPONSE: %#v\n\n", response)
	return response
}

func (server *ctapServer) handleGetRetries() []byte {
	retries := uint8(server.client.PINRetries())
	response := ctapClientPINResponse{
		Retries: &retries,
	}
	ctapLogger.Printf("CTAP_CLIENT_PIN_GET_RETRIES: %v\n\n", response)
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

func (server *ctapServer) handleGetKeyAgreement(args ctapClientPINArgs) []byte {
	key := server.client.PINKeyAgreement()
	response := ctapClientPINResponse{
		KeyAgreement: &ctapCOSEPublicKey{
			KeyType:   int8(cose_KEY_TYPE_EC2),
			Algorithm: int8(cose_ALGORITHM_ID_ECDH_HKDF_256),
			X:         key.x.Bytes(),
			Y:         key.y.Bytes(),
		},
	}
	ctapLogger.Printf("CLIENT_PIN_GET_KEY_AGREEMENT RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}

func (server *ctapServer) handleSetPIN(args ctapClientPINArgs) []byte {
	if server.client.PINHash() != nil {
		return []byte{byte(ctap2_ERR_PIN_AUTH_INVALID)}
	}
	if args.KeyAgreement == nil || args.PINAuth == nil || args.NewPINEncoding == nil {
		return []byte{byte(ctap2_ERR_MISSING_PARAM)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	pinAuth := server.derivePINAuth(sharedSecret, args.NewPINEncoding)
	if !bytes.Equal(pinAuth, args.PINAuth) {
		return []byte{byte(ctap2_ERR_PIN_AUTH_INVALID)}
	}
	decryptedPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(decryptedPIN) < 4 {
		return []byte{byte(ctap2_ERR_PIN_POLICY_VIOLATION)}
	}
	pinHash := hashSHA256(decryptedPIN)[:16]
	server.client.SetPINRetries(8)
	server.client.SetPINHash(pinHash)
	ctapLogger.Printf("SETTING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	return []byte{byte(ctap1_ERR_SUCCESS)}
}

func (server *ctapServer) handleChangePIN(args ctapClientPINArgs) []byte {
	if args.KeyAgreement == nil || args.PINAuth == nil {
		return []byte{byte(ctap2_ERR_MISSING_PARAM)}
	}
	if server.client.PINRetries() == 0 {
		return []byte{byte(ctap2_ERR_PIN_BLOCKED)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	pinAuth := server.derivePINAuth(sharedSecret, append(args.NewPINEncoding, args.PINHashEncoding...))
	if !bytes.Equal(pinAuth, args.PINAuth) {
		return []byte{byte(ctap2_ERR_PIN_AUTH_INVALID)}
	}
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	decryptedPINHash := decryptAESCBC(sharedSecret, args.PINHashEncoding)
	if !bytes.Equal(server.client.PINHash(), decryptedPINHash) {
		// TODO: Mismatch detected, handle it
		return []byte{byte(ctap2_ERR_PIN_INVALID)}
	}
	server.client.SetPINRetries(8)
	newPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(newPIN) < 4 {
		return []byte{byte(ctap2_ERR_PIN_POLICY_VIOLATION)}
	}
	pinHash := hashSHA256(newPIN)[:16]
	server.client.SetPINHash(pinHash)
	return []byte{byte(ctap1_ERR_SUCCESS)}
}

func (server *ctapServer) handleGetPINToken(args ctapClientPINArgs) []byte {
	if args.PINHashEncoding == nil || args.KeyAgreement.X == nil {
		return []byte{byte(ctap2_ERR_MISSING_PARAM)}
	}
	if server.client.PINRetries() <= 0 {
		return []byte{byte(ctap2_ERR_PIN_BLOCKED)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	pinHash := server.decryptPINHash(sharedSecret, args.PINHashEncoding)
	ctapLogger.Printf("TRYING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	if !bytes.Equal(pinHash, server.client.PINHash()) {
		// TODO: Handle mismatch here by regening the key agreement key
		ctapLogger.Printf("MISMATCH: Provided PIN %v doesn't match stored PIN %v\n\n", hex.EncodeToString(pinHash), hex.EncodeToString(server.client.PINHash()))
		return []byte{byte(ctap2_ERR_PIN_INVALID)}
	}
	server.client.SetPINRetries(8)
	response := ctapClientPINResponse{
		PinToken: encryptAESCBC(sharedSecret, server.client.PINToken()),
	}
	ctapLogger.Printf("GET_PIN_TOKEN RESPONSE: %#v\n\n",response)
	return append([]byte{byte(ctap1_ERR_SUCCESS)}, util.MarshalCBOR(response)...)
}
