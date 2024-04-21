package ctap

import (
	"bytes"
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

type ctapCommand uint8

const (
	ctapCommandMakeCredential   ctapCommand = 0x01
	ctapCommandGetAssertion     ctapCommand = 0x02
	ctapCommandGetInfo          ctapCommand = 0x04
	ctapCommandClientPIN        ctapCommand = 0x06
	ctapCommandReset            ctapCommand = 0x07
	ctapCommandGetNextAssertion ctapCommand = 0x08
)

var ctapCommandDescriptions = map[ctapCommand]string{
	ctapCommandMakeCredential:   "ctapCommandMakeCredential",
	ctapCommandGetAssertion:     "ctapCommandGetAssertion",
	ctapCommandGetInfo:          "ctapCommandGetInfo",
	ctapCommandClientPIN:        "ctapCommandClientPIN",
	ctapCommandReset:            "ctapCommandReset",
	ctapCommandGetNextAssertion: "ctapCommandGetNextAssertion",
}

type ctapStatusCode byte

const (
	ctap1ErrSuccess          ctapStatusCode = 0x00
	ctap1ErrInvalidCommand   ctapStatusCode = 0x01
	ctap1ErrInvalidParameter ctapStatusCode = 0x02
	ctap1ErrInvalidLength    ctapStatusCode = 0x03
	ctap1ErrInvalidSequence  ctapStatusCode = 0x04
	ctap1ErrTimeout          ctapStatusCode = 0x05
	ctap1ErrChannelBusy      ctapStatusCode = 0x06

	ctap2ErrUnsupportedAlgorithm ctapStatusCode = 0x26
	ctap2ErrInvalidCBOR          ctapStatusCode = 0x12
	ctap2ErrNoCredentials        ctapStatusCode = 0x2E
	ctap2ErrOperationDenied      ctapStatusCode = 0x27
	ctap2ErrMissingParam         ctapStatusCode = 0x14
	ctap2ErrPINInvalid           ctapStatusCode = 0x31
	ctap2ErrPINBlocked           ctapStatusCode = 0x32
	ctap2ErrPINAuthInvalid       ctapStatusCode = 0x33
	ctap2ErrNoPINSet             ctapStatusCode = 0x35
	ctap2ErrPINRequired          ctapStatusCode = 0x36
	ctap2ErrPINPolicyViolation   ctapStatusCode = 0x37
	ctap2ErrPINExpired           ctapStatusCode = 0x38
)

type CTAPClient interface {
	SupportsResidentKey() bool
	SupportsPIN() bool

	NewCredentialSource(
		PubKeyCredParams []webauthn.PublicKeyCredentialParams,
		ExcludeList []webauthn.PublicKeyCredentialDescriptor,
		relyingParty *webauthn.PublicKeyCredentialRPEntity,
		user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource
	GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource
	CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte

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
	command := ctapCommand(data[0])
	ctapLogger.Printf("CTAP COMMAND: %s\n\n", ctapCommandDescriptions[command])
	switch command {
	case ctapCommandMakeCredential:
		return server.handleMakeCredential(data[1:])
	case ctapCommandGetInfo:
		return server.handleGetInfo()
	case ctapCommandGetAssertion:
		return server.handleGetAssertion(data[1:])
	case ctapCommandClientPIN:
		return server.handleClientPIN(data[1:])
	default:
		panic(fmt.Sprintf("Invalid CTAP Command: %d", command))
	}
}

type attestedCredentialData struct {
	AAGUID             []byte
	CredentialIDLength uint16
	CredentialID       []byte
	EncodedPublicKey   []byte
}

type authDataFlags uint8

const (
	authDataFlagUserPresent           authDataFlags = 0b00000001
	authDataFlagUserVerified          authDataFlags = 0b00000100
	authDataFlagAttestedDataIncluded  authDataFlags = 0b01000000
	authDataFlagExtensionDataIncluded authDataFlags = 0b10000000
)

type authData struct {
	RelyingPartyIDHash     []byte
	Flags                  authDataFlags
	AttestedCredentialData *attestedCredentialData
}

type selfAttestationStatement struct {
	Alg cose.COSEAlgorithmID `cbor:"alg"`
	Sig []byte               `cbor:"sig"`
}

type basicAttestationStatement struct {
	Alg cose.COSEAlgorithmID `cbor:"alg"`
	Sig []byte               `cbor:"sig"`
	X5c [][]byte             `cbor:"x5c"`
}

func makeAttestedCredentialData(credentialSource *identities.CredentialSource) []byte {
	encodedCredentialPublicKey := cose.MarshalCOSEPublicKey(credentialSource.PrivateKey.Public())
	return util.Concat(aaguid[:], util.ToBE(uint16(len(credentialSource.ID))), credentialSource.ID, encodedCredentialPublicKey)
}

func makeAuthData(rpID string, credentialSource *identities.CredentialSource, attestedCredentialData []byte, flags authDataFlags) []byte {
	if attestedCredentialData != nil {
		flags = flags | authDataFlagAttestedDataIncluded
	} else {
		attestedCredentialData = []byte{}
	}
	rpIdHash := sha256.Sum256([]byte(rpID))
	return util.Concat(rpIdHash[:], []byte{uint8(flags)}, util.ToBE(credentialSource.SignatureCounter), attestedCredentialData)
}

type makeCredentialOptions struct {
	ResidentKey      bool  `cbor:"rk,omitempty"`
	UserVerification bool  `cbor:"uv,omitempty"`
	UserPresence     *bool `cbor:"up,omitempty"`
}

type makeCredentialArgs struct {
	ClientDataHash    []byte                                   `cbor:"1,keyasint,omitempty"`
	RP                *webauthn.PublicKeyCredentialRPEntity    `cbor:"2,keyasint,omitempty"`
	User              *webauthn.PublicKeyCrendentialUserEntity `cbor:"3,keyasint,omitempty"`
	PubKeyCredParams  []webauthn.PublicKeyCredentialParams     `cbor:"4,keyasint,omitempty"`
	ExcludeList       []webauthn.PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions        map[string]interface{}                   `cbor:"6,keyasint,omitempty"`
	Options           *makeCredentialOptions                   `cbor:"7,keyasint,omitempty"`
	PINUVAuthParam    []byte                                   `cbor:"8,keyasint,omitempty"`
	PINUVAuthProtocol uint32                                   `cbor:"9,keyasint,omitempty"`
}

func (args makeCredentialArgs) String() string {
	return fmt.Sprintf("ctapMakeCredentialArgs{ ClientDataHash: 0x%s, Relying Party: %s, User: %s, PublicKeyCredentialParams: %#v, ExcludeList: %#v, Extensions: %#v, Options: %#v, PinAuth: %#v, PinProtocol: %d }",
		hex.EncodeToString(args.ClientDataHash),
		args.RP,
		args.User,
		args.PubKeyCredParams,
		args.ExcludeList,
		args.Extensions,
		args.Options,
		args.PINUVAuthParam,
		args.PINUVAuthProtocol,
	)
}

type makeCredentialResponse struct {
	FormatIdentifer      string                    `cbor:"1,keyasint"`
	AuthData             []byte                    `cbor:"2,keyasint"`
	AttestationStatement basicAttestationStatement `cbor:"3,keyasint"`
}

func (server *CTAPServer) handleMakeCredential(data []byte) []byte {
	var args makeCredentialArgs
	err := cbor.Unmarshal(data, &args)
	util.CheckErr(err, fmt.Sprintf("Could not decode CBOR for MAKE_CREDENTIAL: %s %v", err, data))
	ctapLogger.Printf("MAKE CREDENTIAL: %s\n\n", args)
	var flags authDataFlags = 0

	supported := false
	for _, param := range args.PubKeyCredParams {
		if param.Algorithm == cose.COSE_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
		}
	}
	if !supported {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return []byte{byte(ctap2ErrUnsupportedAlgorithm)}
	}

	if server.client.SupportsPIN() {
		if args.PINUVAuthProtocol == 1 && args.PINUVAuthParam != nil {
			pinAuth := server.derivePINAuth(server.client.PINToken(), args.ClientDataHash)
			if !bytes.Equal(pinAuth, args.PINUVAuthParam) {
				return []byte{byte(ctap2ErrPINAuthInvalid)}
			}
			flags = flags | authDataFlagUserVerified
		} else if args.PINUVAuthParam == nil && server.client.PINHash() != nil {
			return []byte{byte(ctap2ErrPINRequired)}
		} else if args.PINUVAuthParam != nil && args.PINUVAuthProtocol != 1 {
			return []byte{byte(ctap2ErrPINAuthInvalid)}
		}
	}

	if !server.client.ApproveAccountCreation(args.RP.Name) {
		ctapLogger.Printf("ERROR: Unapproved action (Create account)")
		return []byte{byte(ctap2ErrOperationDenied)}
	}
	flags = flags | authDataFlagUserPresent

	credentialSource := server.client.NewCredentialSource(args.PubKeyCredParams, args.ExcludeList, args.RP, args.User)
	if credentialSource == nil {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return []byte{byte(ctap2ErrUnsupportedAlgorithm)}
	}
	attestedCredentialData := makeAttestedCredentialData(credentialSource)
	authenticatorData := makeAuthData(args.RP.ID, credentialSource, attestedCredentialData, flags)

	attestationCert := server.client.CreateAttestationCertificiate(credentialSource.PrivateKey)
	attestationSignature := credentialSource.PrivateKey.Sign(append(authenticatorData, args.ClientDataHash...))
	attestationStatement := basicAttestationStatement{
		Alg: cose.COSE_ALGORITHM_ID_ES256,
		Sig: attestationSignature,
		X5c: [][]byte{attestationCert},
	}

	response := makeCredentialResponse{
		AuthData:             authenticatorData,
		FormatIdentifer:      "packed",
		AttestationStatement: attestationStatement,
	}
	ctapLogger.Printf("MAKE CREDENTIAL RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

type getInfoOptions struct {
	IsPlatform      bool  `cbor:"plat"`
	CanResidentKey  bool  `cbor:"rk"`
	HasClientPIN    *bool `cbor:"clientPin,omitempty"`
	CanUserPresence bool  `cbor:"up"`
	// CanUserVerification bool  `cbor:"uv"`
}

type getInfoResponse struct {
	Versions []string `cbor:"1,keyasint,omitempty"`
	//Extensions []string `cbor:"2,keyasint,omitempty"`
	AAGUID  [16]byte       `cbor:"3,keyasint,omitempty"`
	Options getInfoOptions `cbor:"4,keyasint,omitempty"`
	//MaxMessageSize uint32   `cbor:"5,keyasint,omitempty"`
	PINUVAuthProtocols []uint32 `cbor:"6,keyasint,omitempty"`
}

func (server *CTAPServer) handleGetInfo() []byte {
	response := getInfoResponse{
		Versions: []string{"FIDO_2_0", "U2F_V2"},
		AAGUID:   aaguid,
		Options: getInfoOptions{
			IsPlatform:      false,
			CanResidentKey:  server.client.SupportsResidentKey(),
			CanUserPresence: true,
			// CanUserVerification: true,
		},
	}
	if server.client.SupportsPIN() {
		var clientPIN bool = server.client.PINHash() != nil
		response.Options.HasClientPIN = &clientPIN
		response.PINUVAuthProtocols = []uint32{1}
	}
	ctapLogger.Printf("GET_INFO RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

type getAssertionOptions struct {
	UserVerification bool  `cbor:"uv,omitempty"`
	UserPresence     *bool `cbor:"up,omitempty"`
}

type getAssertionArgs struct {
	RPID              string                                   `cbor:"1,keyasint"`
	ClientDataHash    []byte                                   `cbor:"2,keyasint"`
	AllowList         []webauthn.PublicKeyCredentialDescriptor `cbor:"3,keyasint"`
	Options           getAssertionOptions                      `cbor:"5,keyasint"`
	PINUVAuthParam    []byte                                   `cbor:"6,keyasint,omitempty"`
	PINUVAuthProtocol uint32                                   `cbor:"7,keyasint,omitempty"`
}

type getAssertionResponse struct {
	Credential        *webauthn.PublicKeyCredentialDescriptor `cbor:"1,keyasint,omitempty"`
	AuthenticatorData []byte                                  `cbor:"2,keyasint"`
	Signature         []byte                                  `cbor:"3,keyasint"`
	//User                *PublicKeyCrendentialUserEntity `cbor:"4,keyasint,omitempty"`
	//NumberOfCredentials int32 `cbor:"5,keyasint"`
}

func (server *CTAPServer) handleGetAssertion(data []byte) []byte {
	var flags authDataFlags = 0
	var args getAssertionArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2ErrInvalidCBOR)}
	}
	ctapLogger.Printf("GET ASSERTION: %#v\n\n", args)

	if server.client.SupportsPIN() {
		if args.PINUVAuthParam != nil {
			if args.PINUVAuthProtocol != 1 {
				return []byte{byte(ctap2ErrPINAuthInvalid)}
			}
			pinAuth := server.derivePINAuth(server.client.PINToken(), args.ClientDataHash)
			if !bytes.Equal(pinAuth, args.PINUVAuthParam) {
				return []byte{byte(ctap2ErrPINAuthInvalid)}
			}
			flags = flags | authDataFlagUserVerified
		}
	}

	credentialSource := server.client.GetAssertionSource(args.RPID, args.AllowList)
	unsafeCtapLogger.Printf("CREDENTIAL SOURCE: %#v\n\n", credentialSource)
	if credentialSource == nil {
		ctapLogger.Printf("ERROR: No Credentials\n\n")
		return []byte{byte(ctap2ErrNoCredentials)}
	}

	if args.Options.UserPresence == nil || *args.Options.UserPresence {
		if !server.client.ApproveAccountLogin(credentialSource) {
			ctapLogger.Printf("ERROR: Unapproved action (Account login)")
			return []byte{byte(ctap2ErrOperationDenied)}
		}
		flags = flags | authDataFlagUserPresent
	}

	authData := makeAuthData(args.RPID, credentialSource, nil, flags)
	signature := credentialSource.PrivateKey.Sign(util.Concat(authData, args.ClientDataHash))

	credentialDescriptor := credentialSource.CTAPDescriptor()
	response := getAssertionResponse{
		Credential:        &credentialDescriptor,
		AuthenticatorData: authData,
		Signature:         signature,
		//User:                credentialSource.User,
		//NumberOfCredentials: 1,
	}

	ctapLogger.Printf("GET ASSERTION RESPONSE: %#v\n\n", response)

	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

type clientPINSubcommand uint32

const (
	clientPINSubcommandGetRetries      clientPINSubcommand = 1
	clientPinSubcommandGetKeyAgreement clientPINSubcommand = 2
	clientPINSubcommandSetPIN          clientPINSubcommand = 3
	clientPINSubcommandChangePIN       clientPINSubcommand = 4
	clientPinSubcommandGetPINToken     clientPINSubcommand = 5
)

var clientPINSubcommandDescriptions = map[clientPINSubcommand]string{
	clientPINSubcommandGetRetries:      "clientPINSubcommandGetRetries",
	clientPinSubcommandGetKeyAgreement: "clientPinSubcommandGetKeyAgreement",
	clientPINSubcommandSetPIN:          "clientPINSubcommandSetPIN",
	clientPINSubcommandChangePIN:       "clientPINSubcommandChangePIN",
	clientPinSubcommandGetPINToken:     "clientPinSubcommandGetPINToken",
}

type clientPINArgs struct {
	PINUVAuthProtocol uint32              `cbor:"1,keyasint"`
	SubCommand        clientPINSubcommand `cbor:"2,keyasint"`
	KeyAgreement      *cose.COSEEC2Key    `cbor:"3,keyasint,omitempty"`
	PINUVAuthParam    []byte              `cbor:"4,keyasint,omitempty"`
	NewPINEncoding    []byte              `cbor:"5,keyasint,omitempty"`
	PINHashEncoding   []byte              `cbor:"6,keyasint,omitempty"`
}

func (args clientPINArgs) String() string {
	return fmt.Sprintf("ctapClientPINArgs{PinProtocol: %d, SubCommand: %s, KeyAgreement: %v, PINAuth: 0x%s, NewPINEncoding: 0x%s, PINHashEncoding: 0x%s}",
		args.PINUVAuthProtocol,
		clientPINSubcommandDescriptions[args.SubCommand],
		args.KeyAgreement,
		hex.EncodeToString(args.PINUVAuthParam),
		hex.EncodeToString(args.NewPINEncoding),
		hex.EncodeToString(args.PINHashEncoding))
}

type clientPINResponse struct {
	KeyAgreement *cose.COSEEC2Key `cbor:"1,keyasint,omitempty"`
	PinToken     []byte           `cbor:"2,keyasint,omitempty"`
	Retries      *uint8           `cbor:"3,keyasint,omitempty"`
}

func (args clientPINResponse) String() string {
	return fmt.Sprintf("ctapClientPINResponse{KeyAgreement: %s, PinToken: %s, Retries: %#v}",
		args.KeyAgreement,
		hex.EncodeToString(args.PinToken),
		args.Retries)
}

func (server *CTAPServer) getPINSharedSecret(remoteKey cose.COSEEC2Key) []byte {
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
		return []byte{byte(ctap1ErrInvalidCommand)}
	}
	var args clientPINArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2ErrInvalidCBOR)}
	}
	if args.PINUVAuthProtocol != 1 {
		return []byte{byte(ctap1ErrInvalidParameter)}
	}
	ctapLogger.Printf("CLIENT_PIN: %v\n\n", args)
	var response []byte
	switch args.SubCommand {
	case clientPINSubcommandGetRetries:
		response = server.handleGetRetries()
	case clientPinSubcommandGetKeyAgreement:
		response = server.handleGetKeyAgreement()
	case clientPINSubcommandSetPIN:
		response = server.handleSetPIN(args)
	case clientPINSubcommandChangePIN:
		response = server.handleChangePIN(args)
	case clientPinSubcommandGetPINToken:
		response = server.handleGetPINToken(args)
	default:
		return []byte{byte(ctap2ErrMissingParam)}
	}
	ctapLogger.Printf("CLIENT_PIN RESPONSE: %#v\n\n", response)
	return response
}

func (server *CTAPServer) handleGetRetries() []byte {
	retries := uint8(server.client.PINRetries())
	response := clientPINResponse{
		Retries: &retries,
	}
	ctapLogger.Printf("CLIENT_PIN_GET_RETRIES: %v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

func (server *CTAPServer) handleGetKeyAgreement() []byte {
	key := server.client.PINKeyAgreement()
	response := clientPINResponse{
		KeyAgreement: &cose.COSEEC2Key{
			KeyType:   int8(cose.COSE_KEY_TYPE_EC2),
			Algorithm: int8(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256),
			X:         key.X.Bytes(),
			Y:         key.Y.Bytes(),
		},
	}
	ctapLogger.Printf("CLIENT_PIN_GET_KEY_AGREEMENT RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

func (server *CTAPServer) handleSetPIN(args clientPINArgs) []byte {
	if server.client.PINHash() != nil {
		return []byte{byte(ctap2ErrPINAuthInvalid)}
	}
	if args.KeyAgreement == nil || args.PINUVAuthParam == nil || args.NewPINEncoding == nil {
		return []byte{byte(ctap2ErrMissingParam)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	pinAuth := server.derivePINAuth(sharedSecret, args.NewPINEncoding)
	if !bytes.Equal(pinAuth, args.PINUVAuthParam) {
		return []byte{byte(ctap2ErrPINAuthInvalid)}
	}
	decryptedPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(decryptedPIN) < 4 {
		return []byte{byte(ctap2ErrPINPolicyViolation)}
	}
	pinHash := crypto.HashSHA256(decryptedPIN)[:16]
	server.client.SetPINRetries(8)
	server.client.SetPINHash(pinHash)
	ctapLogger.Printf("SETTING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	return []byte{byte(ctap1ErrSuccess)}
}

func (server *CTAPServer) handleChangePIN(args clientPINArgs) []byte {
	if args.KeyAgreement == nil || args.PINUVAuthParam == nil {
		return []byte{byte(ctap2ErrMissingParam)}
	}
	if server.client.PINRetries() == 0 {
		return []byte{byte(ctap2ErrPINBlocked)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	pinAuth := server.derivePINAuth(sharedSecret, append(args.NewPINEncoding, args.PINHashEncoding...))
	if !bytes.Equal(pinAuth, args.PINUVAuthParam) {
		return []byte{byte(ctap2ErrPINAuthInvalid)}
	}
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	decryptedPINHash := crypto.DecryptAESCBC(sharedSecret, args.PINHashEncoding)
	if !bytes.Equal(server.client.PINHash(), decryptedPINHash) {
		// TODO: Mismatch detected, handle it
		return []byte{byte(ctap2ErrPINInvalid)}
	}
	server.client.SetPINRetries(8)
	newPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(newPIN) < 4 {
		return []byte{byte(ctap2ErrPINPolicyViolation)}
	}
	pinHash := crypto.HashSHA256(newPIN)[:16]
	server.client.SetPINHash(pinHash)
	return []byte{byte(ctap1ErrSuccess)}
}

func (server *CTAPServer) handleGetPINToken(args clientPINArgs) []byte {
	if args.PINHashEncoding == nil || args.KeyAgreement.X == nil {
		return []byte{byte(ctap2ErrMissingParam)}
	}
	if server.client.PINRetries() <= 0 {
		return []byte{byte(ctap2ErrPINBlocked)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	pinHash := server.decryptPINHash(sharedSecret, args.PINHashEncoding)
	ctapLogger.Printf("TRYING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	if !bytes.Equal(pinHash, server.client.PINHash()) {
		// TODO: Handle mismatch here by regening the key agreement key
		ctapLogger.Printf("MISMATCH: Provided PIN %v doesn't match stored PIN %v\n\n", hex.EncodeToString(pinHash), hex.EncodeToString(server.client.PINHash()))
		return []byte{byte(ctap2ErrPINInvalid)}
	}
	server.client.SetPINRetries(8)
	response := clientPINResponse{
		PinToken: crypto.EncryptAESCBC(sharedSecret, server.client.PINToken()),
	}
	ctapLogger.Printf("GET_PIN_TOKEN RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}
