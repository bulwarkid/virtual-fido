package ctap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/fido_client"
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
	// CTAP 2.1+: authenticatorSelection (aka authenticatorSelect)
	ctapCommandAuthenticatorSelection ctapCommand = 0x0B
)

var ctapCommandDescriptions = map[ctapCommand]string{
	ctapCommandMakeCredential:         "ctapCommandMakeCredential",
	ctapCommandGetAssertion:           "ctapCommandGetAssertion",
	ctapCommandGetInfo:                "ctapCommandGetInfo",
	ctapCommandClientPIN:              "ctapCommandClientPIN",
	ctapCommandReset:                  "ctapCommandReset",
	ctapCommandGetNextAssertion:       "ctapCommandGetNextAssertion",
	ctapCommandAuthenticatorSelection: "ctapCommandAuthenticatorSelection",
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
	ctap2ErrInvalidSubcommand    ctapStatusCode = 0x2C
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
	SupportsUserVerification() bool

	NewCredentialSource(
		PubKeyCredParams []webauthn.PublicKeyCredentialParams,
		ExcludeList []webauthn.PublicKeyCredentialDescriptor,
		relyingParty *webauthn.PublicKeyCredentialRPEntity,
		user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource
	GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource
	// Returns all matching credential sources for GA
	GetAssertionSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*identities.CredentialSource
	CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte

	PINHash() []byte
	SetPINHash(pin []byte)
	PINRetries() int32
	SetPINRetries(retries int32)
	PINKeyAgreement() *crypto.ECDHKey
	PINToken() []byte

	// Persist any state changes (e.g., credRandom or counters)
	SaveState()
	VerifyUser(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool

	ApproveAccountCreation(relyingParty string) bool
	ApproveAccountLogin(credentialSource *identities.CredentialSource) bool
}

type CTAPServer struct {
	client CTAPClient
	// per-channel assertion sessions for GetNextAssertion
	assertionSessions map[uint32]*assertionSession
	currentChannelID  uint32
	// per-channel PIN key agreement sessions for ClientPIN flows
	pinSessions map[uint32]*pinSession
	// per-channel pinUvAuthToken (plaintext) issued most recently
	pinTokenByChannel map[uint32][]byte
}

func NewCTAPServer(client CTAPClient) *CTAPServer {
	return &CTAPServer{
		client:            client,
		assertionSessions: make(map[uint32]*assertionSession),
		pinSessions:       make(map[uint32]*pinSession),
		pinTokenByChannel: make(map[uint32][]byte),
	}
}

// Optional: allow HID layer to pass channel context
func (server *CTAPServer) HandleMessageForChannel(channelID uint32, data []byte) []byte {
	server.currentChannelID = channelID
	ctapLogger.Printf("CTAP: using channel 0x%x for this request\n\n", channelID)
	defer func() { server.currentChannelID = 0 }()
	return server.HandleMessage(data)
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
	case ctapCommandGetNextAssertion:
		return server.handleGetNextAssertion()
	case ctapCommandClientPIN:
		return server.handleClientPIN(data[1:])
	case ctapCommandAuthenticatorSelection:
		// CTAP2.1 authenticatorSelection requires only a success status and no CBOR payload.
		return []byte{byte(ctap1ErrSuccess)}
	default:
		// Return a proper error instead of panicking on unknown commands.
		ctapLogger.Printf("Invalid CTAP Command: %d\n\n", command)
		return []byte{byte(ctap1ErrInvalidCommand)}
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

func makeAuthDataWithExtensions(rpID string, credentialSource *identities.CredentialSource, attestedCredentialData []byte, flags authDataFlags, extensions []byte) []byte {
	if attestedCredentialData != nil {
		flags = flags | authDataFlagAttestedDataIncluded
	} else {
		attestedCredentialData = []byte{}
	}
	if len(extensions) > 0 {
		flags = flags | authDataFlagExtensionDataIncluded
	}
	rpIdHash := sha256.Sum256([]byte(rpID))
	base := util.Concat(rpIdHash[:], []byte{uint8(flags)}, util.ToBE(credentialSource.SignatureCounter), attestedCredentialData)
	if len(extensions) > 0 {
		base = util.Concat(base, extensions)
	}
	return base
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
	// Normalize empty pinUvAuthParam (empty bstr) to nil for semantics
	if args.PINUVAuthParam != nil && len(args.PINUVAuthParam) == 0 {
		args.PINUVAuthParam = nil
	}
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

	wantsUV := args.Options != nil && args.Options.UserVerification
	rpName := ""
	if args.RP != nil {
		rpName = args.RP.Name
	}
	userName := ""
	if args.User != nil {
		userName = args.User.Name
	}
	uvSatisfied := false
	if server.client.SupportsPIN() && server.client.PINHash() != nil {
		if args.PINUVAuthParam != nil {
			if args.PINUVAuthProtocol != 1 {
				return []byte{byte(ctap2ErrPINAuthInvalid)}
			}
			token := server.pinTokenByChannel[server.currentChannelID]
			// Fallback for unit tests or non-channel flows: allow verifying with authenticator's token
			if token == nil {
				token = server.client.PINToken()
			}
			if token == nil || len(token) == 0 {
				return []byte{byte(ctap2ErrPINRequired)}
			}
			pinAuth := server.derivePINAuth(token, args.ClientDataHash)
			if !bytes.Equal(pinAuth, args.PINUVAuthParam) {
				return []byte{byte(ctap2ErrPINAuthInvalid)}
			}
			uvSatisfied = true
		} else if wantsUV {
			params := fido_client.ClientActionRequestParams{RelyingParty: rpName, UserName: userName}
			verified, status := server.attemptUserVerification(fido_client.ClientActionFIDOMakeCredential, params)
			if verified {
				uvSatisfied = true
			} else if status != nil {
				return []byte{byte(*status)}
			} else {
				return []byte{byte(ctap2ErrPINRequired)}
			}
		}
	} else if wantsUV {
		params := fido_client.ClientActionRequestParams{RelyingParty: rpName, UserName: userName}
		verified, status := server.attemptUserVerification(fido_client.ClientActionFIDOMakeCredential, params)
		if verified {
			uvSatisfied = true
		} else if status != nil {
			return []byte{byte(*status)}
		} else {
			return []byte{byte(ctap2ErrOperationDenied)}
		}
	}
	if uvSatisfied {
		flags = flags | authDataFlagUserVerified
	}

	if !server.client.ApproveAccountCreation(rpName) {
		ctapLogger.Printf("ERROR: Unapproved action (Create account)")
		return []byte{byte(ctap2ErrOperationDenied)}
	}
	flags = flags | authDataFlagUserPresent

	credentialSource := server.client.NewCredentialSource(args.PubKeyCredParams, args.ExcludeList, args.RP, args.User)
	if credentialSource == nil {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return []byte{byte(ctap2ErrUnsupportedAlgorithm)}
	}
	// hmac-secret: if requested during MC, allocate credRandom
	if args.Extensions != nil {
		if extVal, ok := args.Extensions["hmac-secret"]; ok {
			// If truthy, enable hmac-secret for this credential
			enable := false
			switch v := extVal.(type) {
			case bool:
				enable = v
			default:
				// Non-bool values are treated as request present
				enable = true
			}
			if enable {
				credentialSource.CredRandom = crypto.RandomBytes(32)
				server.client.SaveState()
			}
		}
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
	IsPlatform       bool  `cbor:"plat"`
	CanResidentKey   bool  `cbor:"rk"`
	HasClientPIN     *bool `cbor:"clientPin,omitempty"`
	CanUserPresence  bool  `cbor:"up"`
	UserVerification *bool `cbor:"uv,omitempty"`
}

type getInfoResponse struct {
	Versions           []string       `cbor:"1,keyasint,omitempty"`
	Extensions         []string       `cbor:"2,keyasint,omitempty"`
	AAGUID             [16]byte       `cbor:"3,keyasint,omitempty"`
	Options            getInfoOptions `cbor:"4,keyasint,omitempty"`
	MaxMessageSize     uint32         `cbor:"5,keyasint,omitempty"`
	PINUVAuthProtocols []uint32       `cbor:"6,keyasint,omitempty"`
}

func (server *CTAPServer) handleGetInfo() []byte {
	response := getInfoResponse{
		// Force CTAP2.0 path so platforms prefer getPINToken (0x05)
		Versions: []string{"FIDO_2_0", "U2F_V2"},
		AAGUID:   aaguid,
		Options: getInfoOptions{
			IsPlatform:      false,
			CanResidentKey:  server.client.SupportsResidentKey(),
			CanUserPresence: true,
		},
		// A safe upper bound for our HID implementation; large enough for typical requests
		MaxMessageSize: 4096,
		Extensions:     []string{"hmac-secret"},
	}
	if server.client.SupportsPIN() {
		var clientPINSet bool = server.client.PINHash() != nil
		response.Options.HasClientPIN = &clientPINSet
		response.PINUVAuthProtocols = []uint32{1}
		// Do NOT set uv=true here; uv refers to on-device user verification, not PIN
	} else {
		response.PINUVAuthProtocols = []uint32{}
	}
	if server.client.SupportsUserVerification() {
		uv := true
		response.Options.UserVerification = &uv
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
	Extensions        map[string]cbor.RawMessage               `cbor:"4,keyasint,omitempty"`
	Options           getAssertionOptions                      `cbor:"5,keyasint"`
	PINUVAuthParam    []byte                                   `cbor:"6,keyasint,omitempty"`
	PINUVAuthProtocol uint32                                   `cbor:"7,keyasint,omitempty"`
}

type getAssertionResponse struct {
	Credential          *webauthn.PublicKeyCredentialDescriptor  `cbor:"1,keyasint,omitempty"`
	AuthenticatorData   []byte                                   `cbor:"2,keyasint"`
	Signature           []byte                                   `cbor:"3,keyasint"`
	User                *webauthn.PublicKeyCrendentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int32                                    `cbor:"5,keyasint,omitempty"`
}

func (server *CTAPServer) handleGetAssertion(data []byte) []byte {
	var flags authDataFlags = 0
	var args getAssertionArgs
	err := cbor.Unmarshal(data, &args)
	if err != nil {
		ctapLogger.Printf("ERROR: %s", err)
		return []byte{byte(ctap2ErrInvalidCBOR)}
	}
	// Normalize empty pinUvAuthParam to nil
	if args.PINUVAuthParam != nil && len(args.PINUVAuthParam) == 0 {
		args.PINUVAuthParam = nil
	}
	ctapLogger.Printf("GET ASSERTION: %#v\n\n", args)

	// Gather all matching credentials for multi-assertion support
	sources := server.client.GetAssertionSources(args.RPID, args.AllowList)
	if len(sources) == 0 {
		ctapLogger.Printf("ERROR: No Credentials\n\n")
		return []byte{byte(ctap2ErrNoCredentials)}
	}
	credentialSource := sources[0]
	unsafeCtapLogger.Printf("CREDENTIAL SOURCE: %#v\n\n", credentialSource)

	wantUV := args.Options.UserVerification
	discoverable := len(args.AllowList) == 0
	uvRequired := wantUV || discoverable
	uvSatisfied := false
	if args.PINUVAuthParam != nil {
		if args.PINUVAuthProtocol != 1 {
			return []byte{byte(ctap2ErrPINAuthInvalid)}
		}
		token := server.pinTokenByChannel[server.currentChannelID]
		if token == nil {
			token = server.client.PINToken()
		}
		if token == nil || len(token) == 0 {
			return []byte{byte(ctap2ErrPINRequired)}
		}
		pinAuth := server.derivePINAuth(token, args.ClientDataHash)
		if !bytes.Equal(pinAuth, args.PINUVAuthParam) {
			return []byte{byte(ctap2ErrPINAuthInvalid)}
		}
		uvSatisfied = true
	} else if uvRequired {
		params := fido_client.ClientActionRequestParams{}
		if credentialSource.RelyingParty != nil {
			params.RelyingParty = credentialSource.RelyingParty.Name
		}
		if credentialSource.User != nil {
			params.UserName = credentialSource.User.Name
		}
		verified, status := server.attemptUserVerification(fido_client.ClientActionFIDOGetAssertion, params)
		if verified {
			uvSatisfied = true
		} else if status != nil {
			return []byte{byte(*status)}
		} else if server.client.SupportsPIN() && server.client.PINHash() != nil {
			return []byte{byte(ctap2ErrPINRequired)}
		} else if server.client.SupportsPIN() {
			return []byte{byte(ctap2ErrNoPINSet)}
		} else {
			return []byte{byte(ctap2ErrOperationDenied)}
		}
	}
	if uvSatisfied {
		flags = flags | authDataFlagUserVerified
	}

	if args.Options.UserPresence == nil || *args.Options.UserPresence {
		if !server.client.ApproveAccountLogin(credentialSource) {
			ctapLogger.Printf("ERROR: Unapproved action (Account login)")
			return []byte{byte(ctap2ErrOperationDenied)}
		}
		flags = flags | authDataFlagUserPresent
	}

	// Extension handling (hmac-secret)
	var extData []byte
	var hmacInput *hmacSecretInput
	if args.Extensions != nil {
		if raw, ok := args.Extensions["hmac-secret"]; ok {
			var in hmacSecretInput
			if err := cbor.Unmarshal(raw, &in); err == nil && in.SaltEnc != nil && in.SaltAuth != nil && in.KeyAgreement != nil {
				hmacInput = &in
				// Compute hmac-secret output for this credential
				out, ok := server.computeHmacSecretOutput(credentialSource, &in)
				if ok {
					// Build extension map {"hmac-secret": output}
					extMap := map[string][]byte{"hmac-secret": out}
					extData = util.MarshalCBOR(extMap)
				}
			}
		}
	}

	authData := makeAuthDataWithExtensions(args.RPID, credentialSource, nil, flags, extData)
	signature := credentialSource.PrivateKey.Sign(util.Concat(authData, args.ClientDataHash))

	credentialDescriptor := credentialSource.CTAPDescriptor()
	response := getAssertionResponse{
		Credential:          &credentialDescriptor,
		AuthenticatorData:   authData,
		Signature:           signature,
		User:                credentialSource.User,
		NumberOfCredentials: 0,
	}
	if len(sources) > 1 {
		response.NumberOfCredentials = int32(len(sources))
	}

	ctapLogger.Printf("GET ASSERTION RESPONSE: %#v\n\n", response)

	// Save remaining for GetNextAssertion if multiple
	if len(sources) > 1 && server.currentChannelID != 0 {
		sess := &assertionSession{rpID: args.RPID, clientDataHash: args.ClientDataHash}
		// Copy remaining
		rem := make([]*identities.CredentialSource, len(sources)-1)
		copy(rem, sources[1:])
		sess.remaining = rem
		if hmacInput != nil {
			sess.hmacInput = *hmacInput
			sess.useHmac = true
		}
		server.assertionSessions[server.currentChannelID] = sess
	}

	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

// ---------- hmac-secret support ----------
type hmacSecretInput struct {
	KeyAgreement *cose.COSEEC2Key `cbor:"1,keyasint,omitempty"`
	SaltEnc      []byte           `cbor:"2,keyasint,omitempty"`
	SaltAuth     []byte           `cbor:"3,keyasint,omitempty"`
}

func (server *CTAPServer) computeHmacSecretOutput(cred *identities.CredentialSource, in *hmacSecretInput) ([]byte, bool) {
	if cred.CredRandom == nil || len(cred.CredRandom) == 0 {
		return nil, false
	}
	sharedSecret := server.getPINSharedSecret(*in.KeyAgreement)
	// Verify saltAuth = HMAC(sharedSecret, saltEnc)[:16]
	if !bytes.Equal(server.derivePINAuth(sharedSecret, in.SaltEnc), in.SaltAuth) {
		return nil, false
	}
	salts := crypto.DecryptAESCBC(sharedSecret, in.SaltEnc)
	if len(salts) != 32 && len(salts) != 64 {
		return nil, false
	}
	// HMAC-SHA256(credRandom, salt)
	h := hmac.New(sha256.New, cred.CredRandom)
	h.Write(salts[:32])
	out1 := h.Sum(nil)
	if len(salts) == 32 {
		return out1, true
	}
	h2 := hmac.New(sha256.New, cred.CredRandom)
	h2.Write(salts[32:])
	out2 := h2.Sum(nil)
	return util.Concat(out1, out2), true
}

type assertionSession struct {
	rpID           string
	clientDataHash []byte
	remaining      []*identities.CredentialSource
	useHmac        bool
	hmacInput      hmacSecretInput
}

type pinSession struct {
	key *crypto.ECDHKey
}

func (server *CTAPServer) handleGetNextAssertion() []byte {
	sess, ok := server.assertionSessions[server.currentChannelID]
	if !ok || sess == nil || len(sess.remaining) == 0 {
		return []byte{byte(ctap1ErrInvalidSequence)}
	}
	// Pop next
	cred := sess.remaining[0]
	sess.remaining = sess.remaining[1:]

	var flags authDataFlags = 0
	// For simplicity: set UP on each next assertion (user presence was approved earlier)
	flags = flags | authDataFlagUserPresent

	var extData []byte
	if sess.useHmac {
		if out, ok := server.computeHmacSecretOutput(cred, &sess.hmacInput); ok {
			extMap := map[string][]byte{"hmac-secret": out}
			extData = util.MarshalCBOR(extMap)
		}
	}
	// Increment signature counter for this credential
	cred.SignatureCounter++
	server.client.SaveState()
	authData := makeAuthDataWithExtensions(sess.rpID, cred, nil, flags, extData)
	signature := cred.PrivateKey.Sign(util.Concat(authData, sess.clientDataHash))
	credDesc := cred.CTAPDescriptor()
	resp := getAssertionResponse{
		Credential:        &credDesc,
		AuthenticatorData: authData,
		Signature:         signature,
		User:              cred.User,
	}
	// Cleanup when done
	if len(sess.remaining) == 0 {
		delete(server.assertionSessions, server.currentChannelID)
	} else {
		server.assertionSessions[server.currentChannelID] = sess
	}
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(resp)...)
}

type clientPINSubcommand uint32

const (
	clientPINSubcommandGetRetries      clientPINSubcommand = 1
	clientPinSubcommandGetKeyAgreement clientPINSubcommand = 2
	clientPINSubcommandSetPIN          clientPINSubcommand = 3
	clientPINSubcommandChangePIN       clientPINSubcommand = 4
	clientPinSubcommandGetPINToken     clientPINSubcommand = 5
	// CTAP 2.1 additions
	clientPinSubcommandGetPinUvAuthTokenUsingPin clientPINSubcommand = 9
)

var clientPINSubcommandDescriptions = map[clientPINSubcommand]string{
	clientPINSubcommandGetRetries:                "clientPINSubcommandGetRetries",
	clientPinSubcommandGetKeyAgreement:           "clientPinSubcommandGetKeyAgreement",
	clientPINSubcommandSetPIN:                    "clientPINSubcommandSetPIN",
	clientPINSubcommandChangePIN:                 "clientPINSubcommandChangePIN",
	clientPinSubcommandGetPINToken:               "clientPinSubcommandGetPINToken",
	clientPinSubcommandGetPinUvAuthTokenUsingPin: "clientPinSubcommandGetPinUvAuthTokenUsingPin",
}

type clientPINArgs struct {
	PINUVAuthProtocol uint32              `cbor:"1,keyasint"`
	SubCommand        clientPINSubcommand `cbor:"2,keyasint"`
	KeyAgreement      *cose.COSEEC2Key    `cbor:"3,keyasint,omitempty"`
	PINUVAuthParam    []byte              `cbor:"4,keyasint,omitempty"`
	NewPINEncoding    []byte              `cbor:"5,keyasint,omitempty"`
	PINHashEncoding   []byte              `cbor:"6,keyasint,omitempty"`
	// CTAP 2.1 optional fields for getPinUvAuthTokenUsingPin
	Permissions *uint8 `cbor:"9,keyasint,omitempty"`
	RPID        string `cbor:"10,keyasint,omitempty"`
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
	KeyAgreement interface{} `cbor:"1,keyasint,omitempty"`
	PinToken     []byte      `cbor:"2,keyasint,omitempty"`
	Retries      *uint8      `cbor:"3,keyasint,omitempty"`
}

func (args clientPINResponse) String() string {
	return fmt.Sprintf("ctapClientPINResponse{KeyAgreement: %s, PinToken: %s, Retries: %#v}",
		args.KeyAgreement,
		hex.EncodeToString(args.PinToken),
		args.Retries)
}

func (server *CTAPServer) getPINSharedSecret(remoteKey cose.COSEEC2Key) []byte {
	var pinKey *crypto.ECDHKey
	used := server.currentChannelID
	if sess, ok := server.pinSessions[used]; ok && sess != nil && sess.key != nil {
		pinKey = sess.key
	} else if sess0, ok0 := server.pinSessions[0]; ok0 && sess0 != nil && sess0.key != nil {
		// Fallback to channel 0 bucket if channel was not propagated
		pinKey = sess0.key
		used = 0
	}
	if pinKey == nil {
		pinKey = server.client.PINKeyAgreement()
		ctapLogger.Printf("PIN SHARED SECRET using client key (chan=0x%x)\n\n", server.currentChannelID)
	} else {
		if used == 0 {
			ctapLogger.Printf("PIN SHARED SECRET using session key from chan=0x0 (fallback)\n\n")
		} else {
			ctapLogger.Printf("PIN SHARED SECRET using session key (chan=0x%x)\n\n", used)
		}
	}
	// ECDH X coordinate must be 32-byte big-endian before hashing (CTAP v1)
	x := pinKey.ECDH(util.BytesToBigInt(remoteKey.X), util.BytesToBigInt(remoteKey.Y))
	if len(x) != 32 {
		padded := make([]byte, 32)
		if len(x) > 32 {
			// Should not happen for P-256; take least significant 32 bytes
			copy(padded, x[len(x)-32:])
		} else {
			copy(padded[32-len(x):], x)
		}
		x = padded
	}
	return crypto.HashSHA256(x)
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

func (server *CTAPServer) attemptUserVerification(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) (bool, *ctapStatusCode) {
	if !server.client.SupportsUserVerification() {
		return false, nil
	}
	if server.client.VerifyUser(action, params) {
		return true, nil
	}
	if server.client.SupportsPIN() {
		if server.client.PINHash() != nil {
			status := ctap2ErrPINRequired
			return false, &status
		}
		status := ctap2ErrNoPINSet
		return false, &status
	}
	status := ctap2ErrOperationDenied
	return false, &status
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
	case clientPinSubcommandGetPinUvAuthTokenUsingPin:
		response = server.handleGetPinUvAuthTokenUsingPin(args)
	default:
		// Return INVALID_SUBCOMMAND for unknown ClientPIN subcommands
		return []byte{byte(ctap2ErrInvalidSubcommand)}
	}
	ctapLogger.Printf("CLIENT_PIN RESPONSE: %#v\n\n", response)
	return response
}

func (server *CTAPServer) handleGetRetries() []byte {
	// If no PIN has been set, CTAP2 requires returning ctap2ErrNoPINSet
	if server.client.PINHash() == nil {
		ctapLogger.Printf("CLIENT_PIN_GET_RETRIES: No PIN set\n\n")
		return []byte{byte(ctap2ErrNoPINSet)}
	}
	retries := uint8(server.client.PINRetries())
	response := clientPINResponse{Retries: &retries}
	ctapLogger.Printf("CLIENT_PIN_GET_RETRIES: %v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

func (server *CTAPServer) handleGetKeyAgreement() []byte {
	// Use per-channel ephemeral ECDH key and persist until token request completes
	var sess *pinSession
	cid := server.currentChannelID // may be 0 if HID didn't set channel
	if s, ok := server.pinSessions[cid]; ok && s != nil && s.key != nil {
		sess = s
	}
	if sess == nil {
		sess = &pinSession{key: crypto.GenerateECDHKey()}
		// Persist even when cid==0 as a fallback bucket
		server.pinSessions[cid] = sess
	}
	ctapLogger.Printf("CLIENT_PIN GET_KEY_AGREEMENT: generated ephemeral ECDH key for chan=0x%x\n\n", cid)
	key := sess.key
	// Ensure X and Y are 32-byte big-endian values
	pad32 := func(b []byte) []byte {
		if len(b) >= 32 {
			return b
		}
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	// COSE EC2 public key map (CTAP requires alg = -25 for PIN key agreement)
	coseKey := map[int]interface{}{
		1:  int64(cose.COSE_KEY_TYPE_EC2),               // kty = 2 (EC2)
		3:  int64(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256), // alg = -25 (ECDH-ES + HKDF-256)
		-1: int64(1),                                    // crv = 1 (P-256)
		-2: pad32(key.X.Bytes()),                        // x
		-3: pad32(key.Y.Bytes()),                        // y
	}
	response := clientPINResponse{KeyAgreement: coseKey}
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
	// Issue encrypted token; also cache plaintext per channel for MC/GA verification
	plain := server.client.PINToken()
	enc := crypto.EncryptAESCBC(sharedSecret, plain)
	response := clientPINResponse{PinToken: enc}
	if server.currentChannelID != 0 {
		server.pinTokenByChannel[server.currentChannelID] = plain
	}
	ctapLogger.Printf("GET_PIN_TOKEN RESPONSE: token(enc_len=%d) cached(chan=0x%x)\n\n", len(enc), server.currentChannelID)
	// Clear per-channel PIN session after successful token issuance
	if server.currentChannelID != 0 {
		delete(server.pinSessions, server.currentChannelID)
	}
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

// CTAP 2.1: getPinUvAuthTokenUsingPin behaves similarly to getPINToken (0x05)
// Minimal implementation: validate PIN and return encrypted pinUvAuthToken.
// Ignores permissions and rpId for now; server-side will accept the token for MC/GA without checking permissions.
func (server *CTAPServer) handleGetPinUvAuthTokenUsingPin(args clientPINArgs) []byte {
	if args.PINHashEncoding == nil || args.KeyAgreement == nil || args.KeyAgreement.X == nil {
		return []byte{byte(ctap2ErrMissingParam)}
	}
	if server.client.PINRetries() <= 0 {
		return []byte{byte(ctap2ErrPINBlocked)}
	}
	sharedSecret := server.getPINSharedSecret(*args.KeyAgreement)
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	pinHash := server.decryptPINHash(sharedSecret, args.PINHashEncoding)
	ctapLogger.Printf("TRYING PIN HASH (2.1): %v\n\n", hex.EncodeToString(pinHash))
	if !bytes.Equal(pinHash, server.client.PINHash()) {
		ctapLogger.Printf("MISMATCH (2.1): Provided PIN %v doesn't match stored PIN %v\n\n", hex.EncodeToString(pinHash), hex.EncodeToString(server.client.PINHash()))
		return []byte{byte(ctap2ErrPINInvalid)}
	}
	server.client.SetPINRetries(8)
	plain := server.client.PINToken()
	enc := crypto.EncryptAESCBC(sharedSecret, plain)
	response := clientPINResponse{PinToken: enc}
	if server.currentChannelID != 0 {
		server.pinTokenByChannel[server.currentChannelID] = plain
	}
	ctapLogger.Printf("GET_PIN_UV_TOKEN (2.1) RESPONSE: token(enc_len=%d) cached(chan=0x%x)\n\n", len(enc), server.currentChannelID)
	// Clear per-channel PIN session after successful token issuance
	if server.currentChannelID != 0 {
		delete(server.pinSessions, server.currentChannelID)
	}
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}
