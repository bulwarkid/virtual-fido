package u2f

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

var u2fLogger = util.NewLogger("[U2F] ", util.LogLevelDebug)

type U2FCommand uint8

const (
	u2f_COMMAND_REGISTER     U2FCommand = 0x01
	u2f_COMMAND_AUTHENTICATE U2FCommand = 0x02
	u2f_COMMAND_VERSION      U2FCommand = 0x03
)

var U2FCommandDescriptions = map[U2FCommand]string{
	u2f_COMMAND_REGISTER:     "u2f_COMMAND_REGISTER",
	u2f_COMMAND_AUTHENTICATE: "u2f_COMMAND_AUTHENTICATE",
	u2f_COMMAND_VERSION:      "u2f_COMMAND_VERSION",
}

type U2FStatusWord uint16

const (
	u2f_SW_NO_ERROR                 U2FStatusWord = 0x9000
	u2f_SW_CONDITIONS_NOT_SATISFIED U2FStatusWord = 0x6985
	u2f_SW_WRONG_DATA               U2FStatusWord = 0x6A80
	u2f_SW_WRONG_LENGTH             U2FStatusWord = 0x6700
	u2f_SW_CLA_NOT_SUPPORTED        U2FStatusWord = 0x6E00
	u2f_SW_INS_NOT_SUPPORTED        U2FStatusWord = 0x6D00
)

type U2FAuthenticateControl uint8

const (
	u2f_AUTH_CONTROL_CHECK_ONLY                     U2FAuthenticateControl = 0x07
	u2f_AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN U2FAuthenticateControl = 0x03
	u2f_AUTH_CONTROL_SIGN                           U2FAuthenticateControl = 0x08
)

type U2FMessageHeader struct {
	Cla     uint8
	Command U2FCommand
	Param1  uint8
	Param2  uint8
}

func (header U2FMessageHeader) String() string {
	return fmt.Sprintf("U2FMessageHeader{ Cla: 0x%x, Command: %s, Param1: %d, Param2: %d }",
		header.Cla,
		U2FCommandDescriptions[header.Command],
		header.Param1,
		header.Param2)
}

type U2FClient interface {
	SealingEncryptionKey() []byte
	NewPrivateKey() *ecdsa.PrivateKey
	NewAuthenticationCounterId() uint32
	CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte
	ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool
	ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool
}

type U2FServer struct {
	client U2FClient
}

func NewU2FServer(client U2FClient) *U2FServer {
	return &U2FServer{client: client}
}

func decodeU2FMessage(messageBytes []byte) (U2FMessageHeader, []byte, uint16) {
	buffer := bytes.NewBuffer(messageBytes)
	header := util.ReadBE[U2FMessageHeader](buffer)
	if buffer.Len() == 0 {
		// No request length, no response length
		return header, []byte{}, 0
	}
	// We should either have a request length or response length, so we have at least
	// one '0' byte at the start
	if util.Read(buffer, 1)[0] != 0 {
		panic(fmt.Sprintf("Invalid U2F Payload length: %s %#v", header, messageBytes))
	}
	length := util.ReadBE[uint16](buffer)
	if buffer.Len() == 0 {
		// No payload, so length must be the response length
		return header, []byte{}, length
	}
	// length is the request length
	request := util.Read(buffer, uint(length))
	if buffer.Len() == 0 {
		return header, request, 0
	}
	responseLength := util.ReadBE[uint16](buffer)
	return header, request, responseLength
}

func (server *U2FServer) HandleMessage(message []byte) []byte {
	header, request, responseLength := decodeU2FMessage(message)
	u2fLogger.Printf("MESSAGE: Header: %s Request: %#v Response Length: %d\n\n", header, request, responseLength)
	var response []byte
	switch header.Command {
	case u2f_COMMAND_VERSION:
		response = append([]byte("U2F_V2"), util.ToBE(u2f_SW_NO_ERROR)...)
	case u2f_COMMAND_REGISTER:
		response = server.handleU2FRegister(header, request)
	case u2f_COMMAND_AUTHENTICATE:
		response = server.handleU2FAuthenticate(header, request)
	default:
		panic(fmt.Sprintf("Invalid U2F Command: %#v", header))
	}
	u2fLogger.Printf("RESPONSE: %#v\n\n", response)
	return response
}

func (server *U2FServer) sealKeyHandle(keyHandle *webauthn.KeyHandle) []byte {
	box := crypto.Seal(server.client.SealingEncryptionKey(), util.MarshalCBOR(keyHandle))
	return util.MarshalCBOR(box)
}

func (server *U2FServer) openKeyHandle(boxBytes []byte) (*webauthn.KeyHandle, error) {
	var box crypto.EncryptedBox
	err := cbor.Unmarshal(boxBytes, &box)
	if err != nil {
		return nil, err
	}
	data := crypto.Open(server.client.SealingEncryptionKey(), box)
	var keyHandle webauthn.KeyHandle
	err = cbor.Unmarshal(data, &keyHandle)
	if err != nil {
		return nil, err
	}
	return &keyHandle, nil
}

func (server *U2FServer) handleU2FRegister(header U2FMessageHeader, request []byte) []byte {
	challenge := request[:32]
	application := request[32:]
	util.Assert(len(challenge) == 32, "Challenge is not 32 bytes")
	util.Assert(len(application) == 32, "Application is not 32 bytes")

	privateKey := server.client.NewPrivateKey()
	encodedPublicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	encodedPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	util.CheckErr(err, "Could not encode private key")

	unencryptedKeyHandle := webauthn.KeyHandle{PrivateKey: encodedPrivateKey, ApplicationID: application}
	keyHandle := server.sealKeyHandle(&unencryptedKeyHandle)
	u2fLogger.Printf("KEY HANDLE: %d %#v\n\n", len(keyHandle), keyHandle)

	if !server.client.ApproveU2FRegistration(&unencryptedKeyHandle) {
		return util.ToBE(u2f_SW_CONDITIONS_NOT_SATISFIED)
	}

	cosePrivateKey := &cose.SupportedCOSEPrivateKey{ECDSA: privateKey}
	cert := server.client.CreateAttestationCertificiate(cosePrivateKey)

	signatureDataBytes := util.Concat([]byte{0}, application, challenge, keyHandle, encodedPublicKey)
	signature := cosePrivateKey.Sign(signatureDataBytes)

	return util.Concat([]byte{0x05}, encodedPublicKey, []byte{uint8(len(keyHandle))}, keyHandle, cert, signature, util.ToBE(u2f_SW_NO_ERROR))
}

func (server *U2FServer) handleU2FAuthenticate(header U2FMessageHeader, request []byte) []byte {
	requestReader := bytes.NewBuffer(request)
	control := U2FAuthenticateControl(header.Param1)
	challenge := util.Read(requestReader, 32)
	application := util.Read(requestReader, 32)

	keyHandleLength := util.ReadLE[uint8](requestReader)
	encryptedKeyHandleBytes := util.Read(requestReader, uint(keyHandleLength))
	keyHandle, err := server.openKeyHandle(encryptedKeyHandleBytes)
	if err != nil {
		u2fLogger.Printf("U2F AUTHENTICATE: Invalid key handle given - %s %#v\n\n", err, encryptedKeyHandleBytes)
		return util.ToBE(u2f_SW_WRONG_DATA)
	}
	if keyHandle.PrivateKey == nil || bytes.Compare(keyHandle.ApplicationID, application) != 0 {
		u2fLogger.Printf("U2F AUTHENTICATE: Invalid input data %#v\n\n", keyHandle)
		return util.ToBE(u2f_SW_WRONG_DATA)
	}
	privateKey, err := x509.ParseECPrivateKey(keyHandle.PrivateKey)
	util.CheckErr(err, "Could not decode private key")
	cosePrivateKey := &cose.SupportedCOSEPrivateKey{ECDSA: privateKey}

	if control == u2f_AUTH_CONTROL_CHECK_ONLY {
		return util.ToBE(u2f_SW_CONDITIONS_NOT_SATISFIED)
	} else if control == u2f_AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN || control == u2f_AUTH_CONTROL_SIGN {
		if control == u2f_AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN {
			if !server.client.ApproveU2FAuthentication(keyHandle) {
				return util.ToBE(u2f_SW_CONDITIONS_NOT_SATISFIED)
			}
		}
		counter := server.client.NewAuthenticationCounterId()
		signatureDataBytes := util.Concat(application, []byte{1}, util.ToBE(counter), challenge)
		signature := cosePrivateKey.Sign(signatureDataBytes)
		return util.Concat([]byte{1}, util.ToBE(counter), signature, util.ToBE(u2f_SW_NO_ERROR))
	} else {
		// No error specific to invalid control byte, so return WRONG_LENGTH to indicate data error
		return util.ToBE(u2f_SW_WRONG_LENGTH)
	}
}
