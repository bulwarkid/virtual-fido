package virtual_fido

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var u2fLogger = newLogger("[U2F] ", true)

type U2FCommand uint8

const (
	U2F_COMMAND_REGISTER     U2FCommand = 0x01
	U2F_COMMAND_AUTHENTICATE U2FCommand = 0x02
	U2F_COMMAND_VERSION      U2FCommand = 0x03
)

var u2fCommandDescriptions = map[U2FCommand]string{
	U2F_COMMAND_REGISTER:     "U2F_COMMAND_REGISTER",
	U2F_COMMAND_AUTHENTICATE: "U2F_COMMAND_AUTHENTICATE",
	U2F_COMMAND_VERSION:      "U2F_COMMAND_VERSION",
}

type U2FStatusWord uint16

const (
	U2F_SW_NO_ERROR                 U2FStatusWord = 0x9000
	U2F_SW_CONDITIONS_NOT_SATISFIED U2FStatusWord = 0x6985
	U2F_SW_WRONG_DATA               U2FStatusWord = 0x6A80
	U2F_SW_WRONG_LENGTH             U2FStatusWord = 0x6700
	U2F_SW_CLA_NOT_SUPPORTED        U2FStatusWord = 0x6E00
	U2F_SW_INS_NOT_SUPPORTED        U2FStatusWord = 0x6D00
)

type U2FAuthenticateControl uint8

const (
	U2F_AUTH_CONTROL_CHECK_ONLY                     U2FAuthenticateControl = 0x07
	U2F_AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN U2FAuthenticateControl = 0x03
	U2F_AUTH_CONTROL_SIGN                           U2FAuthenticateControl = 0x08
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
		u2fCommandDescriptions[header.Command],
		header.Param1,
		header.Param2)
}

type U2FServer struct {
	client Client
}

func newU2FServer(client Client) *U2FServer {
	return &U2FServer{client: client}
}

func decodeU2FMessage(messageBytes []byte) (U2FMessageHeader, []byte, uint16) {
	buffer := bytes.NewBuffer(messageBytes)
	header := readBE[U2FMessageHeader](buffer)
	if buffer.Len() == 0 {
		// No reqest length, no reponse length
		return header, []byte{}, 0
	}
	// We should either have a request length or reponse length, so we have at least
	// one '0' byte at the start
	if read(buffer, 1)[0] != 0 {
		panic(fmt.Sprintf("Invalid U2F Payload length: %s %#v", header, messageBytes))
	}
	length := readBE[uint16](buffer)
	if buffer.Len() == 0 {
		// No payload, so length must be the response length
		return header, []byte{}, length
	}
	// length is the request length
	request := read(buffer, uint(length))
	if buffer.Len() == 0 {
		return header, request, 0
	}
	responseLength := readBE[uint16](buffer)
	return header, request, responseLength
}

func (server *U2FServer) handleU2FMessage(message []byte) []byte {
	header, request, responseLength := decodeU2FMessage(message)
	u2fLogger.Printf("U2F MESSAGE: Header: %s Request: %#v Reponse Length: %d\n\n", header, request, responseLength)
	var response []byte
	switch header.Command {
	case U2F_COMMAND_VERSION:
		response = append([]byte("U2F_V2"), toBE(U2F_SW_NO_ERROR)...)
	case U2F_COMMAND_REGISTER:
		response = server.handleU2FRegister(header, request)
	case U2F_COMMAND_AUTHENTICATE:
		response = server.handleU2FAuthenticate(header, request)
	default:
		panic(fmt.Sprintf("Invalid U2F Command: %#v", header))
	}
	u2fLogger.Printf("U2F RESPONSE: %#v\n\n", response)
	return response
}

type KeyHandle struct {
	PrivateKey    []byte `cbor:"1,keyasint"`
	ApplicationID []byte `cbor:"2,keyasint"`
}

func (server *U2FServer) sealKeyHandle(keyHandle *KeyHandle) []byte {
	data, err := cbor.Marshal(keyHandle)
	checkErr(err, "Could not encode key handle")
	box := seal(server.client.SealingEncryptionKey(), data)
	boxBytes, err := cbor.Marshal(box)
	checkErr(err, "Could not encode encrypted box")
	return boxBytes
}

func (server *U2FServer) openKeyHandle(boxBytes []byte) *KeyHandle {
	var box EncryptedBox
	err := cbor.Unmarshal(boxBytes, &box)
	checkErr(err, "Could not decode encrypted box")
	data := open(server.client.SealingEncryptionKey(), box)
	var keyHandle KeyHandle
	err = cbor.Unmarshal(data, &keyHandle)
	checkErr(err, "Could not decode key handle")
	return &keyHandle
}

func (server *U2FServer) handleU2FRegister(header U2FMessageHeader, request []byte) []byte {
	challenge := request[:32]
	application := request[32:]
	assert(len(challenge) == 32, "Challenge is not 32 bytes")
	assert(len(application) == 32, "Application is not 32 bytes")

	privateKey := server.client.NewPrivateKey()
	encodedPublicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	encodedPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	checkErr(err, "Could not encode private key")

	unencryptedKeyHandle := KeyHandle{PrivateKey: encodedPrivateKey, ApplicationID: application}
	keyHandle := server.sealKeyHandle(&unencryptedKeyHandle)
	u2fLogger.Printf("KEY HANDLE: %d %#v\n\n", len(keyHandle), keyHandle)

	cert := server.client.CreateAttestationCertificiate(privateKey)

	signatureDataBytes := flatten([][]byte{{0}, application, challenge, keyHandle, encodedPublicKey})
	signature := sign(privateKey, signatureDataBytes)

	return flatten([][]byte{{0x05}, encodedPublicKey, {uint8(len(keyHandle))}, keyHandle, cert, signature, toBE(U2F_SW_NO_ERROR)})
}

func (server *U2FServer) handleU2FAuthenticate(header U2FMessageHeader, request []byte) []byte {
	// TODO: Check user presence
	requestReader := bytes.NewBuffer(request)
	control := U2FAuthenticateControl(header.Param1)
	challenge := read(requestReader, 32)
	application := read(requestReader, 32)

	keyHandleLength := readLE[uint8](requestReader)
	encryptedKeyHandleBytes := read(requestReader, uint(keyHandleLength))
	keyHandle := server.openKeyHandle(encryptedKeyHandleBytes)
	if keyHandle.PrivateKey == nil || bytes.Compare(keyHandle.ApplicationID, application) != 0 {
		u2fLogger.Printf("U2F AUTHENTICATE: Invalid input data %#v\n\n", keyHandle)
		return flatten([][]byte{toBE(U2F_SW_WRONG_DATA)})
	}
	privateKey, err := x509.ParseECPrivateKey(keyHandle.PrivateKey)
	checkErr(err, "Could not decode private key")

	if control == U2F_AUTH_CONTROL_CHECK_ONLY {
		return flatten([][]byte{toBE(U2F_SW_CONDITIONS_NOT_SATISFIED)})
	} else {
		counter := server.client.NewAuthenticationCounterId()
		signatureDataBytes := flatten([][]byte{application, {1}, toBE(counter), challenge})
		signature := sign(privateKey, signatureDataBytes)
		return flatten([][]byte{{1}, toBE(counter), signature, toBE(U2F_SW_NO_ERROR)})
	}
}
