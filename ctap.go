package main

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type CTAPCommand uint8

const (
	CTAP_COMMAND_MAKE_CREDENTIAL    CTAPCommand = 0x01
	CTAP_COMMAND_GET_ASSERTION      CTAPCommand = 0x02
	CTAP_COMMAND_GET_INFO           CTAPCommand = 0x04
	CTAP_COMMAND_CLIENT_PIN         CTAPCommand = 0x06
	CTAP_COMMAND_RESET              CTAPCommand = 0x07
	CTAP_COMMAND_GET_NEXT_ASSERTION CTAPCommand = 0x08
)

func parseMessage(data []byte) {
	command := CTAPCommand(data[0])
	switch command {
	case CTAP_COMMAND_MAKE_CREDENTIAL:
		handleMakeCredential(data[1:])
	default:
		panic(fmt.Sprintf("Invalid CTAP Command: %d", command))
	}
}

type PublicKeyCredentialRpEntity struct {
	Id string `cbor:"id"`
}

type PublicKeyCrendentialUserEntity struct {
	Id          []byte `cbor:"id"`
	DisplayName string `cbor:"displayName"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `cbor:"type"`
	Id         []byte   `cbor:"id"`
	Transports []string `cbor:"transports,omitempty"`
}

type CTAPMakeCredentialArgsOptions struct {
	Rk bool `cbor:"rk"`
	Uv bool `cbor:"uv"`
}

type CTAPMakeCredentialArgs struct {
	ClientDataHash   []byte                          `cbor:"1,keyasint,omitempty"`
	Rp               PublicKeyCredentialRpEntity     `cbor:"2,keyasint,omitempty"`
	User             PublicKeyCrendentialUserEntity  `cbor:"3,keyasint,omitempty"`
	PubKeyCredParams []byte                          `cbor:"4,keyasint,omitempty"`
	ExcludeList      []PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Options          CTAPMakeCredentialArgsOptions   `cbor:"7,keyasint,omitempty"`
}

func handleMakeCredential(data []byte) {
	var args CTAPMakeCredentialArgs
	err := cbor.Unmarshal(data, &args)
	checkErr(err, fmt.Sprintf("Could not decode CBOR for MAKE_CREDENTIAL: %s %v", err, data))
}
