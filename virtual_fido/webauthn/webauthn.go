package webauthn

import (
	"encoding/hex"
	"fmt"

	"github.com/bulwarkid/virtual-fido/virtual_fido/cose"
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
	Algorithm cose.COSEAlgorithmID `cbor:"alg"`
}

type KeyHandle struct {
	PrivateKey    []byte `cbor:"1,keyasint"`
	ApplicationID []byte `cbor:"2,keyasint"`
}