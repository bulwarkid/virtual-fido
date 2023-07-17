package webauthn

import (
	"encoding/hex"
	"fmt"

	"github.com/bulwarkid/virtual-fido/cose"
)

type PublicKeyCredentialRPEntity struct {
	ID   string `cbor:"id" json:"id"`
	Name string `cbor:"name" json:"name"`
}

func (rp PublicKeyCredentialRPEntity) String() string {
	return fmt.Sprintf("RPEntity{ ID: %s, Name: %s }",
		rp.ID, rp.Name)
}

type PublicKeyCrendentialUserEntity struct {
	ID          []byte `cbor:"id" json:"id"`
	DisplayName string `cbor:"displayName" json:"display_name"`
	Name        string `cbor:"name" json:"name"`
}

func (user PublicKeyCrendentialUserEntity) String() string {
	return fmt.Sprintf("User{ ID: %s, DisplayName: %s, Name: %s }",
		hex.EncodeToString(user.ID),
		user.DisplayName,
		user.Name)
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `cbor:"type"`
	ID         []byte   `cbor:"id"`
	Transports []string `cbor:"transports,omitempty"`
}

type PublicKeyCredentialParams struct {
	Type      string               `cbor:"type"`
	Algorithm cose.COSEAlgorithmID `cbor:"alg"`
}

type KeyHandle struct {
	PrivateKey    []byte `cbor:"1,keyasint"`
	ApplicationID []byte `cbor:"2,keyasint"`
}
