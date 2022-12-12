package cose

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/bulwarkid/virtual-fido/virtual_fido/util"
)

type COSEAlgorithmID int32

const (
	COSE_ALGORITHM_ID_ES256         COSEAlgorithmID = -7
	COSE_ALGORITHM_ID_ECDH_HKDF_256 COSEAlgorithmID = -25
)

type coseCurveID int32

const (
	COSE_CURVE_ID_P256 coseCurveID = 1
)

type coseKeyType int32

const (
	COSE_KEY_TYPE_OKP       coseKeyType = 0b001
	COSE_KEY_TYPE_EC2       coseKeyType = 0b010
	COSE_KEY_TYPE_SYMMETRIC coseKeyType = 0b100
)

type COSEPublicKey struct {
	KeyType   int8   `cbor:"1,keyasint"`  // Key Type
	Algorithm int8   `cbor:"3,keyasint"`  // Key Algorithm
	Curve     int8   `cbor:"-1,keyasint"` // Key Curve
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

func (key *COSEPublicKey) String() string {
	return fmt.Sprintf("COSEPublicKey{KeyType: %d, Algorithm: %d, Curve: %d, X: %s, Y: %s}",
		key.KeyType,
		key.Algorithm,
		key.Curve,
		hex.EncodeToString(key.X),
		hex.EncodeToString(key.Y))
}

func EncodeKeyAsCOSE(publicKey *ecdsa.PublicKey) []byte {
	key := COSEPublicKey{
		KeyType:   int8(COSE_KEY_TYPE_EC2),
		Algorithm: int8(COSE_ALGORITHM_ID_ES256),
		Curve:     int8(COSE_CURVE_ID_P256),
		X:         publicKey.X.Bytes(),
		Y:         publicKey.Y.Bytes(),
	}
	return util.MarshalCBOR(key)
}