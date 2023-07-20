package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/fxamacker/cbor/v2"
)

type COSEAlgorithmID int32

const (
	COSE_ALGORITHM_ID_ES256         COSEAlgorithmID = -7
	COSE_ALGORITHM_ID_ECDH_HKDF_256 COSEAlgorithmID = -25
	COSE_ALGORITHM_ID_ES512         COSEAlgorithmID = -36
	COSE_ALGORITHM_ID_ED25519       COSEAlgorithmID = -8
	COSE_ALGORITHM_ID_PS256         COSEAlgorithmID = -37
)

type coseCurveID int32

const (
	COSE_CURVE_ID_P256    coseCurveID = 1
	COSE_CURVE_ID_ED25519 coseCurveID = 6
)

type coseKeyType int32

const (
	COSE_KEY_TYPE_OKP       coseKeyType = 0b001
	COSE_KEY_TYPE_EC2       coseKeyType = 0b010
	COSE_KEY_TYPE_RSA       coseKeyType = 0b011
	COSE_KEY_TYPE_SYMMETRIC coseKeyType = 0b100
)

type SupportedCOSEPrivateKey struct {
	ECDSA   *ecdsa.PrivateKey
	Ed25519 *ed25519.PrivateKey
	RSA     *rsa.PrivateKey
}

func (key *SupportedCOSEPrivateKey) Equal(otherKey *SupportedCOSEPrivateKey) bool {
	if (key.ECDSA == nil) != (otherKey.ECDSA == nil) {
		// One is non-nil and the other is nil
		return false
	}
	if key.ECDSA != nil && !key.ECDSA.Equal(otherKey.ECDSA) {
		// Both are non-nil
		return false
	}
	if (key.Ed25519 == nil) != (otherKey.Ed25519 == nil) {
		return false
	}
	if key.Ed25519 != nil && !key.Ed25519.Equal(*otherKey.Ed25519) {
		return false
	}
	if (key.RSA == nil) != (otherKey.RSA == nil) {
		return false
	}
	if key.RSA != nil && !key.RSA.Equal(otherKey.RSA) {
		return false
	}
	return true
}

func (key *SupportedCOSEPrivateKey) Public() *SupportedCOSEPublicKey {
	coseKey := SupportedCOSEPublicKey{}
	if key.ECDSA != nil {
		coseKey.ECDSA = &key.ECDSA.PublicKey
	} else if key.Ed25519 != nil {
		edPublicKey := key.Ed25519.Public().(ed25519.PublicKey)
		coseKey.Ed25519 = &edPublicKey
	} else if key.RSA != nil {
		coseKey.RSA = &key.RSA.PublicKey
	} else {
		panic("No key provided in public key struct!")
	}
	return &coseKey
}

func (key *SupportedCOSEPrivateKey) Sign(data []byte) []byte {
	if key.ECDSA != nil {
		return crypto.SignECDSA(key.ECDSA, data)
	} else if key.Ed25519 != nil {
		return crypto.SignEd25519(key.Ed25519, data)
	} else if key.RSA != nil {
		return crypto.SignRSA(key.RSA, data)
	} else {
		panic("No supported private key data!")
	}
}

type SupportedCOSEPublicKey struct {
	ECDSA   *ecdsa.PublicKey
	Ed25519 *ed25519.PublicKey
	RSA     *rsa.PublicKey
}

func (key *SupportedCOSEPublicKey) Equal(otherKey *SupportedCOSEPublicKey) bool {
	if (key.ECDSA == nil) != (otherKey.ECDSA == nil) {
		// One is non-nil and the other is nil
		return false
	}
	if key.ECDSA != nil && !key.ECDSA.Equal(otherKey.ECDSA) {
		// Both are non-nil
		return false
	}
	if (key.Ed25519 == nil) != (otherKey.Ed25519 == nil) {
		return false
	}
	if key.Ed25519 != nil && !key.Ed25519.Equal(otherKey.Ed25519) {
		return false
	}
	if (key.RSA == nil) != (otherKey.RSA == nil) {
		return false
	}
	if key.RSA != nil && !key.RSA.Equal(otherKey.RSA) {
		return false
	}
	return true
}

func (key *SupportedCOSEPublicKey) Verify(data []byte, signature []byte) bool {
	if key.ECDSA != nil {
		return crypto.VerifyECDSA(key.ECDSA, data, signature)
	} else if key.Ed25519 != nil {
		return crypto.VerifyEd25519(key.Ed25519, data, signature)
	} else if key.RSA != nil {
		return crypto.VerifyRSA(key.RSA, data, signature)
	} else {
		panic("No supported private key data!")
	}
}

type COSEEC2Key struct {
	KeyType   int8   `cbor:"1,keyasint"`
	Algorithm int8   `cbor:"3,keyasint"`
	Curve     int8   `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
	D         []byte `cbor:"-4,keyasint,omitempty"`
}

func (key *COSEEC2Key) String() string {
	return fmt.Sprintf("COSEPublicKey{KeyType: %d, Algorithm: %d, Curve: %d, X: %s, Y: %s}",
		key.KeyType,
		key.Algorithm,
		key.Curve,
		hex.EncodeToString(key.X),
		hex.EncodeToString(key.Y))
}

func encodeECDSAPublicKey(publicKey *ecdsa.PublicKey) []byte {
	var alg COSEAlgorithmID
	var curve coseCurveID
	if publicKey.Curve == elliptic.P256() {
		alg = COSE_ALGORITHM_ID_ES256
		curve = COSE_CURVE_ID_P256
	} else {
		panic(fmt.Sprintf("Invalid key to encode with COSE"))
	}
	key := COSEEC2Key{
		KeyType:   int8(COSE_KEY_TYPE_EC2),
		Algorithm: int8(alg),
		Curve:     int8(curve),
		X:         publicKey.X.Bytes(),
		Y:         publicKey.Y.Bytes(),
	}
	return util.MarshalCBOR(key)
}

func decodeECDSAPublicKey(publicKeyBytes []byte) *ecdsa.PublicKey {
	key := COSEEC2Key{}
	err := cbor.Unmarshal(publicKeyBytes, &key)
	util.CheckErr(err, "Could not decode CBOR for public key")
	publicKey := ecdsa.PublicKey{}
	if key.Curve == int8(COSE_CURVE_ID_P256) {
		publicKey.Curve = elliptic.P256()
	} else {
		util.CheckErr(fmt.Errorf("Invalid curve"), "Curve is not P256")
	}
	publicKey.X = &big.Int{}
	publicKey.X.SetBytes(key.X)
	publicKey.Y = &big.Int{}
	publicKey.Y.SetBytes(key.Y)
	return &publicKey
}

func encodeECDSAPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	var alg COSEAlgorithmID
	var curve coseCurveID
	if privateKey.Curve == elliptic.P256() {
		alg = COSE_ALGORITHM_ID_ES256
		curve = COSE_CURVE_ID_P256
	} else {
		panic(fmt.Sprintf("Invalid key to encode with COSE"))
	}
	key := COSEEC2Key{
		KeyType:   int8(COSE_KEY_TYPE_EC2),
		Algorithm: int8(alg),
		Curve:     int8(curve),
		X:         privateKey.X.Bytes(),
		Y:         privateKey.Y.Bytes(),
		D:         privateKey.D.Bytes(),
	}
	return util.MarshalCBOR(key)
}

func decodeECDSAPrivateKey(privateKeyBytes []byte) *ecdsa.PrivateKey {
	key := COSEEC2Key{}
	err := cbor.Unmarshal(privateKeyBytes, &key)
	util.CheckErr(err, "Could not decode CBOR for public key")
	privateKey := ecdsa.PrivateKey{}
	if key.Curve == int8(COSE_CURVE_ID_P256) {
		privateKey.Curve = elliptic.P256()
	} else {
		util.CheckErr(fmt.Errorf("Invalid curve"), "Curve is not P256")
	}
	privateKey.X = &big.Int{}
	privateKey.X.SetBytes(key.X)
	privateKey.Y = &big.Int{}
	privateKey.Y.SetBytes(key.Y)
	privateKey.D = &big.Int{}
	privateKey.D.SetBytes(key.D)
	return &privateKey
}

type COSEOKPKey struct {
	KeyType   int8   `cbor:"1,keyasint"`
	Algorithm int8   `cbor:"3,keyasint"`
	Curve     int8   `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	D         []byte `cbor:"-4,keyasint,omitempty"`
}

func encodeEd25519PublicKey(publicKey *ed25519.PublicKey) []byte {
	key := COSEOKPKey{
		KeyType:   int8(COSE_KEY_TYPE_OKP),
		Algorithm: int8(COSE_ALGORITHM_ID_ED25519),
		Curve:     int8(COSE_CURVE_ID_ED25519),
		X:         *publicKey,
	}
	return util.MarshalCBOR(key)
}

func decodeEd25519PublicKey(publicKeyBytes []byte) *ed25519.PublicKey {
	key := COSEOKPKey{}
	err := cbor.Unmarshal(publicKeyBytes, &key)
	util.CheckErr(err, "Could not decode CBOR for COSE public key")
	return (*ed25519.PublicKey)(&key.X)
}

func encodeEd215519PrivateKey(privateKey *ed25519.PrivateKey) []byte {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	key := COSEOKPKey{
		KeyType:   int8(COSE_KEY_TYPE_OKP),
		Algorithm: int8(COSE_ALGORITHM_ID_ED25519),
		Curve:     int8(COSE_CURVE_ID_ED25519),
		X:         publicKey,
		D:         privateKey.Seed(),
	}
	return util.MarshalCBOR(key)
}

func decodeEd25519PrivateKey(privateKeyBytes []byte) *ed25519.PrivateKey {
	key := COSEOKPKey{}
	err := cbor.Unmarshal(privateKeyBytes, &key)
	util.CheckErr(err, "Could not decode CBOR for COSE private key")
	privateKey := ed25519.NewKeyFromSeed(key.D)
	return &privateKey
}

type COSERSAKey struct {
	KeyType   int8   `cbor:"1,keyasint"`
	Algorithm int8   `cbor:"3,keyasint"`
	N         []byte `cbor:"-1,keyasint"`
	E         []byte `cbor:"-2,keyasint"`
	D         []byte `cbor:"-3,keyasint,omitempty"`
	P         []byte `cbor:"-4,keyasint,omitempty"`
	Q         []byte `cbor:"-5,keyasint,omitempty"`
	Dp        []byte `cbor:"-6,keyasint,omitempty"`
	Dq        []byte `cbor:"-7,keyasint,omitempty"`
	Qinv      []byte `cbor:"-8,keyasint,omitempty"`
}

func encodeRSAPublicKey(publicKey *rsa.PublicKey) []byte {
	key := COSERSAKey{
		KeyType:   int8(COSE_KEY_TYPE_RSA),
		Algorithm: int8(COSE_ALGORITHM_ID_PS256),
		N:         publicKey.N.Bytes(),
		E:         util.ToBE(publicKey.E),
	}
	return util.MarshalCBOR(key)
}

func decodeRSAPublicKey(publicKeyBytes []byte) *rsa.PublicKey {
	key := COSERSAKey{}
	err := cbor.Unmarshal(publicKeyBytes, &key)
	util.CheckErr(err, "Could not unmarshal public key")
	publicKey := rsa.PublicKey{}
	publicKey.E = util.FromBE[int](key.E)
	publicKey.N = &big.Int{}
	publicKey.N.SetBytes(key.N)
	return &publicKey
}

func encodeRSAPrivateKey(privateKey *rsa.PrivateKey) []byte {
	publicKey := privateKey.PublicKey
	key := COSERSAKey{
		KeyType:   int8(COSE_KEY_TYPE_RSA),
		Algorithm: int8(COSE_ALGORITHM_ID_PS256),
		N:         publicKey.N.Bytes(),
		E:         util.ToBE(int32(publicKey.E)),
		D:         privateKey.D.Bytes(),
		P:         privateKey.Primes[0].Bytes(),
		Q:         privateKey.Primes[1].Bytes(),
		Dp:        privateKey.Precomputed.Dp.Bytes(),
		Dq:        privateKey.Precomputed.Dq.Bytes(),
		Qinv:      privateKey.Precomputed.Qinv.Bytes(),
	}
	return util.MarshalCBOR(key)
}

func decodeRSAPrivateKey(privateKeyBytes []byte) *rsa.PrivateKey {
	key := COSERSAKey{}
	err := cbor.Unmarshal(privateKeyBytes, &key)
	util.CheckErr(err, "Could not unmarshal public key")
	privateKey := rsa.PrivateKey{}
	privateKey.E = int(util.FromBE[int32](key.E))
	privateKey.N = &big.Int{}
	privateKey.N.SetBytes(key.N)
	privateKey.D = &big.Int{}
	privateKey.D.SetBytes(key.D)
	privateKey.Primes = make([]*big.Int, 2)
	privateKey.Primes[0] = &big.Int{}
	privateKey.Primes[1] = &big.Int{}
	privateKey.Primes[0].SetBytes(key.P)
	privateKey.Primes[1].SetBytes(key.Q)
	privateKey.Precompute()
	return &privateKey
}

func MarshalCOSEPublicKey(publicKey *SupportedCOSEPublicKey) []byte {
	if publicKey.ECDSA != nil {
		return encodeECDSAPublicKey(publicKey.ECDSA)
	} else if publicKey.Ed25519 != nil {
		return encodeEd25519PublicKey(publicKey.Ed25519)
	} else if publicKey.RSA != nil {
		return encodeRSAPublicKey(publicKey.RSA)
	} else {
		panic("No key provided in public key struct!")
	}
}

type COSEKeyHeader struct {
	KeyType   int8 `cbor:"1,keyasint"`
	Algorithm int8 `cbor:"3,keyasint"`
}

func UnmarshalCOSEPublicKey(publicKeyBytes []byte) (*SupportedCOSEPublicKey, error) {
	header := COSEKeyHeader{}
	err := cbor.Unmarshal(publicKeyBytes, &header)
	if err != nil {
		return nil, fmt.Errorf("Could not decode CBOR for public key")
	}
	if header.Algorithm == int8(COSE_ALGORITHM_ID_ES256) {
		publicKey := decodeECDSAPublicKey(publicKeyBytes)
		coseKey := SupportedCOSEPublicKey{ECDSA: publicKey}
		return &coseKey, nil
	} else if header.Algorithm == int8(COSE_ALGORITHM_ID_ED25519) {
		publicKey := decodeEd25519PublicKey(publicKeyBytes)
		coseKey := SupportedCOSEPublicKey{Ed25519: publicKey}
		return &coseKey, nil
	} else if header.Algorithm == int8(COSE_ALGORITHM_ID_PS256) {
		publicKey := decodeRSAPublicKey(publicKeyBytes)
		coseKey := SupportedCOSEPublicKey{RSA: publicKey}
		return &coseKey, nil
	} else {
		return nil, fmt.Errorf("Unsupported COSE public key algorithm: %d", header.Algorithm)
	}
}

func MarshalCOSEPrivateKey(privateKey *SupportedCOSEPrivateKey) []byte {
	if privateKey.ECDSA != nil {
		return encodeECDSAPrivateKey(privateKey.ECDSA)
	} else if privateKey.Ed25519 != nil {
		return encodeEd215519PrivateKey(privateKey.Ed25519)
	} else if privateKey.RSA != nil {
		return encodeRSAPrivateKey(privateKey.RSA)
	} else {
		panic("No key provided in public key struct!")
	}
}

func UnmarshalCOSEPrivateKey(privateKeyBytes []byte) (*SupportedCOSEPrivateKey, error) {
	header := COSEKeyHeader{}
	err := cbor.Unmarshal(privateKeyBytes, &header)
	if err != nil {
		return nil, fmt.Errorf("Could not decode CBOR for private key")
	}
	if header.Algorithm == int8(COSE_ALGORITHM_ID_ES256) {
		privateKey := decodeECDSAPrivateKey(privateKeyBytes)
		coseKey := SupportedCOSEPrivateKey{ECDSA: privateKey}
		return &coseKey, nil
	} else if header.Algorithm == int8(COSE_ALGORITHM_ID_ED25519) {
		privateKey := decodeEd25519PrivateKey(privateKeyBytes)
		coseKey := SupportedCOSEPrivateKey{Ed25519: privateKey}
		return &coseKey, nil
	} else if header.Algorithm == int8(COSE_ALGORITHM_ID_PS256) {
		privateKey := decodeRSAPrivateKey(privateKeyBytes)
		coseKey := SupportedCOSEPrivateKey{RSA: privateKey}
		return &coseKey, nil
	} else {
		return nil, fmt.Errorf("Unsupported COSE private key algorithm: %d", header.Algorithm)
	}
}
