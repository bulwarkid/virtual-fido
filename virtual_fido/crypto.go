package virtual_fido

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

func encrypt(key []byte, data []byte) ([]byte, []byte) {
	// TODO: Handle errors more reliably than panicing
	block, err := aes.NewCipher(key)
	checkErr(err, "Could not create device cipher")
	nonce := read(rand.Reader, 12)
	gcm, err := cipher.NewGCM(block)
	checkErr(err, "Could not create GCM mode")
	encryptedData := gcm.Seal(nil, nonce, data, nil)
	return encryptedData, nonce
}

func decrypt(key []byte, data []byte, nonce []byte) []byte {
	// TODO: Handle errors more reliably than panicing
	block, err := aes.NewCipher(key)
	checkErr(err, "Could not create device cipher")
	gcm, err := cipher.NewGCM(block)
	checkErr(err, "Could not create GCM mode")
	decryptedData, err := gcm.Open(nil, nonce, data, nil)
	checkErr(err, "Could not decrypt data")
	return decryptedData
}

func sign(key *ecdsa.PrivateKey, data []byte) []byte {
	hash := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	checkErr(err, "Could not sign data")
	return signature
}

func verify(key *ecdsa.PublicKey, data []byte, signature []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(key, hash[:], signature)
}

type encryptedBox struct {
	Data []byte `cbor:"1,keyasint"`
	IV   []byte `cbor:"2,keyasint"`
}

func seal(key []byte, data []byte) encryptedBox {
	encryptedData, iv := encrypt(key, data)
	return encryptedBox{Data: encryptedData, IV: iv}
}

func open(key []byte, box encryptedBox) []byte {
	return decrypt(key, box.Data, box.IV)
}
