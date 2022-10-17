package virtual_fido

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/scrypt"
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

type passphraseEncryptedBlob struct {
	Salt          []byte
	EncryptedKey  []byte
	KeyNonce      []byte
	EncryptedData []byte
	DataNonce     []byte
}

func encryptWithPassphrase(passphrase string, data []byte) passphraseEncryptedBlob {
	salt := read(rand.Reader, 16)
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	checkErr(err, "Could not create key encryption key")
	encryptionKey := read(rand.Reader, 32)
	encryptedKey, keyNonce := encrypt(keyEncryptionKey, encryptionKey)
	encryptedData, dataNonce := encrypt(encryptionKey, data)
	return passphraseEncryptedBlob{
		Salt:          salt,
		EncryptedKey:  encryptedKey,
		KeyNonce:      keyNonce,
		EncryptedData: encryptedData,
		DataNonce:     dataNonce,
	}
}

func decryptWithPassphrase(passphrase string, blob passphraseEncryptedBlob) []byte {
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), blob.Salt, 32768, 8, 1, 32)
	checkErr(err, "Could not create key encryption key")
	encryptionKey := decrypt(keyEncryptionKey, blob.EncryptedKey, blob.KeyNonce)
	return decrypt(encryptionKey, blob.EncryptedData, blob.DataNonce)
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
