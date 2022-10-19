package virtual_fido

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func encrypt(key []byte, data []byte) ([]byte, []byte, error) {
	// TODO: Handle errors more reliably than panicing
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create device cipher: %w", err)
	}
	nonce := read(rand.Reader, 12)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create GCM mode: %w", err)
	}
	encryptedData := gcm.Seal(nil, nonce, data, nil)
	return encryptedData, nonce, nil
}

func decrypt(key []byte, data []byte, nonce []byte) ([]byte, error) {
	// TODO: Handle errors more reliably than panicing
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Could not create device cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Could not create GCM mode: %w", err)
	}
	decryptedData, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	return decryptedData, nil
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
	encryptedData, iv, err := encrypt(key, data)
	checkErr(err, "Could not seal data")
	return encryptedBox{Data: encryptedData, IV: iv}
}

func open(key []byte, box encryptedBox) []byte {
	data, err := decrypt(key, box.Data, box.IV)
	checkErr(err, "Could not open data")
	return data
}
