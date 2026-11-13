package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	data := []byte("data")
	key := GenerateSymmetricKey()
	encryptedData, nonce, err := Encrypt(key, data)
	if err != nil {
		t.Fatal(err)
	}
	decryptedData, err := Decrypt(key, encryptedData, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Fatalf("'%s' does not match '%s'", string(decryptedData), string(data))
	}
}

func TestSignVerifyECDSA(t *testing.T) {
	data := []byte("data")
	key := GenerateECDSAKey()
	signature := SignECDSA(key, data)
	if !VerifyECDSA(&key.PublicKey, data, signature) {
		t.Fatalf("Signature not correct: %#v", signature)
	}
}

func TestSignVerifyEd25519(t *testing.T) {
	data := []byte("data")
	key := GenerateEd25519Key()
	signature := SignEd25519(key, data)
	publicKey := key.Public().(ed25519.PublicKey)
	if !VerifyEd25519(&publicKey, data, signature) {
		t.Fatalf("Signature not correct: %#v", signature)
	}
}

func TestSignVerifyRSA(t *testing.T) {
	data := []byte("data")
	key := GenerateRSAKey()
	signature := SignRSA(key, data)
	if !VerifyRSA(&key.PublicKey, data, signature) {
		t.Fatalf("Signature not correct: %#v", signature)
	}
}

func TestSealOpen(t *testing.T) {
	data := []byte("data")
	key := GenerateSymmetricKey()
	box := Seal(key, data)
	decryptedData := Open(key, box)
	if !bytes.Equal(data, decryptedData) {
		t.Fatalf("'%s' does not equal '%s'", decryptedData, data)
	}
}

func TestHashSHA256(t *testing.T) {
	data := []byte("test")
	target := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	hash := HashSHA256(data)
	encodedHash := hex.EncodeToString(hash)
	if encodedHash != target {
		t.Fatalf("'%s' does not equal '%s'", encodedHash, target)
	}
}

func TestEncryptDecryptAESCBC(t *testing.T) {
	data := RandomBytes(32)
	key := GenerateSymmetricKey()
	encryptedData := EncryptAESCBC(key, data)
	decryptedData := DecryptAESCBC(key, encryptedData)
	if !bytes.Equal(data, decryptedData) {
		t.Fatalf("'%s' does not equal '%s'", hex.EncodeToString(decryptedData), hex.EncodeToString(data))
	}
}

func TestECDHSecretIsFullLength(t *testing.T) {
	// About 1 in 256 shared secrets starts with a zero byte; try enough key
	// pairs to hit some. Both sides must hash the full 32-byte x-coordinate.
	for i := 0; i < 2000; i++ {
		local := GenerateECDHKey()
		remote := GenerateECDHKey()
		secret := local.ECDH(remote.X, remote.Y)
		if len(secret) != 32 {
			t.Fatalf("Shared secret is %d bytes, not 32", len(secret))
		}
	}
}
