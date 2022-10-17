package virtual_fido

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

type SavedCredentialSource struct {
	Type             string                         `json:"type"`
	ID               []byte                         `json:"id"`
	PrivateKey       []byte                         `json:"private_key"`
	RelyingParty     PublicKeyCredentialRpEntity    `json:"relying_party"`
	User             PublicKeyCrendentialUserEntity `json:"user"`
	SignatureCounter int32                          `json:"signature_counter"`
}

type FIDODeviceConfig struct {
	EncryptionKey          []byte                  `json:"encryption_key"`
	AttestationCertificate []byte                  `json:"attestation_certificate"`
	AttestationPrivateKey  []byte                  `json:"attestation_private_key"`
	AuthenticationCounter  uint32                  `json:"authentication_counter"`
	Sources                []SavedCredentialSource `json:"sources"`
}

type PassphraseEncryptedBlob struct {
	Salt          []byte `json:"salt"`
	EncryptionKey []byte `json:"encryption_key"`
	KeyNonce      []byte `json:"key_nonce"`
	EncryptedData []byte `json:"encrypted_data"`
	DataNonce     []byte `json:"data_nonce"`
}

func encryptPassphraseBlob(passphrase string, data []byte) PassphraseEncryptedBlob {
	salt := read(rand.Reader, 16)
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	checkErr(err, "Could not create key encryption key")
	encryptionKey := read(rand.Reader, 32)
	encryptedKey, keyNonce := encrypt(keyEncryptionKey, encryptionKey)
	encryptedData, dataNonce := encrypt(encryptionKey, data)
	return PassphraseEncryptedBlob{
		Salt:          salt,
		EncryptionKey: encryptedKey,
		KeyNonce:      keyNonce,
		EncryptedData: encryptedData,
		DataNonce:     dataNonce,
	}
}

func decryptPassphraseBlob(passphrase string, blob PassphraseEncryptedBlob) []byte {
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), blob.Salt, 32768, 8, 1, 32)
	checkErr(err, "Could not create key encryption key")
	encryptionKey := decrypt(keyEncryptionKey, blob.EncryptionKey, blob.KeyNonce)
	return decrypt(encryptionKey, blob.EncryptedData, blob.DataNonce)
}

func EncryptWithPassphrase(savedState FIDODeviceConfig, passphrase string) ([]byte, error) {
	stateBytes, err := json.Marshal(savedState)
	if err != nil {
		return nil, fmt.Errorf("Could not encode JSON: %w", err)
	}
	blob := encryptPassphraseBlob(passphrase, stateBytes)
	output, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("Could not encode JSON: %w", err)
	}
	return output, nil
}

func DecryptWithPassphrase(data []byte, passphrase string) (*FIDODeviceConfig, error) {
	blob := PassphraseEncryptedBlob{}
	err := json.Unmarshal(data, &blob)
	if err != nil {
		return nil, fmt.Errorf("Could not decode JSON: %w", err)
	}
	stateBytes := decryptPassphraseBlob(passphrase, blob)
	state := FIDODeviceConfig{}
	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		return nil, fmt.Errorf("Could not decode JSON: %w", err)
	}
	return &state, nil
}
