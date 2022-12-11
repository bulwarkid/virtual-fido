package virtual_fido

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	util "github.com/bulwarkid/virtual-fido/virtual_fido/util"
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
	PINHash                []byte                  `json:"pin_hash,omitempty"`
	Sources                []SavedCredentialSource `json:"sources"`
}

type PassphraseEncryptedBlob struct {
	Salt          []byte `json:"salt"`
	EncryptionKey []byte `json:"encryption_key"`
	KeyNonce      []byte `json:"key_nonce"`
	EncryptedData []byte `json:"encrypted_data"`
	DataNonce     []byte `json:"data_nonce"`
}

func EncryptWithPassphrase(passphrase string, data []byte) ([]byte, error) {
	salt := util.Read(rand.Reader, 16)
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("Could not create key encryption key: %w", err)
	}
	encryptionKey := util.Read(rand.Reader, 32)
	encryptedKey, keyNonce, err := encrypt(keyEncryptionKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt key: %w", err)
	}
	encryptedData, dataNonce, err := encrypt(encryptionKey, data)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt data: %w", err)
	}
	blob := PassphraseEncryptedBlob{
		Salt:          salt,
		EncryptionKey: encryptedKey,
		KeyNonce:      keyNonce,
		EncryptedData: encryptedData,
		DataNonce:     dataNonce,
	}
	blobBytes, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal JSON: %w", err)
	}
	return blobBytes, nil
}

func DecryptWithPassphrase(passphrase string, data []byte) ([]byte, error) {
	blob := PassphraseEncryptedBlob{}
	err := json.Unmarshal(data, &blob)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal JSON into encrypted data: %w", err)
	}
	keyEncryptionKey, err := scrypt.Key([]byte(passphrase), blob.Salt, 32768, 8, 1, 32)
	util.CheckErr(err, "Could not create key encryption key")
	encryptionKey, err := decrypt(keyEncryptionKey, blob.EncryptionKey, blob.KeyNonce)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt encryption key: %w", err)
	}
	decryptedData, err := decrypt(encryptionKey, blob.EncryptedData, blob.DataNonce)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	return decryptedData, nil
}

func EncryptFIDOState(savedState FIDODeviceConfig, passphrase string) ([]byte, error) {
	stateBytes, err := json.Marshal(savedState)
	if err != nil {
		return nil, fmt.Errorf("Could not encode JSON: %w", err)
	}
	blob, err := EncryptWithPassphrase(passphrase, stateBytes)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt data: %w", err)
	}
	return blob, nil
}

func DecryptFIDOState(data []byte, passphrase string) (*FIDODeviceConfig, error) {
	stateBytes, err := DecryptWithPassphrase(passphrase, data)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	state := FIDODeviceConfig{}
	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		return nil, fmt.Errorf("Could not decode JSON: %w", err)
	}
	return &state, nil
}
