package virtual_fido

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type CredentialSource struct {
	Type             string
	ID               []byte
	PrivateKey       *ecdsa.PrivateKey
	RelyingParty     PublicKeyCredentialRpEntity
	User             PublicKeyCrendentialUserEntity
	SignatureCounter int32
}

func (source *CredentialSource) ctapDescriptor() PublicKeyCredentialDescriptor {
	return PublicKeyCredentialDescriptor{
		Type:       "public-key",
		Id:         source.ID,
		Transports: []string{},
	}
}

type IdentityVault struct {
	CredentialSources []*CredentialSource
}

func NewIdentityVault() *IdentityVault {
	sources := make([]*CredentialSource, 0)
	return &IdentityVault{CredentialSources: sources}
}

func (vault *IdentityVault) NewIdentity(relyingParty PublicKeyCredentialRpEntity, user PublicKeyCrendentialUserEntity) *CredentialSource {
	credentialID := read(rand.Reader, 16)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	credentialSource := CredentialSource{
		Type:             "public-key",
		ID:               credentialID,
		PrivateKey:       privateKey,
		RelyingParty:     relyingParty,
		User:             user,
		SignatureCounter: 0,
	}
	vault.AddIdentity(&credentialSource)
	return &credentialSource
}

func (vault *IdentityVault) AddIdentity(source *CredentialSource) {
	vault.CredentialSources = append(vault.CredentialSources, source)
}

func (vault *IdentityVault) DeleteIdentity(id []byte) bool {
	for i, source := range vault.CredentialSources {
		if bytes.Equal(source.ID, id) {
			vault.CredentialSources[i] = vault.CredentialSources[len(vault.CredentialSources)-1]
			vault.CredentialSources = vault.CredentialSources[:len(vault.CredentialSources)-1]
			return true
		}
	}
	return false
}

func (vault *IdentityVault) GetMatchingCredentialSources(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) []*CredentialSource {
	sources := make([]*CredentialSource, 0)
	for _, credentialSource := range vault.CredentialSources {
		if credentialSource.RelyingParty.Id == relyingPartyID {
			if allowList != nil {
				for _, allowedSource := range allowList {
					if bytes.Equal(allowedSource.Id, credentialSource.ID) {
						sources = append(sources, credentialSource)
						break
					}
				}
			} else {
				sources = append(sources, credentialSource)
			}
		}
	}
	return sources
}

func (vault *IdentityVault) ExportToBytes() []byte {
	sources := make([]savedCredentialSource, 0)
	for _, source := range vault.CredentialSources {
		key, err := x509.MarshalECPrivateKey(source.PrivateKey)
		checkErr(err, "Could not marshall private key")
		savedSource := savedCredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     source.RelyingParty,
			User:             source.User,
			SignatureCounter: source.SignatureCounter,
		}
		sources = append(sources, savedSource)
	}
	output, err := cbor.Marshal(sources)
	checkErr(err, "Could not export identities to CBOR")
	return output
}

func (vault *IdentityVault) ImportFromBytes(data []byte) error {
	sources := make([]savedCredentialSource, 0)
	err := cbor.Unmarshal(data, &sources)
	if err != nil {
		return fmt.Errorf("Invalid bytes for importing identities: %w", err)
	}
	for _, source := range sources {
		key, err := x509.ParseECPrivateKey(source.PrivateKey)
		if err != nil {
			return fmt.Errorf("Invalid private key for source: %w", err)
		}
		decodedSource := CredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     source.RelyingParty,
			User:             source.User,
			SignatureCounter: source.SignatureCounter,
		}
		vault.AddIdentity(&decodedSource)
	}
	return nil
}
