package fido_client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

type CredentialSource struct {
	Type             string
	ID               []byte
	PrivateKey       *ecdsa.PrivateKey
	RelyingParty     webauthn.PublicKeyCredentialRpEntity
	User             webauthn.PublicKeyCrendentialUserEntity
	SignatureCounter int32
}

func (source *CredentialSource) ctapDescriptor() webauthn.PublicKeyCredentialDescriptor {
	return webauthn.PublicKeyCredentialDescriptor{
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

func (vault *IdentityVault) NewIdentity(relyingParty webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCrendentialUserEntity) *CredentialSource {
	credentialID := util.Read(rand.Reader, 16)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	util.CheckErr(err, "Could not generate private key")
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

func (vault *IdentityVault) GetMatchingCredentialSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*CredentialSource {
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

func (vault *IdentityVault) Export() []SavedCredentialSource {
	sources := make([]SavedCredentialSource, 0)
	for _, source := range vault.CredentialSources {
		key, err := x509.MarshalECPrivateKey(source.PrivateKey)
		util.CheckErr(err, "Could not marshall private key")
		savedSource := SavedCredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     source.RelyingParty,
			User:             source.User,
			SignatureCounter: source.SignatureCounter,
		}
		sources = append(sources, savedSource)
	}
	return sources
}

func (vault *IdentityVault) Import(sources []SavedCredentialSource) error {
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
