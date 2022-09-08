package virtual_fido

import (
	"bytes"
	"crypto/ecdsa"
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
	credentialSources []*CredentialSource
}

func newIdentityVault() *IdentityVault {
	sources := make([]*CredentialSource, 0)
	return &IdentityVault{credentialSources: sources}
}

func (vault *IdentityVault) addIdentity(source *CredentialSource) {
	vault.credentialSources = append(vault.credentialSources, source)
}

func (vault *IdentityVault) getMatchingCredentialSources(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) []*CredentialSource {
	sources := make([]*CredentialSource, 0)
	for _, credentialSource := range vault.credentialSources {
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

func (vault *IdentityVault) exportToBytes() []byte {
	sources := make([]SavedCredentialSource, 0)
	for _, source := range vault.credentialSources {
		key, err := x509.MarshalECPrivateKey(source.PrivateKey)
		checkErr(err, "Could not marshall private key")
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
	output, err := cbor.Marshal(sources)
	checkErr(err, "Could not export identities to CBOR")
	return output
}

func (vault *IdentityVault) importFromBytes(data []byte) error {
	sources := make([]SavedCredentialSource, 0)
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
		vault.addIdentity(&decodedSource)
	}
	return nil
}
