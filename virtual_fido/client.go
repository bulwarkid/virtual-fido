package virtual_fido

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type ClientCredentialSource struct {
	Type             string
	ID               []byte
	PrivateKey       *ecdsa.PrivateKey
	RelyingPartyID   string
	User             PublicKeyCrendentialUserEntity
	SignatureCounter int32
}

func (source *ClientCredentialSource) ctapDescriptor() PublicKeyCredentialDescriptor {
	return PublicKeyCredentialDescriptor{
		Type:       "public-key",
		Id:         source.ID,
		Transports: []string{},
	}
}

type Client interface {
	NewCredentialSource(relyingPartyID string, user PublicKeyCrendentialUserEntity) *ClientCredentialSource
	SealingEncryptionKey() []byte
	GetMatchingCredentialSources(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) []*ClientCredentialSource

	NewPrivateKey() *ecdsa.PrivateKey
	NewAuthenticationCounterId() uint32
	CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte
}

type ClientImpl struct {
	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	caPrivateKey          *ecdsa.PrivateKey
	authenticationCounter uint32
	credentialSources     []*ClientCredentialSource
}

func newClient() *ClientImpl {
	// ALL OF THIS IS INSECURE, FOR TESTING PURPOSES ONLY
	authority := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Virtual FIDO"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate attestation CA private key")
	authorityCertBytes, err := x509.CreateCertificate(rand.Reader, authority, authority, &privateKey.PublicKey, privateKey)
	checkErr(err, "Could not generate attestation CA cert bytes")
	authorityCert, err := x509.ParseCertificate(authorityCertBytes)
	checkErr(err, "Could not parse authority CA cert")
	encryptionKey := sha256.Sum256([]byte("test"))
	return &ClientImpl{
		deviceEncryptionKey:   encryptionKey[:],
		certificateAuthority:  authorityCert,
		caPrivateKey:          privateKey,
		authenticationCounter: 1,
	}
}

func (client ClientImpl) SealingEncryptionKey() []byte {
	return client.deviceEncryptionKey
}

func (client ClientImpl) NewCredentialSource(relyingPartyID string, user PublicKeyCrendentialUserEntity) *ClientCredentialSource {
	credentialID := read(rand.Reader, 16)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	credentialSource := ClientCredentialSource{
		Type:             "public-key",
		ID:               credentialID,
		PrivateKey:       privateKey,
		RelyingPartyID:   relyingPartyID,
		User:             user,
		SignatureCounter: 0,
	}
	client.credentialSources = append(client.credentialSources, &credentialSource)
	return &credentialSource
}

func (client ClientImpl) GetMatchingCredentialSources(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) []*ClientCredentialSource {
	sources := make([]*ClientCredentialSource, 0)
	for _, credentialSource := range client.credentialSources {
		if credentialSource.RelyingPartyID == relyingPartyID {
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

// -----------------------------
// U2F Methods
// -----------------------------

func (client ClientImpl) NewPrivateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	return privateKey
}

func (client ClientImpl) NewAuthenticationCounterId() uint32 {
	num := client.authenticationCounter
	client.authenticationCounter++
	return num
}

func (client ClientImpl) CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte {
	// TODO: Fill in fields like SerialNumber and SubjectKeyIdentifier
	templateCert := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Virtual FIDO"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, templateCert, client.certificateAuthority, &privateKey.PublicKey, client.caPrivateKey)
	checkErr(err, "Could not generate attestation certificate")
	return certBytes
}
