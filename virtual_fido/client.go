package virtual_fido

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var clientLogger *log.Logger = newLogger("[CLIENT] ", true)

type ClientRequestApprover interface {
	ApproveLogin(relyingParty string, username string) bool
	ApproveAccountCreation(relyingParty string) bool
}

type ClientDataSaver interface {
	SaveData(data []byte)
	RetrieveData() []byte
	Passphrase() string
}

type ClientCredentialSource struct {
	Type             string
	ID               []byte
	PrivateKey       *ecdsa.PrivateKey
	RelyingParty     PublicKeyCredentialRpEntity
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
	NewCredentialSource(relyingParty PublicKeyCredentialRpEntity, user PublicKeyCrendentialUserEntity) *ClientCredentialSource
	GetAssertionSource(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) *ClientCredentialSource

	SealingEncryptionKey() []byte
	NewPrivateKey() *ecdsa.PrivateKey
	NewAuthenticationCounterId() uint32
	CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte

	ApproveAccountCreation(relyingParty string) bool
	ApproveAccountLogin(credentialSource *ClientCredentialSource) bool
}

type ClientImpl struct {
	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	certPrivateKey        *ecdsa.PrivateKey
	authenticationCounter uint32
	credentialSources     []*ClientCredentialSource
	requestApprover       ClientRequestApprover
	dataSaver             ClientDataSaver
}

func NewClient(
	attestationCertificate []byte,
	certificatePrivateKey *ecdsa.PrivateKey,
	secretEncryptionKey [32]byte,
	requestApprover ClientRequestApprover,
	dataSaver ClientDataSaver) *ClientImpl {
	authorityCert, err := x509.ParseCertificate(attestationCertificate)
	checkErr(err, "Could not parse authority CA cert")
	return &ClientImpl{
		deviceEncryptionKey:   secretEncryptionKey[:],
		certificateAuthority:  authorityCert,
		certPrivateKey:        certificatePrivateKey,
		authenticationCounter: 1,
		requestApprover:       requestApprover,
		dataSaver:             dataSaver,
	}
}

func (client ClientImpl) SealingEncryptionKey() []byte {
	return client.deviceEncryptionKey
}

func (client *ClientImpl) NewCredentialSource(relyingParty PublicKeyCredentialRpEntity, user PublicKeyCrendentialUserEntity) *ClientCredentialSource {
	credentialID := read(rand.Reader, 16)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	credentialSource := ClientCredentialSource{
		Type:             "public-key",
		ID:               credentialID,
		PrivateKey:       privateKey,
		RelyingParty:     relyingParty,
		User:             user,
		SignatureCounter: 0,
	}
	client.credentialSources = append(client.credentialSources, &credentialSource)
	client.saveData()
	return &credentialSource
}

func (client *ClientImpl) getMatchingCredentialSources(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) []*ClientCredentialSource {
	sources := make([]*ClientCredentialSource, 0)
	for _, credentialSource := range client.credentialSources {
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

func (client *ClientImpl) GetAssertionSource(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) *ClientCredentialSource {
	sources := client.getMatchingCredentialSources(relyingPartyID, allowList)
	if len(sources) == 0 {
		clientLogger.Printf("ERROR: No Credentials\n\n")
		return nil
	}

	// TODO: Allow user to choose credential source
	credentialSource := sources[0]
	credentialSource.SignatureCounter++
	client.saveData()
	return credentialSource
}

func (client ClientImpl) ApproveAccountCreation(relyingParty string) bool {
	return client.requestApprover.ApproveAccountCreation(relyingParty)
}

func (client ClientImpl) ApproveAccountLogin(credentialSource *ClientCredentialSource) bool {
	return client.requestApprover.ApproveLogin(credentialSource.RelyingParty.Name, credentialSource.User.Name)
}

// -----------------------------
// U2F Methods
// -----------------------------

func (client *ClientImpl) NewPrivateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	return privateKey
}

func (client *ClientImpl) NewAuthenticationCounterId() uint32 {
	num := client.authenticationCounter
	client.authenticationCounter++
	return num
}

func (client *ClientImpl) CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte {
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
	certBytes, err := x509.CreateCertificate(rand.Reader, templateCert, client.certificateAuthority, &privateKey.PublicKey, client.certPrivateKey)
	checkErr(err, "Could not generate attestation certificate")
	return certBytes
}

type SavedClientCredentialSource struct {
	Type             string
	ID               []byte
	PrivateKey       []byte
	RelyingParty     PublicKeyCredentialRpEntity
	User             PublicKeyCrendentialUserEntity
	SignatureCounter int32
}

type SavedClientState struct {
	DeviceEncryptionKey   []byte
	CertificateAuthority  []byte
	CertPrivateKey        []byte
	AuthenticationCounter uint32
	CredentialSources     []SavedClientCredentialSource
}

func (client *ClientImpl) exportData(passphrase string) []byte {
	privKeyBytes, err := x509.MarshalECPrivateKey(client.certPrivateKey)
	checkErr(err, "Could not marshal private key")
	sources := make([]SavedClientCredentialSource, 0)
	for _, source := range client.credentialSources {
		key, err := x509.MarshalECPrivateKey(source.PrivateKey)
		checkErr(err, "Could not marshall private key")
		savedSource := SavedClientCredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     source.RelyingParty,
			User:             source.User,
			SignatureCounter: source.SignatureCounter,
		}
		sources = append(sources, savedSource)
	}
	state := SavedClientState{
		DeviceEncryptionKey:   client.deviceEncryptionKey,
		CertificateAuthority:  client.certificateAuthority.Raw,
		CertPrivateKey:        privKeyBytes,
		AuthenticationCounter: client.authenticationCounter,
		CredentialSources:     sources,
	}
	stateBytes, err := cbor.Marshal(state)
	checkErr(err, "Could not encode CBOR")
	blob := encryptWithPassphrase(passphrase, stateBytes)
	output, err := cbor.Marshal(blob)
	checkErr(err, "Could not encode CBOR")
	return output
}

func (client *ClientImpl) importData(data []byte, passphrase string) error {
	blob := PassphraseEncryptedBlob{}
	err := cbor.Unmarshal(data, &blob)
	checkErr(err, "Invalid passphrase blob")
	stateBytes := decryptWithPassphrase(passphrase, blob)
	state := SavedClientState{}
	err = cbor.Unmarshal(stateBytes, &state)
	checkErr(err, "Could not unmarshal saved data")
	cert, err := x509.ParseCertificate(state.CertificateAuthority)
	checkErr(err, "Could not parse x509 cert")
	privateKey, err := x509.ParseECPrivateKey(state.CertPrivateKey)
	checkErr(err, "Could not parse private key")
	client.deviceEncryptionKey = state.DeviceEncryptionKey
	client.certificateAuthority = cert
	client.certPrivateKey = privateKey
	client.authenticationCounter = state.AuthenticationCounter
	client.credentialSources = make([]*ClientCredentialSource, 0)
	for _, source := range state.CredentialSources {
		key, err := x509.ParseECPrivateKey(source.PrivateKey)
		if err != nil {
			return fmt.Errorf("Invalid private key for source: %w", err)
		}
		decodedSource := ClientCredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     source.RelyingParty,
			User:             source.User,
			SignatureCounter: source.SignatureCounter,
		}
		client.credentialSources = append(client.credentialSources, &decodedSource)
	}
	return nil
}

func (client *ClientImpl) saveData() {
	data := client.exportData(client.dataSaver.Passphrase())
	client.dataSaver.SaveData(data)
}

func (client *ClientImpl) loadData() {
	data := client.dataSaver.RetrieveData()
	if data != nil {
		client.importData(data, client.dataSaver.Passphrase())
	}
}
