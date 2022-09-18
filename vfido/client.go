package vfido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var clientLogger *log.Logger = newLogger("[CLIENT] ", false)

type ClientRequestApprover interface {
	ApproveLogin(relyingParty string, username string) bool
	ApproveAccountCreation(relyingParty string) bool
}

type ClientDataSaver interface {
	SaveData(data []byte)
	RetrieveData() []byte
	Passphrase() string
}

type Client interface {
	NewCredentialSource(relyingParty PublicKeyCredentialRpEntity, user PublicKeyCrendentialUserEntity) *CredentialSource
	GetAssertionSource(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) *CredentialSource

	SealingEncryptionKey() []byte
	NewPrivateKey() *ecdsa.PrivateKey
	NewAuthenticationCounterId() uint32
	CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte

	ApproveAccountCreation(relyingParty string) bool
	ApproveAccountLogin(credentialSource *CredentialSource) bool
	ApproveU2FRegistration(keyHandle *KeyHandle) bool
	ApproveU2FAuthentication(keyHandle *KeyHandle) bool

	Identities() []CredentialSource
	DeleteIdentity(id []byte) bool
}

type ClientImpl struct {
	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	certPrivateKey        *ecdsa.PrivateKey
	authenticationCounter uint32
	vault                 *IdentityVault
	requestApprover       ClientRequestApprover
	dataSaver             ClientDataSaver
}

func NewClient(
	attestationCertificate []byte,
	certificatePrivateKey *ecdsa.PrivateKey,
	secretEncryptionKey [32]byte,
	requestApprover ClientRequestApprover,
	dataSaver ClientDataSaver,
) *ClientImpl {
	authorityCert, err := x509.ParseCertificate(attestationCertificate)
	checkErr(err, "Could not parse authority CA cert")
	client := &ClientImpl{
		deviceEncryptionKey:   secretEncryptionKey[:],
		certificateAuthority:  authorityCert,
		certPrivateKey:        certificatePrivateKey,
		authenticationCounter: 1,
		vault:                 newIdentityVault(),
		requestApprover:       requestApprover,
		dataSaver:             dataSaver,
	}
	client.loadData()
	return client
}

func (client *ClientImpl) NewCredentialSource(relyingParty PublicKeyCredentialRpEntity, user PublicKeyCrendentialUserEntity) *CredentialSource {
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
	client.vault.addIdentity(&credentialSource)
	client.saveData()
	return &credentialSource
}

func (client *ClientImpl) GetAssertionSource(relyingPartyID string, allowList []PublicKeyCredentialDescriptor) *CredentialSource {
	sources := client.vault.getMatchingCredentialSources(relyingPartyID, allowList)
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

func (client ClientImpl) ApproveAccountLogin(credentialSource *CredentialSource) bool {
	return client.requestApprover.ApproveLogin(credentialSource.RelyingParty.Name, credentialSource.User.Name)
}

func (client ClientImpl) ApproveU2FRegistration(keyHandle *KeyHandle) bool {
	return client.requestApprover.ApproveAccountCreation(hex.EncodeToString(keyHandle.ApplicationID))
}

func (client ClientImpl) ApproveU2FAuthentication(keyHandle *KeyHandle) bool {
	return client.requestApprover.ApproveLogin(hex.EncodeToString(keyHandle.ApplicationID), hex.EncodeToString(keyHandle.PrivateKey))
}

// -----------------------------
// U2F Methods
// -----------------------------

func (client ClientImpl) SealingEncryptionKey() []byte {
	return client.deviceEncryptionKey
}

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

type SavedCredentialSource struct {
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
	CredentialSources     []byte
}

func (client *ClientImpl) exportData(passphrase string) []byte {
	privKeyBytes, err := x509.MarshalECPrivateKey(client.certPrivateKey)
	checkErr(err, "Could not marshal private key")
	identityData := client.vault.exportToBytes()
	state := SavedClientState{
		DeviceEncryptionKey:   client.deviceEncryptionKey,
		CertificateAuthority:  client.certificateAuthority.Raw,
		CertPrivateKey:        privKeyBytes,
		AuthenticationCounter: client.authenticationCounter,
		CredentialSources:     identityData,
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
	client.vault = newIdentityVault()
	client.vault.importFromBytes(state.CredentialSources)
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

func (client *ClientImpl) Identities() []CredentialSource {
	sources := make([]CredentialSource, 0)
	for _, source := range client.vault.credentialSources {
		sources = append(sources, *source)
	}
	return sources
}

func (client *ClientImpl) DeleteIdentity(id []byte) bool {
	success := client.vault.deleteIdentity(id)
	if success {
		client.saveData()
	}
	return success
}
