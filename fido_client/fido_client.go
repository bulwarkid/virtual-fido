package fido_client

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

type ClientAction uint8

type ClientActionRequestParams struct {
	RelyingParty string
	UserName     string
}

const (
	ClientActionU2FRegister        ClientAction = 0
	ClientActionU2FAuthenticate    ClientAction = 1
	ClientActionFIDOMakeCredential ClientAction = 2
	ClientActionFIDOGetAssertion   ClientAction = 3
)

var clientLogger *log.Logger = util.NewLogger("[CLIENT] ", util.LogLevelDebug)

type ClientRequestApprover interface {
	ApproveClientAction(action ClientAction, params ClientActionRequestParams) bool
}

type ClientDataSaver interface {
	SaveData(data []byte)
	RetrieveData() []byte
	Passphrase() string
}

type DefaultFIDOClient struct {
	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	certPrivateKey        *ecdsa.PrivateKey
	authenticationCounter uint32

	pinToken        []byte
	pinKeyAgreement *crypto.ECDHKey
	pinRetries      int32
	pinHash         []byte

	vault           *identities.IdentityVault
	requestApprover ClientRequestApprover
	dataSaver       ClientDataSaver
}

func NewDefaultClient(
	attestationCertificate []byte,
	certificatePrivateKey *ecdsa.PrivateKey,
	secretEncryptionKey [32]byte,
	requestApprover ClientRequestApprover,
	dataSaver ClientDataSaver) *DefaultFIDOClient {
	authorityCert, err := x509.ParseCertificate(attestationCertificate)
	util.CheckErr(err, "Could not parse authority CA cert")
	client := &DefaultFIDOClient{
		deviceEncryptionKey:   secretEncryptionKey[:],
		certificateAuthority:  authorityCert,
		certPrivateKey:        certificatePrivateKey,
		authenticationCounter: 1,
		pinToken:              crypto.RandomBytes(16),
		pinKeyAgreement:       crypto.GenerateECDHKey(),
		pinRetries:            8,
		pinHash:               nil,
		vault:                 identities.NewIdentityVault(),
		requestApprover:       requestApprover,
		dataSaver:             dataSaver,
	}
	client.loadData()
	return client
}

func (client *DefaultFIDOClient) SupportsResidentKey() bool {
	return true
}

func (client *DefaultFIDOClient) NewCredentialSource(relyingParty webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	newSource := client.vault.NewIdentity(relyingParty, user)
	client.saveData()
	return newSource
}

func (client *DefaultFIDOClient) GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	sources := client.vault.GetMatchingCredentialSources(relyingPartyID, allowList)
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

func (client DefaultFIDOClient) ApproveAccountCreation(relyingParty string) bool {
	params := ClientActionRequestParams{
		RelyingParty: relyingParty,
	}
	return client.requestApprover.ApproveClientAction(ClientActionFIDOMakeCredential, params)
}

func (client DefaultFIDOClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	params := ClientActionRequestParams{
		RelyingParty: credentialSource.RelyingParty.Name,
		UserName:     credentialSource.User.Name,
	}
	return client.requestApprover.ApproveClientAction(ClientActionFIDOGetAssertion, params)
}

// -----------------------
// PIN Management Methods
// -----------------------

func (client *DefaultFIDOClient) SupportsPIN() bool {
	return true
}

func (client *DefaultFIDOClient) PINHash() []byte {
	return client.pinHash
}

func (client *DefaultFIDOClient) SetPINHash(newHash []byte) {
	client.pinHash = newHash
	client.saveData()
}

func (client *DefaultFIDOClient) PINRetries() int32 {
	util.Assert(client.pinRetries > 0 && client.pinRetries <= 8, "Invalid PIN Retries")
	return client.pinRetries
}

func (client *DefaultFIDOClient) SetPINRetries(retries int32) {
	client.pinRetries = retries
}

func (client *DefaultFIDOClient) PINKeyAgreement() *crypto.ECDHKey {
	return client.pinKeyAgreement
}

func (client *DefaultFIDOClient) PINToken() []byte {
	return client.pinToken
}

// -----------------------------
// U2F Methods
// -----------------------------

func (client DefaultFIDOClient) SealingEncryptionKey() []byte {
	return client.deviceEncryptionKey
}

func (client *DefaultFIDOClient) NewPrivateKey() *ecdsa.PrivateKey {
	return crypto.GenerateECDSAKey()
}

func (client *DefaultFIDOClient) NewAuthenticationCounterId() uint32 {
	num := client.authenticationCounter
	client.authenticationCounter++
	return num
}

func (client *DefaultFIDOClient) CreateAttestationCertificiate(privateKey *ecdsa.PrivateKey) []byte {
	// TODO: Fill in fields like SerialNumber and SubjectKeyIdentifier
	templateCert := &x509.Certificate{
		Version:      2,
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization:       []string{"Self-Signed Virtual FIDO"},
			Country:            []string{"US"},
			CommonName:         "Self-Signed Virtual FIDO",
			OrganizationalUnit: []string{"Authenticator Attestation"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, templateCert, client.certificateAuthority, &privateKey.PublicKey, client.certPrivateKey)
	util.CheckErr(err, "Could not generate attestation certificate")
	return certBytes
}

func (client DefaultFIDOClient) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	params := ClientActionRequestParams{}
	return client.requestApprover.ApproveClientAction(ClientActionU2FRegister, params)
}

func (client DefaultFIDOClient) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	params := ClientActionRequestParams{}
	return client.requestApprover.ApproveClientAction(ClientActionU2FAuthenticate, params)
}

func (client *DefaultFIDOClient) exportData(passphrase string) []byte {
	privKeyBytes, err := x509.MarshalECPrivateKey(client.certPrivateKey)
	util.CheckErr(err, "Could not marshal private key")
	identityData := client.vault.Export()
	state := identities.FIDODeviceConfig{
		EncryptionKey:          client.deviceEncryptionKey,
		AttestationCertificate: client.certificateAuthority.Raw,
		AttestationPrivateKey:  privKeyBytes,
		AuthenticationCounter:  client.authenticationCounter,
		PINHash:                client.pinHash,
		Sources:                identityData,
	}
	savedBytes, err := identities.EncryptFIDOState(state, passphrase)
	util.CheckErr(err, "Could not encode saved state")
	return savedBytes
}

func (client *DefaultFIDOClient) importData(data []byte, passphrase string) error {
	state, err := identities.DecryptFIDOState(data, passphrase)
	util.CheckErr(err, "Could not decrypt vault data")
	cert, err := x509.ParseCertificate(state.AttestationCertificate)
	util.CheckErr(err, "Could not parse x509 cert")
	privateKey, err := x509.ParseECPrivateKey(state.AttestationPrivateKey)
	util.CheckErr(err, "Could not parse private key")
	client.deviceEncryptionKey = state.EncryptionKey
	client.certificateAuthority = cert
	client.certPrivateKey = privateKey
	client.authenticationCounter = state.AuthenticationCounter
	client.pinHash = state.PINHash
	client.vault = identities.NewIdentityVault()
	client.vault.Import(state.Sources)
	return nil
}

func (client *DefaultFIDOClient) saveData() {
	data := client.exportData(client.dataSaver.Passphrase())
	client.dataSaver.SaveData(data)
}

func (client *DefaultFIDOClient) loadData() {
	data := client.dataSaver.RetrieveData()
	if data != nil {
		client.importData(data, client.dataSaver.Passphrase())
	}
}

func (client *DefaultFIDOClient) Identities() []identities.CredentialSource {
	sources := make([]identities.CredentialSource, 0)
	for _, source := range client.vault.CredentialSources {
		sources = append(sources, *source)
	}
	return sources
}

func (client *DefaultFIDOClient) DeleteIdentity(id []byte) bool {
	success := client.vault.DeleteIdentity(id)
	if success {
		client.saveData()
	}
	return success
}
