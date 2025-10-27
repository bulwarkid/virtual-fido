package fido_client

import (
	"crypto/ecdsa"
	"crypto/x509"
	"log"
	"strings"

	"github.com/bulwarkid/virtual-fido/cose"
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
	ClientActionU2FRegister         ClientAction = 0
	ClientActionU2FAuthenticate     ClientAction = 1
	ClientActionFIDOMakeCredential  ClientAction = 2
	ClientActionFIDOGetAssertion    ClientAction = 3
	ClientActionManageAuthenticator ClientAction = 4
)

var clientLogger *log.Logger = util.NewLogger("[CLIENT] ", util.LogLevelDebug)

type ClientRequestApprover interface {
	ApproveClientAction(action ClientAction, params ClientActionRequestParams) bool
}

type UserVerifier interface {
	SupportsUserVerification() bool
	VerifyUser(action ClientAction, params ClientActionRequestParams) bool
}

type ClientDataSaver interface {
	SaveData(data []byte)
	RetrieveData() []byte
	Passphrase() string
}

type DefaultFIDOClient struct {
	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	certPrivateKey        *cose.SupportedCOSEPrivateKey
	authenticationCounter uint32

	pinEnabled         bool
	pinToken           []byte
	pinKeyAgreement    *crypto.ECDHKey
	pinRetries         int32
	pinHash            []byte
	fingerprintEnabled bool

	vault           *identities.IdentityVault
	requestApprover ClientRequestApprover
	userVerifier    UserVerifier
	dataSaver       ClientDataSaver
}

func NewDefaultClient(
	rootAttestationCertificate *x509.Certificate,
	rootAttestationCertPrivateKey *cose.SupportedCOSEPrivateKey,
	secretEncryptionKey [32]byte,
	enablePIN bool,
	requestApprover ClientRequestApprover,
	userVerifier UserVerifier,
	dataSaver ClientDataSaver) *DefaultFIDOClient {
	if userVerifier == nil {
		userVerifier = &noopUserVerifier{}
	}
	client := &DefaultFIDOClient{
		pinEnabled:            enablePIN,
		deviceEncryptionKey:   secretEncryptionKey[:],
		certificateAuthority:  rootAttestationCertificate,
		certPrivateKey:        rootAttestationCertPrivateKey,
		authenticationCounter: 1,
		// CTAP2 spec: pinUvAuthToken length is 32 bytes for v1/v2
		pinToken:           crypto.RandomBytes(32),
		pinKeyAgreement:    crypto.GenerateECDHKey(),
		pinRetries:         8,
		pinHash:            nil,
		fingerprintEnabled: false,
		vault:              identities.NewIdentityVault(),
		requestApprover:    requestApprover,
		userVerifier:       userVerifier,
		dataSaver:          dataSaver,
	}
	client.loadData()
	return client
}

func (client *DefaultFIDOClient) SupportsResidentKey() bool {
	return true
}

func (client *DefaultFIDOClient) NewCredentialSource(
	PubKeyCredParams []webauthn.PublicKeyCredentialParams,
	ExcludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	supported := false
	for _, param := range PubKeyCredParams {
		if param.Algorithm == cose.COSE_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
			break
		}
	}
	if !supported {
		return nil
	}
	// Treat platform health-check registrations (e.g., rpId ".dummy" or invalid rp) as ephemeral.
	// Do not persist these into the vault to avoid polluting real credentials.
	if relyingParty != nil {
		rpID := relyingParty.ID
		rpName := relyingParty.Name
		userName := ""
		if user != nil {
			userName = user.Name
		}
		if rpID == ".dummy" || rpID == "" || strings.HasPrefix(rpID, ".") || (rpName == "" && userName == "dummy") {
			// Create an ephemeral credential without saving to vault
			priv := crypto.GenerateECDSAKey()
			eph := &identities.CredentialSource{
				Type:             "public-key",
				ID:               crypto.RandomBytes(16),
				PrivateKey:       &cose.SupportedCOSEPrivateKey{ECDSA: priv},
				RelyingParty:     relyingParty,
				User:             user,
				SignatureCounter: 0,
			}
			return eph
		}
	}
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

func (client *DefaultFIDOClient) GetAssertionSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*identities.CredentialSource {
	sources := client.vault.GetMatchingCredentialSources(relyingPartyID, allowList)
	if len(sources) == 0 {
		return []*identities.CredentialSource{}
	}
	// Increment the first one now (first assertion); GetNextAssertion will increment others when signed there if needed
	sources[0].SignatureCounter++
	client.saveData()
	return sources
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

func (client *DefaultFIDOClient) EnablePIN() {
	client.pinEnabled = true
	client.saveData()
}

func (client *DefaultFIDOClient) DisablePIN() {
	client.pinEnabled = false
	client.saveData()
}

func (client *DefaultFIDOClient) SupportsPIN() bool {
	return client.pinEnabled
}

func (client *DefaultFIDOClient) PINHash() []byte {
	return client.pinHash
}

func (client *DefaultFIDOClient) SetPIN(pin []byte) {
	pinHash := crypto.HashSHA256(pin)[:16]
	client.SetPINHash(pinHash)
}

func (client *DefaultFIDOClient) SetPINHash(newHash []byte) {
	client.pinHash = newHash
	client.saveData()
}

// ---------------------------
// Fingerprint/Uv Methods
// ---------------------------

func (client *DefaultFIDOClient) FingerprintEnabled() bool {
	return client.fingerprintEnabled
}

func (client *DefaultFIDOClient) FingerprintAvailable() bool {
	if client.userVerifier == nil {
		return false
	}
	return client.userVerifier.SupportsUserVerification()
}

func (client *DefaultFIDOClient) EnableFingerprint() {
	client.fingerprintEnabled = true
	client.saveData()
}

func (client *DefaultFIDOClient) DisableFingerprint() {
	client.fingerprintEnabled = false
	client.saveData()
}

func (client *DefaultFIDOClient) SupportsUserVerification() bool {
	if !client.fingerprintEnabled {
		return false
	}
	return client.FingerprintAvailable()
}

func (client *DefaultFIDOClient) VerifyUser(action ClientAction, params ClientActionRequestParams) bool {
	if !client.FingerprintAvailable() {
		return false
	}
	return client.userVerifier.VerifyUser(action, params)
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

// RotatePINKeyAgreement generates a fresh ephemeral ECDH key for the next PIN protocol exchange.
func (client *DefaultFIDOClient) RotatePINKeyAgreement() {
	client.pinKeyAgreement = crypto.GenerateECDHKey()
}

func (client *DefaultFIDOClient) PINToken() []byte {
	return client.pinToken
}

func (client *DefaultFIDOClient) SaveState() {
	client.saveData()
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

func (client *DefaultFIDOClient) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	cert, err := identities.CreateSelfSignedAttestationCertificate(client.certificateAuthority, client.certPrivateKey, privateKey)
	util.CheckErr(err, "Could not create attestation certificate")
	return cert.Raw
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
	privKeyBytes := cose.MarshalCOSEPrivateKey(client.certPrivateKey)
	identityData := client.vault.Export()
	state := identities.FIDODeviceConfig{
		EncryptionKey:          client.deviceEncryptionKey,
		AttestationCertificate: client.certificateAuthority.Raw,
		AttestationPrivateKey:  privKeyBytes,
		AuthenticationCounter:  client.authenticationCounter,
		PINEnabled:             client.pinEnabled,
		PINHash:                client.pinHash,
		FingerprintEnabled:     client.fingerprintEnabled,
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
	privateKey, err := cose.UnmarshalCOSEPrivateKey(state.AttestationPrivateKey)
	if err != nil {
		privateKeyECDSA, err := x509.ParseECPrivateKey(state.AttestationPrivateKey)
		util.CheckErr(err, "Could not parse private key")
		privateKey = &cose.SupportedCOSEPrivateKey{ECDSA: privateKeyECDSA}
	}
	client.deviceEncryptionKey = state.EncryptionKey
	client.certificateAuthority = cert
	client.certPrivateKey = privateKey
	client.authenticationCounter = state.AuthenticationCounter
	client.pinEnabled = state.PINEnabled
	client.pinHash = state.PINHash
	client.fingerprintEnabled = state.FingerprintEnabled
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

type noopUserVerifier struct{}

func (n *noopUserVerifier) SupportsUserVerification() bool {
	return false
}

func (n *noopUserVerifier) VerifyUser(action ClientAction, params ClientActionRequestParams) bool {
	return false
}
