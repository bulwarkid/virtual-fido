package u2f

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

func checkErr(err error, t *testing.T) {
	if err != nil {
		t.Fatalf("FAIL: Error - %v", err)
	}
}

type DummyU2FClient struct {
	encryptionKey  []byte
	authorityCert  *x509.Certificate
	certPrivateKey *ecdsa.PrivateKey
	counter        uint32
}

func newDummyU2FClient() U2FClient {
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
	util.CheckErr(err, "Could not generate attestation CA private key")
	authorityCertBytes, err := x509.CreateCertificate(rand.Reader, authority, authority, &privateKey.PublicKey, privateKey)
	util.CheckErr(err, "Could not generate attestation CA cert bytes")
	authorityCert, err := x509.ParseCertificate(authorityCertBytes)
	util.CheckErr(err, "Could not parse cert")
	encryptionKey := sha256.Sum256([]byte("test"))
	client := DummyU2FClient{
		encryptionKey:  encryptionKey[:],
		authorityCert:  authorityCert,
		certPrivateKey: privateKey,
		counter:        0,
	}
	return &client
}

func (client *DummyU2FClient) SealingEncryptionKey() []byte {
	return client.encryptionKey
}

func (client *DummyU2FClient) NewPrivateKey() *ecdsa.PrivateKey {
	return crypto.GenerateECDSAKey()
}

func (client *DummyU2FClient) NewAuthenticationCounterId() uint32 {
	i := client.counter
	client.counter += 1
	return i
}

func (client *DummyU2FClient) CreateAttestationCertificiate(cosePrivateKey *cose.SupportedCOSEPrivateKey) []byte {
	privateKey := cosePrivateKey.ECDSA
	util.Assert(privateKey != nil, "No ECDSA private key provided to attestation creator")
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
	certBytes, err := x509.CreateCertificate(rand.Reader, templateCert, client.authorityCert, &privateKey.PublicKey, client.certPrivateKey)
	util.CheckErr(err, "Could not generate attestation certificate")
	return certBytes
}

func (client *DummyU2FClient) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	return true
}

func (client *DummyU2FClient) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	return true
}

func u2fHeader(command U2FCommand, param1 uint8, param2 uint8) []byte {
	return util.ToLE(U2FMessageHeader{Cla: 0, Command: command, Param1: param1, Param2: param2})
}

func parseRegistrationResponse(response []byte, t *testing.T) (uint8, *ecdsa.PublicKey, []byte, *x509.Certificate, []byte, U2FStatusWord) {
	responseReader := bytes.NewBuffer(response)
	code, err := responseReader.ReadByte()
	checkErr(err, t)
	encodedPublicKey := util.Read(responseReader, 65)
	publicKey := crypto.DecodePublicKey(encodedPublicKey)
	keyHandleLength, _ := responseReader.ReadByte()
	keyHandle := make([]byte, keyHandleLength)
	responseReader.Read(keyHandle)
	input := cryptobyte.String(responseReader.Bytes())
	certificateBytes := cryptobyte.String{}
	if !input.ReadASN1Element(&certificateBytes, 0x20|asn1.TagSequence) {
		t.Fatalf("Could not parse certificate ASN1")
	}
	certificate, err := x509.ParseCertificate(certificateBytes)
	checkErr(err, t)
	util.Read(responseReader, uint(len(certificateBytes)))
	signature := util.Read(responseReader, uint(len(responseReader.Bytes())-int(util.SizeOf[U2FStatusWord]())))
	returnCode := util.ReadBE[U2FStatusWord](responseReader)
	return code, publicKey, keyHandle, certificate, signature, returnCode
}

func TestU2FRegistration(t *testing.T) {
	client := newDummyU2FClient()
	server := NewU2FServer(client)
	challenge := crypto.RandomBytes(32)
	application := crypto.RandomBytes(32)
	registration := util.Flatten([][]byte{u2fHeader(u2f_COMMAND_REGISTER, 0, 0), {0, 0, 64}, util.ToBE(512), challenge, application})
	response := server.HandleMessage(registration)
	code, publicKey, keyHandle, certificate, signature, returnCode := parseRegistrationResponse(response, t)
	if code != 0x05 {
		t.Fatalf("Incorrect response code for registration: %d", code)
	}
	encodedPublicKey := crypto.EncodePublicKey(publicKey)
	certificatePublicKey := certificate.PublicKey.(*ecdsa.PublicKey)
	encodedCertPublicKey := crypto.EncodePublicKey(certificatePublicKey)
	if !bytes.Equal(encodedCertPublicKey, encodedPublicKey) {
		t.Fatalf("Certificate does not verify the public key returned")
	}
	if returnCode != u2f_SW_NO_ERROR {
		t.Fatalf("Incorrect return code: %d", returnCode)
	}
	signatureBytes := util.Flatten([][]byte{{0}, application, challenge, keyHandle, encodedPublicKey})
	if !crypto.VerifyECDSA(publicKey, signatureBytes, signature) {
		t.Fatalf("Could not verify signature returned by Authenticate")
	}
}
