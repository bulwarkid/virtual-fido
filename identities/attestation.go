package identities

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/bulwarkid/virtual-fido/cose"
)

// We need two functions here because Go's type system isn't enough to support this
func extractPublicKey(key *cose.SupportedCOSEPublicKey) any {
	if key.ECDSA != nil {
		return key.ECDSA
	} else if key.Ed25519 != nil {
		return *key.Ed25519
	} else if key.RSA != nil {
		return key.RSA
	} else {
		panic("No supported private key data!")
	}

}
func extractPrivateKey(key *cose.SupportedCOSEPrivateKey) any {
	if key.ECDSA != nil {
		return key.ECDSA
	} else if key.Ed25519 != nil {
		return *key.Ed25519
	} else if key.RSA != nil {
		return key.RSA
	} else {
		panic("No supported private key data!")
	}

}

func CreateSelfSignedAttestationCertificate(
	certificateAuthority *x509.Certificate,
	certificateAuthorityPrivateKey *cose.SupportedCOSEPrivateKey,
	targetPrivateKey *cose.SupportedCOSEPrivateKey) (*x509.Certificate, error) {
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
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		templateCert,
		certificateAuthority,
		extractPublicKey(targetPrivateKey.Public()),
		extractPrivateKey(certificateAuthorityPrivateKey))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

func CreateCAPrivateKey() (*cose.SupportedCOSEPrivateKey, error) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	coseKey := cose.SupportedCOSEPrivateKey{ECDSA: ecdsaKey}
	return &coseKey, nil
}

func CreateSelfSignedCA(privateKey *cose.SupportedCOSEPrivateKey) (*x509.Certificate, error) {
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
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		authority, authority,
		extractPublicKey(privateKey.Public()),
		extractPrivateKey(privateKey))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}
