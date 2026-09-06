package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func InitializeEphemeralMTLSCA() error {
	if os.Getenv("CA_CERT_PEM") != "" && os.Getenv("CA_KEY_PEM") != "" {
		return nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"SentinelCore Demo CA"}, CommonName: "SentinelCore Demo CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := os.Setenv("CA_CERT_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))); err != nil {
		return err
	}
	if err := os.Setenv("CA_KEY_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}))); err != nil {
		return err
	}
	return nil
}
