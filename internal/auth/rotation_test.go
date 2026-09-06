package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestIssueAgentCertificateFromCSRUsesCSRPublicKey(t *testing.T) {
	caCert, caKey := testCA(t)
	manager, err := NewSecurityManager(caCert, caKey, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := manager.IssueAgentCertificateFromCSR("node-1", "7", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 30)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "node-1" || cert.Subject.Organization[0] != "SentinelCore Tenant: 7" {
		t.Fatalf("unexpected certificate identity: %s %v", cert.Subject.CommonName, cert.Subject.Organization)
	}
	if !cert.NotAfter.After(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("certificate validity is shorter than requested")
	}
}

func TestIssueAgentCertificateFromCSRRejectsUnsafeValidity(t *testing.T) {
	caCert, caKey := testCA(t)
	manager, err := NewSecurityManager(caCert, caKey, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.IssueAgentCertificateFromCSR("node-1", "7", []byte("invalid"), 91); err == nil {
		t.Fatal("expected validity limit error")
	}
}

func TestValidateGeneratedJWTRejectsTamperedToken(t *testing.T) {
	caCert, caKey := testCA(t)
	manager, err := NewSecurityManager(caCert, caKey, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	token, err := manager.GenerateSignedJWT("node-1", "7", "agent", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	last := token[len(token)-1]
	tampered := token[:len(token)-1] + string(last^1)
	if _, err := manager.ValidateJWT(tampered); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}
