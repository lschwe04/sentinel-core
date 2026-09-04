package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type AgentClaims struct {
	NodeID    string `json:"sub"`
	TenantID  string `json:"tenant_id"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type SecurityManager struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	jwtSecret []byte
}

func NewSecurityManager(caCertPEM, caKeyPEM []byte, jwtSecret string) (*SecurityManager, error) {
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, errors.New("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to parse CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CA private key: %w", err)
	}

	return &SecurityManager{
		caCert:    caCert,
		caKey:     caKey,
		jwtSecret: []byte(jwtSecret),
	}, nil
}

// IssueAgentCertificate erzeugt ein neues signiertes mTLS-Client-Zertifikat für den Agenten (z. B. 30 Tage Gültigkeit)
func (sm *SecurityManager) IssueAgentCertificate(nodeID, tenantID string, validDays int) (certPEM, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"SentinelCore Tenant: " + tenantID},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, sm.caCert, &privKey.PublicKey, sm.caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

// GenerateSignedJWT generiert einen zeitlich begrenzten HS256 JWT Token ohne externe Abhaengigkeiten
func (sm *SecurityManager) GenerateSignedJWT(nodeID, tenantID, role string, ttl time.Duration) (string, error) {
	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(AgentClaims{
		NodeID:    nodeID,
		TenantID:  tenantID,
		Role:      role,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(ttl).Unix(),
	})

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := encodedHeader + "." + encodedClaims

	h := hmac.New(sha256.New, sm.jwtSecret)
	h.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return unsignedToken + "." + signature, nil
}

// ValidateJWT ueberprueft die Signatur und Expiration des Agenten-Tokens
func (sm *SecurityManager) ValidateJWT(tokenStr string) (*AgentClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsignedToken := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, sm.jwtSecret)
	h.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, errors.New("invalid signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims AgentClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}
