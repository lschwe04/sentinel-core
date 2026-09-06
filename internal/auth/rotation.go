package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AgentClaims struct {
	NodeID    string `json:"sub"`
	TenantID  string `json:"tenant_id"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type SecurityManager struct {
	caCert            *x509.Certificate
	caKey             *ecdsa.PrivateKey
	jwtSecret         []byte
	jwtPrivate        ed25519.PrivateKey
	jwtPublic         ed25519.PublicKey
	jwtKID            string
	revocationVersion string
}

// IssueAgentCertificateFromCSR signs only the public key supplied by the agent.
// The Hub never receives or generates the agent private key.
func (sm *SecurityManager) IssueAgentCertificateFromCSR(nodeID, tenantID string, csrPEM []byte, validDays int) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate signing request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate signing request signature: %w", err)
	}
	if err := validateCSRKey(csr.PublicKey); err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: nodeID, Organization: []string{"SentinelCore Tenant: " + tenantID}},
		NotBefore:             time.Now().Add(-2 * time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, sm.caCert, csr.PublicKey, sm.caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func validateCSRKey(key any) error {
	switch key.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		return nil
	default:
		return errors.New("unsupported CSR public key type")
	}
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

	manager := &SecurityManager{
		caCert:            caCert,
		caKey:             caKey,
		jwtSecret:         []byte(jwtSecret),
		jwtKID:            os.Getenv("JWT_KEY_ID"),
		revocationVersion: os.Getenv("JWT_REVOCATION_VERSION"),
	}
	if manager.jwtKID == "" {
		manager.jwtKID = "hub-1"
	}
	if manager.revocationVersion == "" {
		manager.revocationVersion = "1"
	}
	if privatePEM := os.Getenv("JWT_PRIVATE_KEY_PEM"); privatePEM != "" {
		block, _ := pem.Decode([]byte(privatePEM))
		if block == nil {
			return nil, errors.New("invalid JWT private key PEM")
		}
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse JWT private key: %w", parseErr)
		}
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("JWT private key must be Ed25519")
		}
		manager.jwtPrivate = privateKey
		manager.jwtPublic = privateKey.Public().(ed25519.PublicKey)
	} else {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			return nil, keyErr
		}
		manager.jwtPublic, manager.jwtPrivate = publicKey, privateKey
	}
	return manager, nil
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
	if len(sm.jwtPrivate) > 0 {
		if ttl <= 0 || ttl > 15*time.Minute {
			ttl = 15 * time.Minute
		}
		now := time.Now()
		claims := jwt.MapClaims{"sub": nodeID, "tenant_id": tenantID, "role": role, "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": generateJTI(), "rv": sm.revocationVersion}
		if issuer := os.Getenv("JWT_ISSUER"); issuer != "" {
			claims["iss"] = issuer
		}
		if audience := os.Getenv("JWT_AUDIENCE"); audience != "" {
			claims["aud"] = audience
		}
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["kid"] = sm.jwtKID
		return token.SignedString(sm.jwtPrivate)
	}
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
	if len(sm.jwtPublic) > 0 {
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodEdDSA || token.Header["kid"] != sm.jwtKID {
				return nil, jwt.ErrSignatureInvalid
			}
			return sm.jwtPublic, nil
		})
		if err != nil || !token.Valid || claims["rv"] != sm.revocationVersion {
			return nil, errors.New("invalid or revoked token")
		}
		return agentClaimsFromMap(claims)
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid token header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "HS256" {
		return nil, errors.New("invalid signing algorithm")
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

	if claims.NodeID == "" || claims.TenantID == "" || claims.Role == "" || claims.ExpiresAt <= time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

func (sm *SecurityManager) JWKS() map[string]any {
	return map[string]any{"keys": []any{map[string]any{
		"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": sm.jwtKID,
		"x": base64.RawURLEncoding.EncodeToString(sm.jwtPublic),
	}}}
}

func agentClaimsFromMap(claims jwt.MapClaims) (*AgentClaims, error) {
	nodeID, _ := claims["sub"].(string)
	tenantID, _ := claims["tenant_id"].(string)
	role, _ := claims["role"].(string)
	if nodeID == "" || tenantID == "" || role == "" {
		return nil, errors.New("incomplete token claims")
	}
	return &AgentClaims{NodeID: nodeID, TenantID: tenantID, Role: role}, nil
}

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
