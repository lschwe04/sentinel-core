package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

// ParseUserJWT benötigt zwingend die injecteten Secrets
func ParseUserJWT(tokenString string, jwtSecret []byte, publicPEM, keyID, revocationVersion, issuer, audience string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	if publicPEM == "" {
		if len(jwtSecret) < 32 {
			return nil, errors.New("JWT verifier is not configured securely")
		}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return nil, errors.New("invalid JWT")
		}
		return claims, nil
	}

	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		return nil, errors.New("invalid JWT public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("JWT public key must be Ed25519")
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodEdDSA || token.Header["kid"] != keyID {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid JWT")
	}
	if revocationVersion != "" && claims["rv"] != revocationVersion {
		return nil, errors.New("revoked JWT")
	}
	if issuer != "" && claims["iss"] != issuer {
		return nil, errors.New("invalid JWT issuer")
	}
	if audience != "" && !claims.VerifyAudience(audience, true) {
		return nil, errors.New("invalid JWT audience")
	}
	return claims, nil
}
