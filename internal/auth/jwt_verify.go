package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

func ParseUserJWT(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	publicPEM := os.Getenv("JWT_PUBLIC_KEY_PEM")
	if publicPEM == "" {
		secret := os.Getenv("JWT_SECRET")
		if len(secret) < 32 {
			return nil, errors.New("JWT verifier is not configured")
		}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
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
		if token.Method != jwt.SigningMethodEdDSA || token.Header["kid"] != os.Getenv("JWT_KEY_ID") {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid JWT")
	}
	if version := os.Getenv("JWT_REVOCATION_VERSION"); version != "" && claims["rv"] != version {
		return nil, errors.New("revoked JWT")
	}
	if issuer := os.Getenv("JWT_ISSUER"); issuer != "" && claims["iss"] != issuer {
		return nil, errors.New("invalid JWT issuer")
	}
	if audience := os.Getenv("JWT_AUDIENCE"); audience != "" && !claims.VerifyAudience(audience, true) {
		return nil, errors.New("invalid JWT audience")
	}
	return claims, nil
}
