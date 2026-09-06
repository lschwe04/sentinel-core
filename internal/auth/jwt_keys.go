package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func InitializeEphemeralJWTKeys() error {
	if os.Getenv("JWT_PRIVATE_KEY_PEM") != "" && os.Getenv("JWT_PUBLIC_KEY_PEM") != "" {
		return nil
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	if err := os.Setenv("JWT_PRIVATE_KEY_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))); err != nil {
		return err
	}
	if err := os.Setenv("JWT_PUBLIC_KEY_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))); err != nil {
		return err
	}
	if os.Getenv("JWT_KEY_ID") == "" {
		if err := os.Setenv("JWT_KEY_ID", "ephemeral-demo"); err != nil {
			return err
		}
	}
	return nil
}
