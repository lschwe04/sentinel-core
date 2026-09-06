package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type SecretProvider interface {
	Get(context.Context, string) (string, error)
}

type Provider struct {
	vaultAddr  string
	vaultToken string
	path       string
	client     *http.Client
}

func NewProvider() *Provider {
	return &Provider{
		vaultAddr:  strings.TrimRight(os.Getenv("VAULT_ADDR"), "/"),
		vaultToken: os.Getenv("VAULT_TOKEN"),
		path:       strings.Trim(os.Getenv("VAULT_SECRET_PATH"), "/"),
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *Provider) Get(ctx context.Context, name string) (string, error) {
	if p.vaultAddr == "" {
		value := os.Getenv(name)
		if value == "" {
			return "", fmt.Errorf("secret %s is not configured", name)
		}
		return value, nil
	}
	if p.vaultToken == "" || p.path == "" {
		return "", errors.New("Vault is configured without token or secret path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.vaultAddr+"/v1/"+p.path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", p.vaultToken)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Vault returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var envelope struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", err
	}
	value, ok := envelope.Data[name]
	if !ok || value == "" {
		return "", fmt.Errorf("secret %s missing in Vault", name)
	}
	return value, nil
}
