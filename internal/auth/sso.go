// sentinel-core: internal/auth/sso.go
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"
)

type SSOManager struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthorityURL string
}

func NewSSOManager() *SSOManager {
	return &SSOManager{
		ClientID:     os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AZURE_REDIRECT_URL"),
		AuthorityURL: "https://login.microsoftonline.com/" + os.Getenv("AZURE_TENANT_ID") + "/v2.0",
	}
}

// GenerateStateParam schützt vor CSRF-Angriffen beim OAuth-Login
func GenerateStateParam() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HandleMicrosoftLogin leitet den Techniker zum Microsoft Entra ID Login weiter
func (s *SSOManager) HandleMicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	state, err := GenerateStateParam()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Cookie für State-Validierung setzen (Secure, HttpOnly)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	authURL := fmt.Sprintf(
		"%s/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query&scope=openid+profile+email&state=%s",
		s.AuthorityURL, s.ClientID, s.RedirectURL, state,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}
