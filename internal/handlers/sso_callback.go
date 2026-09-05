package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"sentinel-core/internal/auth"
	"sentinel-core/internal/db"
)

type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type MicrosoftGraphUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// HandleMicrosoftCallback verarbeitet den OAuth2 Rücksprung von Microsoft Entra ID
func HandleMicrosoftCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 1. CSRF State Validierung aus Cookie
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Unauthorized: Missing state cookie", http.StatusUnauthorized)
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState == "" || queryState != cookie.Value {
		http.Error(w, "Security Warning: Invalid OAuth State Parameter", http.StatusForbidden)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Bad Request: Missing authorization code", http.StatusBadRequest)
		return
	}

	// 2. Token Exchange mit Microsoft Endpoint
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	redirectURL := os.Getenv("AZURE_REDIRECT_URL")

	if tenantID == "" || clientID == "" || clientSecret == "" || redirectURL == "" {
		slog.Error("Azure SSO environment variables are not fully configured")
		http.Error(w, "Internal Server Error: SSO configuration missing", http.StatusInternalServerError)
		return
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	formValues := strings.NewReader(fmt.Sprintf(
		"client_id=%s&scope=openid+profile+email+User.Read&code=%s&redirect_uri=%s&grant_type=authorization_code&client_secret=%s",
		clientID, code, redirectURL, clientSecret,
	))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, formValues)
	if err != nil {
		http.Error(w, "Internal error creating token request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to exchange token with Microsoft", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	// 3. Benutzerprofil von Microsoft Graph abrufen
	userReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/v1.0/me", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := client.Do(userReq)
	if err != nil || userResp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch Microsoft User Profile", http.StatusBadGateway)
		return
	}
	defer userResp.Body.Close()

	var msUser MicrosoftGraphUser
	if err := json.NewDecoder(userResp.Body).Decode(&msUser); err != nil {
		http.Error(w, "Failed to parse Microsoft user profile", http.StatusInternalServerError)
		return
	}

	userEmail := msUser.Mail
	if userEmail == "" {
		userEmail = msUser.UserPrincipalName
	}

	// 4. Sichere Initialisierung des SecurityManagers ohne unsichere Hardcoded-Fallbacks
	caCertEnv := os.Getenv("CA_CERT_PEM")
	caKeyEnv := os.Getenv("CA_KEY_PEM")
	jwtSecretEnv := os.Getenv("JWT_SECRET")

	if jwtSecretEnv == "" {
		slog.Error("CRITICAL: JWT_SECRET environment variable is missing")
		http.Error(w, "Internal Server Error: Authentication configuration error", http.StatusInternalServerError)
		return
	}

	secManager, err := auth.NewSecurityManager([]byte(caCertEnv), []byte(caKeyEnv), jwtSecretEnv)
	if err != nil {
		slog.Error("Failed to initialize SecurityManager", "error", err)
		http.Error(w, "Internal Server Error: Security initialization failed", http.StatusInternalServerError)
		return
	}

	sessionToken, err := secManager.GenerateSignedJWT(msUser.ID, "systemhaus-dach", "technician", 8*time.Hour)
	if err != nil {
		http.Error(w, "Failed to issue session token", http.StatusInternalServerError)
		return
	}

	// 5. Secure HttpOnly Cookie für das Dashboard setzen
	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_session",
		Value:    sessionToken,
		Expires:  time.Now().Add(8 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	// Audit Log schreiben
	go func() {
		_, _ = db.Pool.Exec(context.Background(),
			`INSERT INTO security_logs (node_id, severity, source, message) VALUES ($1, $2, $3, $4)`,
			"hub-server", "INFO", "SSO_LOGIN", fmt.Sprintf("Techniker %s erfolgreich via Microsoft Entra ID angemeldet.", userEmail),
		)
	}()

	// Weiterleitung zum Dashboard
	http.Redirect(w, r, "/dashboard.html", http.StatusTemporaryRedirect)
}
