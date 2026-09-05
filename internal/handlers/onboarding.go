package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"sentinel-core/internal/db"
	"sentinel-core/internal/middleware"
)

type OnboardingResponse struct {
	Token      string `json:"token"`
	BashScript string `json:"bash_script"`
	PS1Script  string `json:"ps1_script"`
	ExpiresAt  int64  `json:"expires_at"`
}

func GenerateOnboardingPayload(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := middleware.TenantIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "Fehler bei der Token-Generierung", http.StatusInternalServerError)
		return
	}
	jitToken := hex.EncodeToString(tokenBytes)
	tokenHashBytes := sha256.Sum256([]byte(jitToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])
	expiresAt := time.Now().Add(1 * time.Hour)

	result, err := db.Pool.Exec(r.Context(), `
		INSERT INTO enrollment_tokens (tenant_id, token_hash, expires_at, is_used) 
		SELECT id, $2, $3, false FROM tenants WHERE slug = $1 OR id::text = $1
	`, tenantID, tokenHash, expiresAt)

	if err != nil {
		http.Error(w, "Fehler bei der Token-Generierung", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() != 1 {
		http.Error(w, "Unbekannter Tenant", http.StatusNotFound)
		return
	}

	hubURL := "https://hub.sentinel-core.local:8443"

	bashScript := fmt.Sprintf(`curl -sSL %s/downloads/linux/install.sh | sudo bash -s -- "%s" "%s"`, hubURL, jitToken, hubURL)
	ps1Script := fmt.Sprintf(`Invoke-WebRequest -Uri "%s/downloads/windows/install.ps1" -OutFile "$env:TEMP\install.ps1"; & "$env:TEMP\install.ps1" -EnrollmentToken "%s" -HubUrl "%s"`, hubURL, jitToken, hubURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(OnboardingResponse{
		Token:      jitToken,
		BashScript: bashScript,
		PS1Script:  ps1Script,
		ExpiresAt:  expiresAt.Unix(),
	})
}
