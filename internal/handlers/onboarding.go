package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type OnboardingResponse struct {
	Token      string `json:"token"`
	BashScript string `json:"bash_script"`
	PS1Script  string `json:"ps1_script"`
	ExpiresAt  int64  `json:"expires_at"`
}

func GenerateOnboardingPayload(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenBytes := make([]byte, 24)
	rand.Read(tokenBytes)
	jitToken := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(1 * time.Hour)

	_, err := db.Pool.Exec(r.Context(), `
		INSERT INTO enrollment_tokens (tenant_id, token_hash, expires_at, is_used) 
		VALUES ((SELECT id FROM tenants WHERE slug = $1 OR id::text = $1), $2, $3, false)
	`, tenantID, jitToken, expiresAt)

	if err != nil {
		http.Error(w, "Fehler bei der Token-Generierung", http.StatusInternalServerError)
		return
	}

	hubURL := "https://hub.sentinel-core.local:8443"

	bashScript := fmt.Sprintf(`curl -sSL %s/downloads/linux/install.sh | sudo ENROLL_TOKEN="%s" HUB_URL="%s" bash`, hubURL, jitToken, hubURL)
	ps1Script := fmt.Sprintf(`Invoke-WebRequest -Uri "%s/downloads/windows/install.ps1" -OutFile "$env:TEMP\install.ps1"; & "$env:TEMP\install.ps1" -EnrollmentToken "%s" -HubUrl "%s"`, hubURL, jitToken, hubURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(OnboardingResponse{
		Token:      jitToken,
		BashScript: bashScript,
		PS1Script:  ps1Script,
		ExpiresAt:  expiresAt.Unix(),
	})
}
