package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/audit"
	"sentinel-core/internal/middleware"
	"sentinel-core/internal/remediation"
)

type RemediationTriggerRequest struct {
	NodeID string `json:"node_id"`
	RuleID string `json:"rule_id"` // z. B. "cis-ssh-hardening"
}

// HandleTriggerRemediation führt automatisierte Korrekturen auf betroffenen Nodes aus
func HandleTriggerRemediation(auditLogger *audit.Logger, playbookDir string) http.HandlerFunc {
	engine := remediation.NewEngine(auditLogger, playbookDir)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		tenantID, ok := r.Context().Value(middleware.ContextKeyTenantID).(string)
		if !ok || tenantID == "" {
			http.Error(w, `{"error": "Unauthorized tenant context"}`, http.StatusUnauthorized)
			return
		}

		var req RemediationTriggerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" || req.RuleID == "" {
			http.Error(w, `{"error": "Invalid request payload"}`, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		err := engine.TriggerHardening(ctx, tenantID, req.NodeID, req.RuleID)
		if err != nil {
			http.Error(w, `{"error": "Remediation execution failed"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "remediation_success",
			"node_id": req.NodeID,
			"rule_id": req.RuleID,
		})
	}
}
