package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"sentinel-core/internal/auth"
	"sentinel-core/internal/db"

	"github.com/jackc/pgx/v5"
)

type HardeningReport struct {
	NodeID     string `json:"node_id"`
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	OpenIssues int    `json:"open_issues"`
}

func HandleHardeningReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAgentError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var report HardeningReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&report); err != nil || report.NodeID == "" || len(report.NodeID) > 64 || report.OpenIssues < 0 {
		writeAgentError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	tenantID, ok := r.Context().Value(auth.AuthenticatedTenantKey).(string)
	tenantNumber, parseErr := strconv.Atoi(tenantID)
	if !ok || parseErr != nil || tenantNumber < 1 {
		writeAgentError(w, http.StatusForbidden, "authenticated tenant context is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO hardening_status (node_id, tenant_id, cis_level_2_compliant, last_scan, open_issues)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4)
		ON CONFLICT (node_id)
		DO UPDATE SET cis_level_2_compliant = $3, last_scan = CURRENT_TIMESTAMP, open_issues = $4, tenant_id = $2
	`
	err := db.WithTenantTx(ctx, tenantNumber, func(txCtx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(txCtx, query, report.NodeID, tenantNumber, report.Success, report.OpenIssues)
		return err
	})
	if err != nil {
		slog.Error("Fehler beim Speichern des Hardening-Reports", "tenant_id", tenantNumber, "node_id", report.NodeID, "error", err)
		writeAgentError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "report_received"}`))
}

func RenderHardeningWidget(w http.ResponseWriter, r *http.Request) {
	rawNodeID := r.URL.Query().Get("node_id")
	if rawNodeID == "" {
		rawNodeID = "node-local-docker"
	}
	safeNodeID := html.EscapeString(rawNodeID)
	tenantID, ok := r.Context().Value(auth.AuthenticatedTenantKey).(string)
	tenantNumber, parseErr := strconv.Atoi(tenantID)

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var compliant bool
	var openIssues int
	var statusText = "Wartet auf Prüfung..."
	var badgeColor = "text-yellow-400"

	query := `SELECT cis_level_2_compliant, open_issues FROM hardening_status WHERE node_id = $1`
	var err error
	if ok && parseErr == nil && tenantNumber > 0 {
		err = db.WithTenantTx(ctx, tenantNumber, func(txCtx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(txCtx, query, rawNodeID).Scan(&compliant, &openIssues)
		})
	}

	if err == nil {
		if compliant {
			statusText = "Erfolgreich gehärtet (CIS Level 2 Konform)"
			badgeColor = "text-green-400"
		} else {
			statusText = fmt.Sprintf("Fehlgeschlagen (%d offene Issues)", openIssues)
			badgeColor = "text-red-400"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div id="hardening-widget" hx-get="/api/v1/ui/hardening/widget?node_id=%s" hx-trigger="every 5s" hx-swap="outerHTML"
			 class="border border-gray-700 rounded-lg p-6 bg-gray-800">
			<h2 class="text-xl font-semibold mb-4">🛡️ CIS Hardening Management</h2>
			<p class="text-gray-400 mb-6">Node: <span class="font-mono text-blue-400">%s</span></p>
			
			<div class="mb-4 p-4 bg-gray-900 rounded border border-gray-700 font-mono text-sm">
				Status: <span class="%s font-bold">%s</span>
			</div>

			<button hx-post="/api/v1/hardening/trigger" hx-swap="none"
					class="px-6 py-2 bg-blue-600 hover:bg-blue-500 font-bold rounded transition text-white">
				CIS Hardening (Level 2) jetzt ausführen
			</button>
		</div>
	`, safeNodeID, safeNodeID, badgeColor, statusText)
}
