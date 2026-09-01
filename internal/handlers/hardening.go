package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type HardeningStatus struct {
	NodeID     string    `json:"node_id"`
	CISLevel1  bool      `json:"cis_level_1_compliant"`
	CISLevel2  bool      `json:"cis_level_2_compliant"`
	LastScan   time.Time `json:"last_scan"`
	OpenIssues int       `json:"open_issues"`
}

type HardeningReport struct {
	NodeID     string `json:"node_id"`
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	OpenIssues int    `json:"open_issues"`
}

// HandleHardeningReport empfängt den geschützten mTLS-Report des Agenten (Closed Loop)
func HandleHardeningReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var report HardeningReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Status in der PostgreSQL Datenbank aktualisieren
	query := `
		INSERT INTO hardening_status (node_id, cis_level_2_compliant, last_scan, open_issues)
		VALUES ($1, $2, CURRENT_TIMESTAMP, $3)
		ON CONFLICT (node_id) 
		DO UPDATE SET cis_level_2_compliant = $2, last_scan = CURRENT_TIMESTAMP, open_issues = $3
	`
	_, err := db.Pool.Exec(ctx, query, report.NodeID, report.Success, report.OpenIssues)
	if err != nil {
		slog.Error("Fehler beim Speichern des Hardening-Reports in DB", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	slog.Info("Hardening-Report erfolgreich verarbeitet", "node_id", report.NodeID, "success", report.Success)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "report_received"}`))
}

// RenderHardeningWidget liefert das HTMX-Fragment mit Live-Polling für den Status
func RenderHardeningWidget(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		nodeID = "node-local-docker"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var compliant bool
	var openIssues int
	var statusText = "Läuft / Wartet auf Callback..."
	var badgeColor = "text-yellow-400"

	query := `SELECT cis_level_2_compliant, open_issues FROM hardening_status WHERE node_id = $1`
	err := db.Pool.QueryRow(ctx, query, nodeID).Scan(&compliant, &openIssues)

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
	// HTMX-Polling: Fragt alle 3 Sekunden den Status dieses Widgets neu ab
	fmt.Fprintf(w, `
		<div id="hardening-widget" hx-get="/api/v1/ui/hardening/widget?node_id=%s" hx-trigger="every 3s" hx-swap="outerHTML"
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
	`, nodeID, nodeID, badgeColor, statusText)
}
