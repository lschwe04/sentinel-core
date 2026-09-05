package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"sentinel-core/internal/db"
	"sentinel-core/internal/middleware"
)

func ExportSIEMLogs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(middleware.ContextKeyTenantID).(string)
	if !ok {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	format := r.URL.Query().Get("format") // "json" oder "syslog"
	if format == "" {
		format = "json"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := `
		SELECT s.node_id, s.severity, s.source, s.message, s.created_at
		FROM security_logs s
		JOIN customers c ON s.customer_id = c.id
		JOIN tenants t ON c.tenant_id = t.id
		WHERE t.slug = $1 OR t.id::text = $1
		ORDER BY s.created_at DESC
		LIMIT 500
	`
	rows, err := db.Pool.Query(ctx, query, tenantID)
	if err != nil {
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type LogRecord struct {
		NodeID    string    `json:"node_id"`
		Severity  string    `json:"severity"`
		Source    string    `json:"source"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
	}

	var logs []LogRecord
	for rows.Next() {
		var l LogRecord
		if err := rows.Scan(&l.NodeID, &l.Severity, &l.Source, &l.Message, &l.Timestamp); err == nil {
			logs = append(logs, l)
		}
	}

	if format == "syslog" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, l := range logs {
			fmt.Fprintf(w, "<134>1 %s sentinel-core %s - - - [%s severity=%s] %s\n",
				l.Timestamp.Format(time.RFC3339), l.NodeID, l.Source, l.Severity, l.Message)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenant_id": tenantID,
		"count":     len(logs),
		"logs":      logs,
	})
}
