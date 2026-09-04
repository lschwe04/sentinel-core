// sentinel-core: internal/handlers/compliance.go
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type CustomerComplianceReport struct {
	CustomerID   int       `json:"customer_id"`
	CustomerName string    `json:"customer_name"`
	TotalNodes   int       `json:"total_nodes"`
	Compliant    int       `json:"compliant_nodes"`
	ScorePct     float64   `json:"compliance_score_pct"`
	GeneratedAt  time.Time `json:"generated_at"`
}

func ExportCustomerComplianceReport(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	customerID := r.URL.Query().Get("customer_id")

	if tenantID == "" || customerID == "" {
		http.Error(w, `{"error": "tenant_id and customer_id are required"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// KORREKTUR: Verwendung von ":=" statt "=" für die Variablendeklaration
	query := `
		SELECT c.id, c.name, 
		       COUNT(h.node_id) as total,
		       COUNT(CASE WHEN h.cis_level_2_compliant THEN 1 END) as compliant
		FROM customers c
		LEFT JOIN hardening_status h ON c.id = h.customer_id
		WHERE c.tenant_id = $1 AND c.id = $2
		GROUP BY c.id, c.name
	`

	var report CustomerComplianceReport
	var total, compliant int

	err := db.Pool.QueryRow(ctx, query, tenantID, customerID).Scan(
		&report.CustomerID, &report.CustomerName, &total, &compliant,
	)

	if err != nil {
		http.Error(w, `{"error": "Customer not found or database error"}`, http.StatusNotFound)
		return
	}

	report.TotalNodes = total
	report.Compliant = compliant
	if total > 0 {
		report.ScorePct = (float64(compliant) / float64(total)) * 100.0
	} else {
		report.ScorePct = 0.0
	}
	report.GeneratedAt = time.Now().UTC()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=compliance-report-"+customerID+".json")
	json.NewEncoder(w).Encode(report)
}
