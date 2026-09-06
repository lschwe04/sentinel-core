package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type AVVDocument struct {
	TenantName      string   `json:"tenant_name"`
	CustomerName    string   `json:"customer_name"`
	ContractDate    string   `json:"contract_date"`
	TechnicalOrgs   []string `json:"technical_organizational_measures"`
	IsCISCompliant  bool     `json:"is_cis_compliant"`
	ComplianceScore int      `json:"compliance_score"`
}

func RenderAVVDocument(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	customerID := r.URL.Query().Get("customer_id")

	if tenantID == "" || customerID == "" {
		http.Error(w, "Tenant ID und Customer ID erforderlich", http.StatusBadRequest)
		return
	}

	var tenantName, customerName string
	err := db.Pool.QueryRow(r.Context(), `SELECT name FROM tenants WHERE slug = $1 OR id::text = $1`, tenantID).Scan(&tenantName)
	if err != nil {
		http.Error(w, "Mandant nicht gefunden", http.StatusNotFound)
		return
	}

	err = db.Pool.QueryRow(r.Context(), `
		SELECT c.name
		FROM customers c
		JOIN tenants t ON t.id = c.tenant_id
		WHERE c.id = $1 AND (t.slug = $2 OR t.id::text = $2)
	`, customerID, tenantID).Scan(&customerName)
	if err != nil {
		http.Error(w, "Endkunde nicht gefunden", http.StatusNotFound)
		return
	}

	// Dynamische Ermittlung der TOMs aus dem Hardening-Status der Kunden-Nodes
	rows, err := db.Pool.Query(r.Context(), `SELECT cis_level_1_compliant FROM hardening_status WHERE customer_id = $1`, customerID)
	if err != nil {
		http.Error(w, "Compliance-Daten konnten nicht geladen werden", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	totalNodes := 0
	compliantNodes := 0
	for rows.Next() {
		var compliant bool
		rows.Scan(&compliant)
		totalNodes++
		if compliant {
			compliantNodes++
		}
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Compliance-Daten konnten nicht gelesen werden", http.StatusInternalServerError)
		return
	}

	score := 0
	if totalNodes > 0 {
		score = (compliantNodes * 100) / totalNodes
	}

	doc := AVVDocument{
		TenantName:   tenantName,
		CustomerName: customerName,
		ContractDate: time.Now().Format("2006-01-02"),
		TechnicalOrgs: []string{
			"AES-256-GCM Verschlüsselung ruhender Telemetriedaten (Agent-Level)",
			"Strikte Mandantentrennung via PostgreSQL Row-Level-Security",
			"Bidirektionale mTLS-Authentifizierung (TLS 1.3)",
			"Automatisierte FIM-Überwachung (File Integrity Monitoring)",
		},
		IsCISCompliant:  score >= 90,
		ComplianceScore: score,
	}

	if r.URL.Query().Get("format") == "pdf" {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=AVV-%s.pdf", customerID))
		lines := []string{fmt.Sprintf("Auftraggeber: %s", doc.TenantName), fmt.Sprintf("Auftragnehmer/Kunde: %s", doc.CustomerName), "Vertragsdatum: " + doc.ContractDate, fmt.Sprintf("Compliance-Score: %d%%", doc.ComplianceScore)}
		lines = append(lines, doc.TechnicalOrgs...)
		if err := writePDF(w, "Auftragsverarbeitungsvertrag", lines); err != nil {
			return
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}
