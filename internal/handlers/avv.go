package handlers

import (
	"encoding/json"
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

	err = db.Pool.QueryRow(r.Context(), `SELECT name FROM customers WHERE id = $1`, customerID).Scan(&customerName)
	if err != nil {
		http.Error(w, "Endkunde nicht gefunden", http.StatusNotFound)
		return
	}

	// Dynamische Ermittlung der TOMs aus dem Hardening-Status der Kunden-Nodes
	rows, _ := db.Pool.Query(r.Context(), `SELECT cis_level_1_compliant FROM hardening_status WHERE customer_id = $1`, customerID)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
